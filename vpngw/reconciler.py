"""The single writer.

Everything that changes kernel state goes through one loop in one thread. The
API and the CLI only ever write to the database and ask for a reconcile; they
never touch nftables or the routing table themselves. That is what makes the
system's behaviour a function of its database rather than of the order in which
somebody clicked things.

Order within a pass is chosen so that no step can open a gap:

    1. firewall   - before anything can route
    2. routes     - blackholes exist before defaults do
    3. tunnels    - only now can traffic actually move
    4. health     - observe
    5. steering   - point tables at healthy tunnels, blackhole the rest
    6. resolvers  - last, because they depend on the routes above

Step 2 before step 3 is the important one. A tunnel that comes up before its
table has a blackhole would, for the instant between the two, have a table with
no default at all - and a table with no default falls through to the main
table, which reaches the uplink.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from contextlib import contextmanager

from . import config, dnsmgr
from .db import Database
from .discovery import Discovery
from .health import HealthMonitor
from .models import Egress, EgressKind, HealthState, Pool, Tunnel, TunnelKind
from .net import ifaces, nft, routing
from .net.shell import missing_binaries, try_run
from .pools import PoolManager
from .render import nftables as render_nft
from .tunnels import driver_for

log = logging.getLogger("vpngw.reconcile")

MAINTENANCE_KEY = "maintenance_until"
PROVIDERS_KEY = "providers_enabled"


class Reconciler:
    def __init__(self, db: Database, settings: config.Settings) -> None:
        self.db = db
        self.settings = settings
        self.health = HealthMonitor(settings.health)
        self.pools = PoolManager()
        self.discovery = Discovery(settings)
        self._structural_fingerprint: str | None = None
        self._link_info: dict[str, object] = {}
        self._last_pass: float = 0.0
        self._endpoint_refreshed: float = 0.0
        self._api_endpoints: list[str] = []
        #: via as last actually applied to the device, per slug. Seeded from
        #: the kernel (wg's own fwmark) rather than the database, because a
        #: CLI edit made while the daemon was down leaves the database ahead
        #: of the device - trusting the database would skip the very re-apply
        #: that closes that gap.
        self._applied_via: dict[str, str] = {}
        # Tunnels the reconcile loop must leave alone. Used by the leak test:
        # without it, taking a tunnel down and measuring the result is a race
        # the loop wins - it restores the tunnel within its five-second timer
        # and the test ends up measuring a working gateway while believing it
        # measured a broken one. A test that reports what it wanted to see is
        # worse than no test.
        self._held: set[str] = set()

    # -- lifecycle ----------------------------------------------------------

    def bootstrap(self) -> None:
        """First pass after start. Fails loudly rather than half-configuring."""
        self.settings.validate()

        missing = missing_binaries()
        if missing:
            raise RuntimeError(
                "required tools are not installed: " + ", ".join(missing)
            )

        net = self.settings.net
        routing.harden_sysctls(net)
        ifaces.ensure_bridge(net.lan_bridge, net.lan_member)
        ifaces.ensure_address(net.lan_bridge, net.lan_cidr)
        if net.mgmt_iface:
            ifaces.ensure_address(net.mgmt_iface, net.mgmt_cidr)
        for iface in (net.wan_iface, net.lan_member):
            if ifaces.exists(iface):
                ifaces.disable_offloads(iface)
        dnsmgr.ensure_dummy_iface()
        self.refresh_api_endpoints(force=True)

        self.reconcile(force_structural=True)

        # Forwarding is raised only now, with a complete ruleset loaded. The
        # sysctl file ships it as 0 so that a boot where vpngw never starts
        # cannot forward at all.
        routing.enable_forwarding(True)
        log.info("bootstrap complete; forwarding enabled")

    # -- the pass -----------------------------------------------------------

    def reconcile(self, *, force_structural: bool = False) -> None:
        started = time.time()
        tunnels = self.db.tunnels()
        pools = self.db.pools()
        clients = self.db.clients()
        egresses = self._egresses(tunnels, pools)

        self._step_firewall(tunnels, pools, clients, force=force_structural)
        self._step_routes(egresses, tunnels)
        self._step_tunnels(tunnels)
        self._step_health(tunnels)
        self._step_steer_tunnels(tunnels)
        self._step_steer_pools(pools, tunnels)
        self._step_resolvers(tunnels, pools, egresses)

        # Observation only - nothing here changes what is allowed. It exists so
        # a machine that is being dropped shows up in the panel rather than
        # looking like one that is switched off.
        try:
            self.discovery.scan({c.ip for c in clients})
        except Exception as exc:
            log.debug("discovery pass failed: %s", exc)

        self._last_pass = time.time()
        log.debug("reconcile pass took %.2fs", self._last_pass - started)

    # -- 1. firewall --------------------------------------------------------

    def _fingerprint(self, tunnels, pools, clients) -> str:
        """What forces a full ruleset rebuild, as opposed to an element edit.

        Client changes deliberately are *not* in here: they move map elements,
        which keeps the drop counters intact. Those counters are the evidence
        the kill switch works, and resetting them on every UI edit would throw
        that evidence away.
        """
        payload = {
            "tunnels": sorted((t.slug, t.iface, t.enabled, t.via)
                              for t in tunnels),
            "pools": sorted((p.slug, p.esid, p.enabled) for p in pools),
            "maintenance": self.maintenance_active(),
            "settings": [
                self.settings.net.wan_iface,
                self.settings.net.lan_bridge,
                self.settings.net.mgmt_iface,
                self.settings.net.lan_cidr,
                # Access control is part of the ruleset, so changing it from
                # the panel must rebuild the ruleset. Before these were here,
                # unticking WAN said "saved" while the firewall kept answering
                # on WAN until the next restart - a lie with a security shape.
                self.settings.net.management_ifaces(),
                tuple(self.settings.net.client_interfaces()),
                tuple(self.settings.net.client_cidrs),
                self.settings.dns.resolver_subnet,
                self.settings.dns.block_dot,
                self.settings.killswitch.strict_host_egress,
                self.settings.api.port,
            ],
        }
        blob = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def _step_firewall(self, tunnels, pools, clients, *, force: bool) -> None:
        fingerprint = self._fingerprint(tunnels, pools, clients)
        structural = force or fingerprint != self._structural_fingerprint

        if structural or not nft.table_exists():
            ruleset = render_nft.render(
                self.settings, tunnels, pools, clients,
                maintenance=self.maintenance_active(),
                api_endpoints=self._api_endpoints,
            )
            ok, error = nft.check_ruleset(ruleset)
            if not ok:
                # Refusing to apply leaves the previous ruleset in force, which
                # is fail-closed. Never try to "recover" by relaxing anything.
                log.error("generated ruleset is invalid, keeping the current "
                          "one: %s", error)
                self.db.log_event("error", "firewall",
                                  f"ruleset rejected: {error}")
                return
            nft.apply_ruleset(ruleset)
            self._structural_fingerprint = fingerprint
            self.db.log_event("info", "firewall", "ruleset rebuilt")
            return

        # Incremental: only the elements moved.
        self._sync_elements(tunnels, pools, clients)

    def _sync_elements(self, tunnels, pools, clients) -> None:
        enabled_tunnels = [t for t in tunnels if t.enabled]
        esid_by_egress = {
            (EgressKind.TUNNEL, t.slug): t.esid for t in enabled_tunnels
        }
        esid_by_egress.update(
            {(EgressKind.POOL, p.slug): p.esid for p in pools if p.enabled}
        )

        cli2mark: dict[str, str] = {}
        cli2dns: dict[str, str] = {}
        for c in clients:
            if not c.enabled or not c.egress_slug:
                continue
            esid = esid_by_egress.get((c.egress_kind, c.egress_slug))
            if esid is None:
                continue
            cli2mark[c.ip] = f"{esid:#06x}"
            cli2dns[c.ip] = self.settings.dns.resolver_ip(esid)

        nft.sync_map("cli2mark", cli2mark)
        nft.sync_map("cli2dns", cli2dns)
        nft.sync_set("tun_ifaces", {f'"{t.iface}"' for t in enabled_tunnels})
        # Only tunnels that legitimately dial out over the WAN. A chained
        # tunnel's endpoint is deliberately absent: its handshake leaves
        # through the parent (@tun_ifaces is already accepted), and keeping
        # the address off this set means a routing mistake ends in a drop on
        # the uplink, not in the ISP watching us greet the exit provider.
        nft.sync_set(
            "vpn_endpoints",
            {ep for t in enabled_tunnels if not t.via for ep in t.endpoints},
        )
        nft.sync_set("provider_api", set(self._api_endpoints))

    # -- 2. routes ----------------------------------------------------------

    def _egresses(self, tunnels: list[Tunnel], pools: list[Pool]) -> list[Egress]:
        out = [Egress.of(t) for t in tunnels if t.enabled]
        out += [Egress.of(p) for p in pools if p.enabled]
        return out

    def _step_routes(self, egresses: list[Egress],
                     tunnels: list[Tunnel]) -> None:
        for eg in egresses:
            routing.ensure_blackhole(eg.table)
        by_slug = {t.slug: t for t in tunnels if t.enabled}
        chained = [(t, by_slug[t.via]) for t in by_slug.values()
                   if t.via and t.via in by_slug]
        routing.sync_rules(
            routing.desired_rules(egresses, self.settings.dns.resolver_ip,
                                  chained)
        )

    # -- 3. tunnels ---------------------------------------------------------

    @contextmanager
    def hold(self, slugs):
        """Stop reconciling the named tunnels for the duration of the block.

        Their routes are withdrawn on entry and everything is restored on exit,
        including if the caller raises - a test that leaves the gateway with a
        tunnel held down would be a far worse bug than the one it was checking
        for.
        """
        slugs = set(slugs)
        self._held |= slugs
        try:
            for slug in slugs:
                tunnel = self.db.tunnel(slug)
                if tunnel:
                    routing.clear_default(tunnel.table)
            yield
        finally:
            self._held -= slugs
            try:
                self.reconcile()
            except Exception:
                log.exception("could not restore tunnels after a hold")

    def _chain_mtu(self, t: Tunnel, by_slug: dict[str, Tunnel]) -> int:
        """The MTU a chained tunnel gets when the operator has not set one.

        Each layer of encapsulation costs CHAIN_MTU_OVERHEAD; ignoring that
        is the classic double-VPN failure - handshake fine, DNS fine, HTTPS
        hangs - because full-size packets silently vanish inside the outer
        tunnel. Walks to the WAN and subtracts per hop.
        """
        depth, seen = 0, set()
        current = t
        while current.via and current.slug not in seen:
            seen.add(current.slug)
            depth += 1
            parent = by_slug.get(current.via)
            if parent is None:
                break
            current = parent
        base = current.mtu or 1420
        return max(1280, base - config.CHAIN_MTU_OVERHEAD * depth)

    def _via_needs_reapply(self, t: Tunnel) -> bool:
        if t.slug not in self._applied_via:
            # First sight of an interface this process did not bring up. Ask
            # the device what it actually carries where we can (WireGuard
            # reports its fwmark); OpenVPN cannot be asked, so trust the
            # database and accept that a daemon-down CLI edit needs the next
            # via change (or a restart) to land.
            if t.kind is TunnelKind.WIREGUARD:
                res = try_run(["wg", "show", t.iface, "fwmark"])
                raw = (res.stdout or "").strip()
                actual = 0 if raw in ("off", "") else int(raw, 16)
                wanted = t.outer_mark if t.via else 0
                self._applied_via[t.slug] = t.via if actual == wanted else "\0"
            else:
                self._applied_via[t.slug] = t.via
        return self._applied_via[t.slug] != t.via

    def _step_tunnels(self, tunnels: list[Tunnel]) -> None:
        # Parents before children: a chained tunnel's first handshake needs
        # the parent's interface (and its route) to exist. Depth 0 first.
        by_slug = {t.slug: t for t in tunnels}

        def depth(t: Tunnel) -> int:
            d, cur, seen = 0, t, set()
            while cur.via and cur.slug not in seen:
                seen.add(cur.slug)
                nxt = by_slug.get(cur.via)
                if nxt is None:
                    break
                cur = nxt
                d += 1
            return d

        tunnels = sorted(tunnels, key=depth)
        expected: set[str] = set()
        for t in tunnels:
            if t.via and not t.mtu:
                # In-memory only: mtu=0 stays on disk meaning "derive it",
                # so re-parenting the chain re-derives automatically.
                t.mtu = self._chain_mtu(t, by_slug)
            driver = driver_for(t)
            if t.slug in self._held:
                # Held down deliberately; keep the interface name reserved so
                # the orphan sweep below does not treat it as abandoned.
                expected.add(t.iface)
                continue
            if t.enabled:
                expected.add(t.iface)
                if not ifaces.exists(t.iface):
                    try:
                        self._link_info[t.slug] = driver.up(t)
                        self._applied_via[t.slug] = t.via
                        self.db.log_event("info", t.slug, "tunnel brought up")
                    except Exception as exc:
                        log.error("cannot bring up %s: %s", t.slug, exc)
                        self.db.log_event("error", t.slug, f"up failed: {exc}")
                elif ifaces.mtu_of(t.iface) not in (0, t.mtu or None) and t.mtu:
                    # An MTU edit alone must not wait for the next re-up: on a
                    # chain it is the difference between working and "DNS fine,
                    # HTTPS hangs". Setting it live costs no handshake.
                    routing.set_link_mtu(t.iface, t.mtu)
                    self.db.log_event("info", t.slug, f"mtu set to {t.mtu}")
                elif self._via_needs_reapply(t):
                    # Chaining changed under a live interface. Re-running the
                    # driver replaces the device config - including the outer
                    # fwmark, which is the part that makes the chain real.
                    try:
                        self._link_info[t.slug] = driver.up(t)
                        self._applied_via[t.slug] = t.via
                        self.db.log_event(
                            "info", t.slug,
                            f"now routed via {t.via}" if t.via
                            else "unchained; leaves over the WAN again")
                    except Exception as exc:
                        log.error("cannot re-apply %s: %s", t.slug, exc)
                        self.db.log_event("error", t.slug,
                                          f"re-apply failed: {exc}")
            else:
                if ifaces.exists(t.iface):
                    driver.down(t)
                    self._link_info.pop(t.slug, None)
                    self.health.forget(t.slug)
                    self.db.log_event("info", t.slug, "tunnel disabled")
        ifaces.remove_orphans(expected)

    # -- 4. health ----------------------------------------------------------

    def _step_health(self, tunnels: list[Tunnel]) -> None:
        for t in tunnels:
            before = self.health.get(t.slug).state
            after = self.health.probe(t).state
            if before is not after:
                self.db.log_event(
                    "warning" if after is not HealthState.UP else "info",
                    t.slug,
                    f"health {before.value} -> {after.value}"
                    + (f": {self.health.get(t.slug).last_error}"
                       if self.health.get(t.slug).last_error else ""),
                )
                # Flows pinned to a tunnel that just died must not linger; the
                # client should see a clean failure and reconnect, not a socket
                # that hangs until its own timeout.
                if after is HealthState.DOWN:
                    routing.flush_conntrack_mark(t.mark)
            if after is HealthState.UP:
                self.health.refresh_exit_ip(t)

    # -- 5. steering --------------------------------------------------------

    def _link_for(self, t: Tunnel):
        info = self._link_info.get(t.slug)
        if info is None or not getattr(info, "exists", False):
            info = driver_for(t).state(t)
            self._link_info[t.slug] = info
        return info

    def _ancestors_usable(self, t: Tunnel,
                          by_slug: dict[str, Tunnel]) -> bool:
        """False when anything this tunnel rides through cannot carry it.

        Without this, a dead entry hop leaves the exit hop looking healthy
        for up to handshake_max_age - and its clients pointlessly routed at
        a tunnel whose packets are falling into the parent's blackhole.
        The blackhole keeps them safe either way; this makes the panel and
        the failover tell the truth *now*.
        """
        seen = set()
        current = t
        while current.via and current.slug not in seen:
            seen.add(current.slug)
            parent = by_slug.get(current.via)
            if parent is None or not parent.enabled:
                return False
            state = self.health.get(parent.slug).state
            if not ifaces.exists(parent.iface) or state in (
                    HealthState.DOWN, HealthState.DISABLED):
                return False
            current = parent
        return True

    def _step_steer_tunnels(self, tunnels: list[Tunnel]) -> None:
        by_slug = {t.slug: t for t in tunnels}
        for t in tunnels:
            if t.slug in self._held:
                continue
            if not t.enabled:
                routing.clear_default(t.table)
                continue

            health = self.health.get(t.slug)
            info = self._link_for(t)
            usable = (
                ifaces.exists(t.iface)
                and health.state is not HealthState.DOWN
                and health.state is not HealthState.DISABLED
                and self._ancestors_usable(t, by_slug)
            )
            if usable:
                current = routing.table_default(t.table)
                if current != t.iface:
                    routing.set_default_via(
                        t.table, t.iface, getattr(info, "gateway", None)
                    )
            elif routing.table_default(t.table):
                routing.clear_default(t.table)
                self.db.log_event(
                    "warning", t.slug,
                    "default route withdrawn; clients on this tunnel are "
                    "blackholed until it recovers",
                )

    def _step_steer_pools(self, pools: list[Pool], tunnels: list[Tunnel]) -> None:
        by_slug = {t.slug: t for t in tunnels}
        for p in pools:
            routing.ensure_blackhole(p.table)
            chosen, reason = self.pools.select(p, self.health)
            changed = self.pools.commit(p, chosen, reason)

            if chosen is None:
                if routing.table_default(p.table):
                    routing.clear_default(p.table)
                if changed:
                    self.db.log_event(
                        "error", p.slug,
                        "no healthy member; clients are blackholed",
                    )
                    routing.flush_conntrack_mark(p.mark)
                continue

            member = by_slug.get(chosen)
            if member is None:
                continue
            info = self._link_for(member)
            current = routing.table_default(p.table)
            if changed or current != member.iface:
                routing.set_default_via(
                    p.table, member.iface, getattr(info, "gateway", None)
                )
            if changed:
                # The old member's flows are meaningless on the new one.
                routing.flush_conntrack_mark(p.mark)
                self.db.log_event("info", p.slug, reason)

    # -- 6. resolvers -------------------------------------------------------

    def _step_resolvers(self, tunnels, pools, egresses: list[Egress]) -> None:
        # The gateway's own lookups, which are separate from the per-client
        # resolvers below: this is how it finds a VPN endpoint by name before
        # any tunnel exists to carry the query.
        dnsmgr.ensure_host_resolver(list(self.settings.dns.bootstrap))
        dnsmgr.sync_addresses(self.settings, egresses)
        by_slug = {t.slug: t for t in tunnels}
        wanted: set[str] = set()

        for eg in egresses:
            wanted.add(eg.slug)
            tunnel_dns: list[str] = []
            if eg.kind is EgressKind.TUNNEL:
                t = by_slug.get(eg.slug)
                if t:
                    info = self._link_for(t)
                    tunnel_dns = list(getattr(info, "dns", None) or t.dns)
            _, previous = dnsmgr.write_config(eg, self.settings, tunnel_dns)
            changed = bool(previous) and previous != (
                dnsmgr.DNS_RUNTIME / f"{eg.slug}.conf"
            ).read_text()
            try:
                dnsmgr.ensure_running(eg, restart=changed)
            except Exception as exc:
                log.error("resolver for %s: %s", eg.slug, exc)

        for stale in dnsmgr.running_slugs() - wanted:
            dnsmgr.stop(stale)

    # -- endpoint refresh ---------------------------------------------------

    # -- provider APIs ------------------------------------------------------

    def enabled_providers(self) -> list[str]:
        raw = self.db.get(PROVIDERS_KEY, "[]") or "[]"
        try:
            return sorted(set(json.loads(raw)))
        except ValueError:
            return []

    def enable_provider(self, provider_id: str) -> None:
        """Open the firewall to one provider's API and reconcile immediately.

        Called before the first API request for that provider - under strict
        host egress the call would otherwise be dropped by our own output
        chain, with the packets landing in host_egress_drop and nothing
        obvious to point at.
        """
        current = set(self.enabled_providers())
        if provider_id in current:
            return
        current.add(provider_id)
        self.db.set(PROVIDERS_KEY, json.dumps(sorted(current)))
        self.db.log_event("info", "provider",
                          f"{provider_id} API allowed through the firewall")
        self.refresh_api_endpoints(force=True)
        self.reconcile(force_structural=True)

    def disable_provider(self, provider_id: str) -> None:
        current = set(self.enabled_providers())
        if provider_id not in current:
            return
        current.discard(provider_id)
        self.db.set(PROVIDERS_KEY, json.dumps(sorted(current)))
        self.refresh_api_endpoints(force=True)
        self.reconcile(force_structural=True)

    def refresh_api_endpoints(self, force: bool = False) -> None:
        """Resolve the API hosts of enabled providers into the allowlist."""
        from .importers import resolve_endpoints
        from . import providers as provider_registry

        enabled = self.enabled_providers()
        if not enabled:
            self._api_endpoints = []
            return

        hosts: list[str] = []
        for pid in enabled:
            try:
                hosts.extend(provider_registry.get(pid).api_hosts)
            except Exception as exc:
                log.warning("provider %s: %s", pid, exc)
        if not hosts:
            self._api_endpoints = []
            return

        addrs, _ = resolve_endpoints(hosts)
        if addrs != self._api_endpoints:
            log.info("provider API allowlist: %s", ", ".join(addrs) or "empty")
            self._api_endpoints = addrs

    def refresh_endpoints(self, force: bool = False) -> int:
        """Re-resolve endpoint hostnames and update the egress allowlist.

        Providers move a hostname to a new address without warning. With strict
        host egress on, a stale allowlist means the tunnel simply stops
        connecting and the cause is invisible - the packets are dropped by our
        own output chain. So this runs on a timer.
        """
        from .importers import resolve_endpoints

        if not force and time.time() - self._endpoint_refreshed < 900:
            return 0
        self._endpoint_refreshed = time.time()
        self.refresh_api_endpoints()

        changed = 0
        for t in self.db.tunnels(enabled_only=True):
            if not t.endpoint_hosts:
                continue
            addrs, _ = resolve_endpoints(t.endpoint_hosts)
            literal = [e for e in t.endpoints if e not in addrs]
            merged = sorted(set(addrs) | set(literal))
            if merged != sorted(t.endpoints):
                log.info("%s endpoints changed: %s -> %s", t.slug,
                         t.endpoints, merged)
                t.endpoints = merged
                self.db.update_tunnel(t)
                self.db.log_event("info", t.slug, "endpoint addresses refreshed")
                changed += 1
        return changed

    # -- maintenance --------------------------------------------------------

    def maintenance_active(self) -> bool:
        raw = self.db.get(MAINTENANCE_KEY)
        if not raw:
            return False
        try:
            return time.time() < float(raw)
        except ValueError:
            return False

    def maintenance_remaining(self) -> int:
        raw = self.db.get(MAINTENANCE_KEY)
        if not raw:
            return 0
        try:
            return max(0, int(float(raw) - time.time()))
        except ValueError:
            return 0

    def set_maintenance(self, minutes: int | None) -> None:
        """Open or close the gateway's own egress.

        Only the gateway's. The forward chain is not touched by this, so a
        maintenance window cannot let a client out unencrypted - it exists so
        that `apt upgrade` works, nothing more.
        """
        if minutes is None or minutes <= 0:
            self.db.unset(MAINTENANCE_KEY)
            self.db.log_event("info", "maintenance", "window closed")
        else:
            self.db.set(MAINTENANCE_KEY, str(time.time() + minutes * 60))
            self.db.log_event(
                "warning", "maintenance",
                f"host egress opened for {minutes} minutes "
                f"(client traffic is unaffected)",
            )
        self.reconcile(force_structural=True)
