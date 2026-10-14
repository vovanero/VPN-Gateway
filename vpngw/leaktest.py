"""Proof that the kill switch works, rather than the claim that it does.

Most VPN-router guides end at "now traffic goes through the tunnel". Nobody
tests the interesting case: what happens the moment the tunnel is gone. This
module does, automatically, on the real box.

A network namespace is attached to the client bridge with a veth pair, which
makes it a LAN client indistinguishable from a Hyper-V VM as far as the kernel
is concerned - same bridge, same forward path, same firewall rules. Traffic
generated inside it is real forwarded traffic.

Every leak assertion is checked twice, by two mechanisms that do not share a
failure mode:

  * **nftables counters** - authoritative, in-kernel, but they only prove that
    the rule we think is matching is matching.
  * **tcpdump on the uplink**, filtered to a port used by nothing else - an
    independent observation of the wire that does not trust our ruleset at all.

If those two ever disagree, believe tcpdump.
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
import time
from dataclasses import dataclass, field

from . import config
from .models import Client, EgressKind, TunnelKind, ValidationError
from .net import ifaces, nft, routing
from .net.shell import run, try_run

log = logging.getLogger("vpngw.leaktest")

NETNS = "vpngw-test"
VETH_HOST = "vt-host"
VETH_NS = "vt-ns"

# A destination and port used by nothing else on this machine, so a single
# packet seen on the uplink with this port is unambiguous evidence of a leak.
CANARY_HOST = "203.0.113.9"      # TEST-NET-3, never routed
CANARY_PORT = 51999
CANARY_BPF = f"port {CANARY_PORT} or host {CANARY_HOST}"

# How long a request through a proxy exit is given before it counts as failed.
PROXY_PATIENCE = 20


@dataclass
class Check:
    # Stable identifier, separate from the human-readable name. The CLI prints
    # the name; the web UI looks the id up in its own translation table. Reword
    # a name freely - only changing an id breaks anything.
    id: str
    name: str
    passed: bool
    detail: str = ""
    critical: bool = True

    @property
    def symbol(self) -> str:
        if self.passed:
            return "PASS"
        return "FAIL" if self.critical else "WARN"


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, check_id: str, name: str, passed: bool, detail: str = "",
            critical: bool = True) -> Check:
        check = Check(check_id, name, passed, detail, critical)
        self.checks.append(check)
        log.info("[%s] %s%s", check.symbol, name,
                 f" - {detail}" if detail else "")
        return check

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if not c.passed and c.critical]

    @property
    def ok(self) -> bool:
        return not self.failed

    def render(self) -> str:
        width = max((len(c.name) for c in self.checks), default=10)
        lines = [f"  {c.symbol:4}  {c.name:<{width}}  {c.detail}"
                 for c in self.checks]
        lines.append("")
        if self.ok:
            lines.append("  RESULT: no leak found.")
        else:
            lines.append(f"  RESULT: {len(self.failed)} CRITICAL FAILURE(S). "
                         "Do not treat this gateway as leak-proof.")
        return "\n".join(lines)


class LeakTest:
    # Seconds a request is given before it counts as failed; run() raises it
    # for a proxy exit.
    patience = 8

    def __init__(self, service) -> None:
        self.service = service
        self.db = service.db
        self.settings = service.settings
        net = self.settings.net
        # Deliberately near the top of the subnet, away from where anyone
        # would hand-assign a real client.
        self.test_ip = str(
            ipaddress.ip_address(net.lan_network.broadcast_address) - 5
        )
        self.gateway = str(net.lan_address)
        self._created_client = False

    # -- namespace ----------------------------------------------------------

    def _ns(self, *argv: str, timeout: int = 20):
        return try_run(["ip", "netns", "exec", NETNS, *argv], timeout=timeout)

    def setup_namespace(self) -> None:
        self.teardown_namespace()
        run(["ip", "netns", "add", NETNS])
        run(["ip", "link", "add", VETH_HOST, "type", "veth",
             "peer", "name", VETH_NS])
        run(["ip", "link", "set", VETH_NS, "netns", NETNS])
        run(["ip", "link", "set", VETH_HOST, "master",
             self.settings.net.lan_bridge, "up"])
        self._ns("ip", "link", "set", "lo", "up")
        self._ns("ip", "addr", "add",
                 f"{self.test_ip}/{self.settings.net.lan_network.prefixlen}",
                 "dev", VETH_NS)
        self._ns("ip", "link", "set", VETH_NS, "up")
        self._ns("ip", "route", "add", "default", "via", self.gateway)
        log.info("test client %s attached to %s", self.test_ip,
                 self.settings.net.lan_bridge)

    def teardown_namespace(self) -> None:
        try_run(["ip", "netns", "del", NETNS])
        if ifaces.exists(VETH_HOST):
            try_run(["ip", "link", "del", VETH_HOST])

    # -- client registration ------------------------------------------------

    def register_client(self, kind: EgressKind, slug: str) -> None:
        existing = self.db.client(self.test_ip)
        if existing:
            existing.egress_kind = kind
            existing.egress_slug = slug
            existing.enabled = True
            self.db.update_client(existing)
        else:
            self.db.add_client(Client(
                name="leaktest", ip=self.test_ip, egress_kind=kind,
                egress_slug=slug, notes="temporary, created by vpngwctl selftest",
            ))
            self._created_client = True
        self.service.reconciler.reconcile()

    def unregister_client(self) -> None:
        if self._created_client:
            self.db.delete_client(self.test_ip)
            self._created_client = False
            self.service.reconciler.reconcile()

    # -- traffic ------------------------------------------------------------

    def _canary(self, count: int = 5) -> None:
        """Emit UDP the uplink watcher can recognise, plus a TCP attempt."""
        for _ in range(count):
            self._ns("sh", "-c",
                     f"echo vpngw-canary | timeout 1 nc -u -w1 "
                     f"{CANARY_HOST} {CANARY_PORT}", timeout=5)
        self._ns("timeout", "3", "curl", "--silent", "--max-time", "2",
                 "http://" + CANARY_HOST, timeout=6)

    def _resolver_addresses(self) -> list[str]:
        """Every resolver a client could name directly: one per live egress."""
        esids = [t.esid for t in self.db.tunnels(enabled_only=True)]
        esids += [p.esid for p in self.db.pools(enabled_only=True)]
        return [self.settings.dns.resolver_ip(e) for e in esids]

    def _resolves_via(self, resolver: str) -> bool:
        """Whether the test client gets an answer from this resolver."""
        res = self._ns("dig", "+short", "+time=2", "+tries=1",
                       f"@{resolver}", "example.com", timeout=8)
        return res.ok and bool(res.stdout.strip())

    def _reaches_internet(self, timeout: int = 8) -> str | None:
        res = self._ns("curl", "--silent", "--fail", "--max-time", str(timeout),
                       "https://1.1.1.1/cdn-cgi/trace", timeout=timeout + 4)
        if not res.ok:
            return None
        for line in res.stdout.splitlines():
            if line.startswith("ip="):
                return line[3:].strip()
        return None

    class _Watch:
        """tcpdump on one interface, keeping the lines that name a needle.

        Address and port filters only: nothing is resolved, so a watch can
        never itself put a lookup on the wire it is watching.
        """

        def __init__(self, iface: str, bpf: str, needles: list[str],
                     *, payload: bool = False, count: int = 2000) -> None:
            self.iface, self.bpf, self.needles = iface, bpf, needles
            self.payload, self.count = payload, count
            self.proc: subprocess.Popen | None = None

        def __enter__(self) -> "LeakTest._Watch":
            argv = ["tcpdump", "-i", self.iface, "-n", "-l", "-c", str(self.count)]
            if self.payload:
                argv.append("-A")
            self.proc = subprocess.Popen(
                argv + [self.bpf],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                errors="replace",
            )
            time.sleep(1.5)  # let the capture actually attach
            return self

        def __exit__(self, *exc) -> None:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()

        def captured(self) -> list[str]:
            if not self.proc:
                return []
            time.sleep(1.0)
            if self.proc.poll() is None:
                self.proc.terminate()
            try:
                out, _ = self.proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                return []
            return [l for l in (out or "").splitlines()
                    if any(n in l for n in self.needles)]

    class _UplinkWatch(_Watch):
        """tcpdump on the uplink, looking only for the canary."""

        def __init__(self, iface: str) -> None:
            super().__init__(iface, CANARY_BPF, [CANARY_HOST, str(CANARY_PORT)],
                             count=50)

    # -- the suite ----------------------------------------------------------

    def run(self, egress_kind: EgressKind, egress_slug: str,
            *, disrupt: bool = False) -> Report:
        report = Report()
        wan = self.settings.net.wan_iface

        proxy = (self.db.tunnel(egress_slug)
                 if egress_kind is EgressKind.TUNNEL else None)
        if proxy is not None and proxy.kind is not TunnelKind.PROXY:
            proxy = None
        # A proxy exit is slower by design - every connection crosses the
        # relay, the entry tunnel and the proxy - and a working one often
        # takes longer than a tunnel's eight seconds. Measured: free proxies
        # behind a 200 ms entry answered in 2 to 5.5 s. A test that calls a
        # slow exit dead is wrong, not strict.
        self.patience = PROXY_PATIENCE if proxy is not None else 8

        try:
            self.setup_namespace()
            self.register_client(egress_kind, egress_slug)
            time.sleep(2)

            # 1. baseline -------------------------------------------------
            exit_ip = self._reaches_internet(timeout=self.patience)
            report.add(
                "tunnel_carries", "tunnel carries traffic",
                exit_ip is not None,
                f"client exits as {exit_ip}" if exit_ip
                else "the test client could not reach the internet at all; "
                     "fix that before trusting any result below",
            )

            if exit_ip:
                wan_addr = self._local_wan_address()
                report.add(
                    "exit_not_uplink", "exit address is not the uplink's",
                    exit_ip != wan_addr,
                    f"exit {exit_ip}, uplink {wan_addr}",
                )

            # 2. no leak while healthy ------------------------------------
            before = nft.counters()
            with self._UplinkWatch(wan) as watch:
                self._canary()
                captured = watch.captured()
            report.add(
                "no_leak_healthy", "no canary on the uplink while the tunnel is up",
                not captured,
                "clean" if not captured
                else f"{len(captured)} packet(s) seen on {wan}: {captured[:2]}",
            )

            # 2b. a proxy exit's own way to fail --------------------------
            if proxy is not None:
                self._check_proxy(report, proxy, exit_ip)

            # 3. unassigned client is dropped ------------------------------
            client = self.db.client(self.test_ip)
            if client:
                client.egress_slug = ""
                self.db.update_client(client)
                self.service.reconciler.reconcile()
                time.sleep(1)
                with self._UplinkWatch(wan) as watch:
                    self._canary(count=3)
                    captured = watch.captured()
                reachable = self._reaches_internet(timeout=4)
                after = nft.counters()
                # Which rule catches an unassigned client depends on where the
                # routing sent its packet. With no mark, no ip rule matches and
                # the main table hands it to the uplink - so in practice it is
                # wan_leak_drop that fires, not unclassified_drop. Report all
                # three rather than guessing, or the detail line contradicts a
                # test that actually passed.
                caught = {
                    name: self._delta(before, after, name)
                    for name in ("wan_leak_drop", "nontunnel_drop",
                                 "unclassified_drop")
                }
                where = ", ".join(f"{k} +{v}" for k, v in caught.items() if v)
                report.add(
                    "unassigned_blocked",
                    "client with no egress cannot reach the internet",
                    reachable is None and not captured,
                    f"blocked ({where or 'no counter moved'})"
                    if reachable is None
                    else f"LEAKED - reached the internet as {reachable}",
                )
                # DNS, from the same unassigned state. Such a client misses the
                # DNAT that pins a client to its own resolver, so the input
                # chain is all that stops it asking any egress's resolver by
                # address - and choosing its exit country by the last octet.
                # The probes above never asked a resolver, which is how that
                # gap went unnoticed by this suite.
                answered = [addr for addr in self._resolver_addresses()
                            if self._resolves_via(addr)]
                report.add(
                    "unassigned_no_dns",
                    "client with no egress cannot use any resolver",
                    not answered,
                    "no resolver answered"
                    if not answered
                    else "LEAKED - answered by " + ", ".join(answered),
                )
                client.egress_kind = egress_kind
                client.egress_slug = egress_slug
                self.db.update_client(client)
                self.service.reconciler.reconcile()
                time.sleep(2)

            # 4. IPv6 ------------------------------------------------------
            v6 = self._ns("ping", "-6", "-c", "1", "-W", "2",
                          "2606:4700:4700::1111", timeout=8)
            report.add(
                "ipv6_blocked", "IPv6 cannot escape",
                not v6.ok,
                "blocked" if not v6.ok
                else "LEAKED - IPv6 reached the internet outside the tunnel",
            )

            # 5. DNS hijack ------------------------------------------------
            self._check_dns(report)

            # 6. boot ordering ---------------------------------------------
            self._check_boot_order(report)

            # 7. the real test ---------------------------------------------
            if disrupt and proxy is not None:
                self._check_disrupted_proxy(report, proxy, wan)
            elif disrupt:
                self._check_disrupted(report, egress_kind, egress_slug, wan)
            else:
                report.add(
                    "disrupt_skipped", "kill switch under tunnel failure", True,
                    "SKIPPED - rerun with --disrupt to actually take the "
                    "tunnel down and measure it",
                    critical=False,
                )

        finally:
            self.unregister_client()
            self.teardown_namespace()
            self.service.reconciler.reconcile()

        return report

    # -- individual checks --------------------------------------------------

    def _local_wan_address(self) -> str:
        addrs = ifaces.addresses(self.settings.net.wan_iface)
        return next(iter(sorted(addrs)), "").split("/")[0]

    @staticmethod
    def _delta(before: dict, after: dict, name: str) -> int:
        return (after.get(name, {}).get("packets", 0)
                - before.get(name, {}).get("packets", 0))

    def _check_dns(self, report: Report) -> None:
        # Asking a resolver we never configured. If the answer comes back at
        # all, the DNAT caught it; a client cannot opt out by hard-coding 8.8.8.8.
        #
        # dig with eight seconds, not nslookup: nslookup gives up after two,
        # and a proxy exit - the lookup goes over TCP through the relay, the
        # entry tunnel and the proxy - is often slower than that while
        # working perfectly. Any response at all, even SERVFAIL, came from a
        # resolver that took a packet addressed to 8.8.8.8.
        res = self._ns("dig", "+time=8", "+tries=1", "@8.8.8.8", "example.com",
                       timeout=14)
        answered = res.ok and "status:" in (res.stdout or "")
        report.add(
            "dns_intercepted", "hard-coded public DNS is intercepted",
            answered,
            "8.8.8.8 was answered by the gateway's own resolver" if answered
            else "no answer; either the resolver is down or the DNAT is not "
                 "matching - check dns_hijacked counter",
        )

        chaos = self._ns(
            "sh", "-c",
            "timeout 5 dig +short +time=2 @8.8.8.8 chaos txt version.bind "
            "2>/dev/null || true",
            timeout=10,
        )
        is_ours = "dnsmasq" in (chaos.stdout or "").lower()
        report.add(
            "dns_is_ours", "the answering resolver is ours",
            is_ours,
            (chaos.stdout or "").strip() or "no CHAOS response (dig may be "
                                            "missing; not conclusive)",
            critical=False,
        )

    def _check_boot_order(self, report: Report) -> None:
        res = try_run(["systemctl", "show", "vpngw-killswitch.service",
                       "--property=Before", "--property=UnitFileState"])
        text = res.stdout or ""
        ordered = "network-pre.target" in text
        enabled = "UnitFileState=enabled" in text
        report.add(
            "boot_order", "kill switch is loaded before the network at boot",
            ordered and enabled,
            "ordered before network-pre.target and enabled" if ordered and enabled
            else f"ordering/enablement problem: {text.strip() or 'unit not found'}",
        )

        res = try_run(["sysctl", "-n", "net.ipv4.ip_forward"])
        report.add(
            "sysctl_forward_off", "forwarding is off in the boot-time sysctl defaults",
            self._sysctl_default_is_zero(),
            "/etc/sysctl.d ships ip_forward=0; the daemon raises it only "
            "after a ruleset is loaded",
            critical=False,
        )

        # A gateway that emits ICMP redirects teaches clients to route around
        # it. Nothing else in this suite can catch that: once a client takes
        # the redirect its packets never arrive here, so no rule sees them and
        # no counter moves. The only place it is visible is the knob itself.
        noisy = self._interfaces_sending_redirects()
        report.add(
            "no_icmp_redirects",
            "the gateway does not teach clients to bypass it",
            not noisy,
            "no interface sends ICMP redirects" if not noisy
            else f"sending redirects on {', '.join(noisy)} - a client that "
                 f"obeys one leaves through the uplink with its own address, "
                 f"and nothing here would see it",
        )

    @staticmethod
    def _interfaces_sending_redirects() -> list[str]:
        """Interfaces with send_redirects still on.

        Checked per interface because the kernel ORs this setting rather than
        ANDing it: conf.all = 0 does not turn it off for adapters that already
        have it set.
        """
        from pathlib import Path

        out = []
        try:
            entries = sorted(Path("/proc/sys/net/ipv4/conf").iterdir())
        except OSError:
            return []
        for entry in entries:
            if entry.name == "default":
                continue
            knob = entry / "send_redirects"
            try:
                if knob.read_text().strip() != "0":
                    out.append(entry.name)
            except OSError:
                continue
        return out

    @staticmethod
    def _sysctl_default_is_zero() -> bool:
        from pathlib import Path
        for path in Path("/etc/sysctl.d").glob("*vpngw*.conf"):
            for line in path.read_text().splitlines():
                if line.replace(" ", "").startswith("net.ipv4.ip_forward=0"):
                    return True
        return False

    def _check_proxy(self, report: Report, t, exit_ip: str | None) -> None:
        """What only a proxy exit can get wrong: going around the proxy.

        A tunnel either carries a packet or blackholes it. A proxy exit has a
        third way to fail. Traffic that leaves through the entry tunnel
        without passing the proxy is no leak to the ISP, but it shows the
        destination the entry's address instead of the proxy's - the one
        thing the operator chose a proxy to change. Every observation is
        made at three points: the uplink, inside the entry tunnel, and on
        the veth into the proxy's namespace.
        """
        import secrets

        from .tunnels.proxy import server_of

        wan = self.settings.net.wan_iface
        entry = self.db.tunnel(t.via)
        if entry is None or not t.endpoints:
            report.add("proxy_server_via_entry",
                       "the proxy is dialled only through its entry tunnel", False,
                       f"cannot check: {t.via!r} is missing" if entry is None
                       else f"cannot check: {t.proxy.get('host')} is not resolved")
            return
        server, port = server_of(t), int(t.proxy["port"])
        to_server = f"host {server} and tcp port {port}"
        label = "vpngw-" + secrets.token_hex(5)
        before = nft.counters()

        with self._Watch(wan, f"host {server} or port 53 or {CANARY_BPF}",
                         [server, label, CANARY_HOST, str(CANARY_PORT)]) as on_wan, \
             self._Watch(entry.iface, f"({to_server}) or udp port 53 or {CANARY_BPF}",
                         [server, label, CANARY_HOST, str(CANARY_PORT)]) as in_entry, \
             self._Watch(t.iface, f"udp and ({CANARY_BPF})",
                         [" IP ", " IP6 "]) as into_ns, \
             self._Watch(t.iface, f"tcp and {to_server}", [label],
                         payload=True) as stream:
            self._reaches_internet(timeout=self.patience)
            self._canary(count=3)
            asked = self._ns("dig", f"+time={self.patience}", "+tries=1",
                             f"@{self.settings.dns.resolver_ip(t.esid)}",
                             f"{label}.example.com", timeout=self.patience + 6)
            wan_lines, entry_lines = on_wan.captured(), in_entry.captured()
            ns_udp, in_stream = into_ns.captured(), stream.captured()
        refused = self._delta(before, nft.counters(), "proxy_nontcp_drop")

        # 1. The exit is the proxy's. ------------------------------------
        entry_exit = self.service.reconciler.health.get(entry.slug).exit_ip
        if exit_ip and entry_exit:
            report.add(
                "proxy_exit_not_entry", "the exit is the proxy's, not the entry tunnel's",
                exit_ip != entry_exit,
                f"exits as {exit_ip}; {entry.slug} exits as {entry_exit}"
                if exit_ip != entry_exit
                else f"AROUND THE PROXY - the client exits as {entry.slug}'s own "
                     f"address {exit_ip}")
        else:
            report.add("proxy_exit_not_entry",
                       "the exit is the proxy's, not the entry tunnel's", False,
                       "not measured: " + ("the client reached nothing" if not exit_ip
                                           else f"{entry.slug}'s exit is not known yet"),
                       critical=False)

        # 2. Rule 2: the proxy is dialled through the entry, never the WAN.
        dialled_wan = [l for l in wan_lines if server in l]
        dialled_entry = [l for l in entry_lines if server in l]
        ok = not dialled_wan and bool(dialled_entry)
        report.add(
            "proxy_server_via_entry", "the proxy is dialled only through its entry tunnel",
            ok,
            f"{len(dialled_entry)} packet(s) to {server}:{port} inside {entry.iface}, "
            f"none on {wan}" if ok
            else f"LEAKED - {len(dialled_wan)} packet(s) to {server} on {wan}: "
                 f"{dialled_wan[:2]}" if dialled_wan
            else f"no packet to {server} was seen inside {entry.iface} either, so "
                 f"this capture proves nothing",
            critical=ok or bool(dialled_wan))

        # 3. UDP is refused, three ways.
        canary = (CANARY_HOST, str(CANARY_PORT))
        around = [l for l in entry_lines if any(c in l for c in canary)]
        out = [l for l in wan_lines if any(c in l for c in canary)]
        into = [l for l in ns_udp if any(c in l for c in canary)]
        ok = refused > 0 and not around and not out and not into
        seen = around or out or into
        report.add(
            "proxy_udp_refused", "client UDP is refused, not sent around the proxy",
            ok,
            f"refused (proxy_nontcp_drop +{refused}); none on {wan}, inside "
            f"{entry.iface} or into the namespace" if ok
            else f"AROUND THE PROXY - {len(seen)} packet(s): {seen[:2]}" if seen
            else "no packet was seen anywhere, but proxy_nontcp_drop did not move "
                 "either: the UDP was stopped somewhere this test does not watch",
            critical=ok or bool(seen))

        # 4. DNS goes through the proxy, over TCP.
        # The resolver's UDP into the namespace is by design - pxdns, in
        # there, turns it into TCP through the relay - so the veth is not
        # where to look. Plain DNS carrying this name anywhere past the
        # namespace would be the leak: on the uplink, or inside the entry.
        answered = asked.ok and "status:" in (asked.stdout or "")
        leaked = [l for l in wan_lines + entry_lines if label in l]
        ok = answered and not leaked
        report.add(
            "proxy_dns_through_proxy", "DNS is resolved through the proxy, over TCP",
            ok,
            ("answered; the name crossed the proxy over TCP and appeared nowhere "
             "else" if in_stream else
             "answered; the name appeared nowhere outside the proxy") if ok
            else f"AROUND THE PROXY - the lookup appeared as plain DNS: "
                 f"{leaked[:2]}" if leaked
            else "the lookup got no answer, so this proves nothing",
            critical=ok or bool(leaked))

    def _check_disrupted_proxy(self, report: Report, t, wan: str) -> None:
        """A proxy exit under the two failures that are its own.

        First its relay stops while everything else is up: a client must then
        reach nothing, rather than be carried by the entry tunnel without the
        proxy. Then the entry tunnel goes down: the relay must not reach for
        its proxy over the uplink, where the proxy's provider would see this
        gateway's own address. Clients on the entry and on the proxy lose
        connectivity for the duration.
        """
        from .tunnels import driver_for
        from .tunnels.proxy import DNS_UNIT, RELAY_UNIT, server_of

        entry = self.db.tunnel(t.via)
        if entry is None or not t.endpoints:
            report.add("disrupt_no_targets", "kill switch under tunnel failure",
                       False, f"{t.slug} has no entry or no resolved server to test")
            return
        server = server_of(t)
        units = [RELAY_UNIT.format(slug=t.slug), DNS_UNIT.format(slug=t.slug)]
        log.warning("stopping %s's relay, then taking %s down; clients on them "
                    "lose connectivity for the duration of this test",
                    t.slug, entry.slug)

        # A hold keeps the loop's hands off, but it also withdraws the held
        # tunnels' routes - and with the proxy's route gone, this would only
        # re-test the routing blackhole. Put that route back, so what refuses
        # the client is the namespace and the relay, which is the point.
        into_namespace = (t.table, t.iface, config.proxy_link(t.esid)[1])

        # 1. The relay stops. --------------------------------------------
        with self.service.reconciler.hold([t.slug]):
            try_run(["systemctl", "stop", *units])
            routing.set_default_via(*into_namespace)
            time.sleep(1)
            with self._UplinkWatch(wan) as on_wan, \
                 self._Watch(entry.iface, CANARY_BPF,
                             [CANARY_HOST, str(CANARY_PORT)]) as in_entry:
                self._canary(count=3)
                reachable = self._reaches_internet(timeout=5)
                routed = routing.table_default(t.table) == t.iface
                seen = on_wan.captured() + in_entry.captured()
            try_run(["systemctl", "start", *units])
            time.sleep(2)
        report.add(
            "disrupt_relay_stopped",
            f"with {t.slug}'s relay stopped, nothing goes around it",
            reachable is None and not seen,
            ("blocked inside the namespace, its route in place" if routed
             else "blocked, though its route had been withdrawn")
            + f"; nothing on {wan} or inside {entry.iface}"
            if reachable is None and not seen
            else f"AROUND THE PROXY - the client still reached the internet as "
                 f"{reachable}" if reachable
            else f"LEAKED - {len(seen)} packet(s): {seen[:3]}")

        # 2. The entry goes down. ----------------------------------------
        with self.service.reconciler.hold([entry.slug, t.slug]):
            driver_for(entry).down(entry)
            routing.set_default_via(*into_namespace)
            time.sleep(2)
            with self._Watch(wan, f"{CANARY_BPF} or host {server}",
                             [CANARY_HOST, str(CANARY_PORT), server],
                             count=200) as watch, \
                 self._Watch(t.iface, f"tcp and host {server}", [server],
                             count=200) as tries:
                self._canary(count=6)
                reachable = self._reaches_internet(timeout=5)
                captured = watch.captured()
                tried = [l for l in tries.captured() if f"> {server}" in l]
            blackholed = self._table_has_only_blackhole(entry.table)

        dialled = [l for l in captured if server in l]
        leaked = [l for l in captured if l not in dialled]
        report.add(
            "disrupt_unreachable",
            f"internet is unreachable while {entry.slug} is down",
            reachable is None,
            "blocked" if reachable is None
            else f"LEAKED - client still reached the internet as {reachable}")
        report.add(
            "disrupt_tcpdump", "nothing reached the uplink (tcpdump)",
            not leaked,
            f"0 packets on {wan}" if not leaked
            else f"LEAKED - {len(leaked)} packet(s): {leaked[:3]}")
        report.add(
            "disrupt_proxy_server",
            f"the proxy was not dialled over the uplink while {entry.slug} was down",
            not dialled,
            (f"the relay tried {server} {len(tried)} time(s); none of it reached "
             f"{wan}" if tried else
             f"0 packets to {server} on {wan}, though the relay made no attempt "
             f"in the window") if not dialled
            else f"LEAKED - {len(dialled)} packet(s) to {server} on {wan}: "
                 f"{dialled[:2]}")
        report.add(
            "disrupt_blackhole",
            f"routing table {entry.table} fell back to blackhole",
            blackholed,
            "only the blackhole default remains" if blackholed
            else "a real default route was still present - the kernel-level "
                 "failsafe is NOT in effect")
        log.info("%s and %s restored", t.slug, entry.slug)

    def _check_disrupted(self, report: Report, egress_kind: EgressKind,
                         egress_slug: str, wan: str) -> None:
        """The measurement everything else exists to support."""
        from .tunnels import driver_for

        if egress_kind is EgressKind.TUNNEL:
            targets = [self.db.tunnel(egress_slug)]
        else:
            pool = self.db.pool(egress_slug)
            if not pool:
                raise ValidationError(f"unknown pool {egress_slug!r}")
            targets = [self.db.tunnel(m.tunnel_slug) for m in pool.members]
        targets = [t for t in targets if t]
        if not targets:
            report.add("disrupt_no_targets", "kill switch under tunnel failure",
                       False, "no tunnels to disrupt")
            return

        names = ", ".join(t.slug for t in targets)
        log.warning("taking %s down; clients on it will lose connectivity "
                    "for the duration of this test", names)

        before = nft.counters()

        # The reconcile loop restores a downed tunnel within its probe
        # interval, so simply calling down() and measuring is a race the loop
        # wins - and losing it quietly produces a *passing* result for the
        # wrong reason. Hold the tunnels for the duration instead; the hold is
        # released even if this raises.
        with self.service.reconciler.hold(t.slug for t in targets):
            for t in targets:
                driver_for(t).down(t)
            time.sleep(2)

            with self._UplinkWatch(wan) as watch:
                self._canary(count=6)
                reachable = self._reaches_internet(timeout=5)
                captured = watch.captured()
            after = nft.counters()

            blackholed = {t.slug: self._table_has_only_blackhole(t.table)
                          for t in targets}

        leaked_pkts = self._delta(before, after, "wan_leak_drop")
        nontunnel = self._delta(before, after, "nontunnel_drop")
        unclassified = self._delta(before, after, "unclassified_drop")

        report.add(
            "disrupt_unreachable",
            f"internet is unreachable while {names} is down",
            reachable is None,
            "blocked" if reachable is None
            else f"LEAKED - client still reached the internet as {reachable}",
        )
        report.add(
            "disrupt_tcpdump", "nothing reached the uplink (tcpdump)",
            not captured,
            f"0 packets on {wan}" if not captured
            else f"LEAKED - {len(captured)} packet(s): {captured[:3]}",
        )
        # Which layer catches it depends on how far the packet got. With the
        # blackhole in place the routing layer discards it before the firewall
        # is consulted, so the counters legitimately stay at zero - that is the
        # stronger result, not a missing one. Only "nothing stopped it
        # anywhere" would be a finding, and the two checks above cover that.
        firewall_saw_it = (leaked_pkts + nontunnel + unclassified) > 0
        all_blackholed = all(blackholed.values()) if blackholed else False
        report.add(
            "disrupt_counters", "the attempt was stopped and accounted for",
            firewall_saw_it or all_blackholed,
            f"firewall: wan_leak_drop +{leaked_pkts}, nontunnel_drop "
            f"+{nontunnel}, unclassified_drop +{unclassified}"
            if firewall_saw_it
            else "discarded by the routing blackhole before reaching the "
                 "firewall, which is why no counter moved",
            critical=False,
        )

        for t in targets:
            # Sampled while the tunnels were held, not afterwards: by now the
            # reconcile loop has restored the real default route, and reading
            # it here would report a failure that never happened.
            ok = blackholed.get(t.slug, False)
            report.add(
                "disrupt_blackhole",
                f"routing table {t.table} fell back to blackhole",
                ok,
                "only the blackhole default remains" if ok
                else "a real default route was still present - the "
                     "kernel-level failsafe is NOT in effect",
            )

        log.info("tunnels restored")

    @staticmethod
    def _table_has_only_blackhole(table: int) -> bool:
        res = try_run(["ip", "route", "show", "default", "table", str(table)])
        lines = [l for l in (res.stdout or "").splitlines() if l.strip()]
        if not lines:
            return False  # empty table falls through to main: worse, not better
        return all("blackhole" in l for l in lines)
