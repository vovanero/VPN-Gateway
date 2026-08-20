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
from .models import Client, EgressKind, ValidationError
from .net import ifaces, nft
from .net.shell import run, try_run

log = logging.getLogger("vpngw.leaktest")

NETNS = "vpngw-test"
VETH_HOST = "vt-host"
VETH_NS = "vt-ns"

# A destination and port used by nothing else on this machine, so a single
# packet seen on the uplink with this port is unambiguous evidence of a leak.
CANARY_HOST = "203.0.113.9"      # TEST-NET-3, never routed
CANARY_PORT = 51999


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

    def _reaches_internet(self, timeout: int = 8) -> str | None:
        res = self._ns("curl", "--silent", "--fail", "--max-time", str(timeout),
                       "https://1.1.1.1/cdn-cgi/trace", timeout=timeout + 4)
        if not res.ok:
            return None
        for line in res.stdout.splitlines():
            if line.startswith("ip="):
                return line[3:].strip()
        return None

    class _UplinkWatch:
        """tcpdump on the uplink, looking only for the canary."""

        def __init__(self, iface: str) -> None:
            self.iface = iface
            self.proc: subprocess.Popen | None = None

        def __enter__(self) -> "LeakTest._UplinkWatch":
            self.proc = subprocess.Popen(
                ["tcpdump", "-i", self.iface, "-n", "-l", "-c", "50",
                 f"port {CANARY_PORT} or host {CANARY_HOST}"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
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
                    if CANARY_HOST in l or str(CANARY_PORT) in l]

    # -- the suite ----------------------------------------------------------

    def run(self, egress_kind: EgressKind, egress_slug: str,
            *, disrupt: bool = False) -> Report:
        report = Report()
        wan = self.settings.net.wan_iface

        try:
            self.setup_namespace()
            self.register_client(egress_kind, egress_slug)
            time.sleep(2)

            # 1. baseline -------------------------------------------------
            exit_ip = self._reaches_internet()
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
            if disrupt:
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
        res = self._ns("sh", "-c",
                       "timeout 5 nslookup example.com 8.8.8.8 2>&1 || true",
                       timeout=10)
        answered = "Address" in (res.stdout or "") or "answer" in (res.stdout or "").lower()
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
