"""Policy routing: per-egress tables, blackhole fallbacks, ip rules.

The single most important property in this file is the blackhole route.

Every per-egress routing table contains two default routes:

    default dev wg-nl              metric 100
    blackhole default              metric 1000

The kernel prefers the lower metric, so traffic normally rides the tunnel. When
the tunnel interface goes down the kernel *automatically* withdraws every route
pointing at it, and the blackhole is all that remains. Packets are discarded in
the routing layer.

That happens inside the kernel, with no help from this daemon. If vpngw
crashes, is killed, or is stopped mid-reconcile, clients still cannot reach the
internet. The kill switch does not depend on the kill switch's own process
being alive.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .. import config
from .shell import run, try_run

log = logging.getLogger("vpngw.routing")


# ---------------------------------------------------------------------------
# routing tables
# ---------------------------------------------------------------------------


def ensure_blackhole(table: int) -> None:
    """Install the fallback discard route. Safe to call repeatedly."""
    run(
        [
            "ip", "route", "replace", "blackhole", "default",
            "metric", str(config.BLACKHOLE_METRIC),
            "table", str(table),
        ]
    )


def set_default_via(table: int, iface: str, gateway: str | None = None) -> None:
    """Point a table's default route at an interface, atomically."""
    argv = ["ip", "route", "replace", "default"]
    if gateway:
        argv += ["via", gateway]
    argv += [
        "dev", iface,
        "metric", str(config.DEFAULT_METRIC),
        "table", str(table),
    ]
    run(argv)
    log.info("table %d default -> %s%s", table, iface,
             f" via {gateway}" if gateway else "")


def clear_default(table: int) -> None:
    """Drop the real default so only the blackhole remains."""
    try_run(
        [
            "ip", "route", "del", "default",
            "metric", str(config.DEFAULT_METRIC),
            "table", str(table),
        ]
    )
    log.info("table %d default cleared (blackhole now active)", table)


def flush_table(table: int) -> None:
    try_run(["ip", "route", "flush", "table", str(table)])


def table_default(table: int) -> str | None:
    """Return the interface currently serving a table's real default route."""
    res = try_run(["ip", "-json", "route", "show", "default", "table", str(table)])
    if not res.ok:
        return None
    import json

    try:
        routes = json.loads(res.stdout or "[]")
    except ValueError:
        return None
    for r in routes:
        if r.get("type") == "blackhole":
            continue
        if r.get("dev"):
            return r["dev"]
    return None


# ---------------------------------------------------------------------------
# ip rules
# ---------------------------------------------------------------------------


def _rules() -> list[dict]:
    import json

    res = try_run(["ip", "-json", "rule", "show"])
    try:
        return json.loads(res.stdout or "[]")
    except ValueError:
        return []


def desired_rules(egresses, resolver_ip_for) -> list[list[str]]:
    """Build the full set of ip-rule argument lists we want to exist.

    Two rules per egress:
      * one selecting the table by fwmark  (forwarded client traffic)
      * one selecting it by source address (that egress's DNS resolver)
    """
    # Consulted first: locally connected destinations resolve from the main
    # table, and only traffic with nowhere local to go falls through to a
    # tunnel. Without it the tunnel tables' default route swallows replies
    # addressed to clients, because a default route matches those too.
    out: list[list[str]] = [
        [
            "from", "all", "lookup", "main",
            "suppress_prefixlength", "0",
            "priority", str(config.RULE_PRIO_LOCAL),
        ]
    ]
    for eg in egresses:
        out.append(
            [
                "from", "all",
                "fwmark", f"{eg.mark:#x}/{config.MARK_MASK:#x}",
                "lookup", str(eg.table),
                "priority", str(config.RULE_PRIO_MARK + eg.esid),
            ]
        )
        out.append(
            [
                "from", resolver_ip_for(eg.esid),
                "lookup", str(eg.table),
                "priority", str(config.RULE_PRIO_RESOLVER + eg.esid),
            ]
        )
    return out


def sync_rules(desired: list[list[str]]) -> None:
    """Make the kernel's rule set match ``desired`` exactly.

    Rules are identified by their priority, which we allocate deterministically
    from the esid, so reconciling is just "delete unknown priorities in our
    range, add missing ones".
    """
    ours_lo = config.RULE_PRIO_LOCAL
    ours_hi = config.RULE_PRIO_MARK + config.POOL_ESID_MAX

    want_by_prio: dict[int, list[str]] = {}
    for argv in desired:
        prio = int(argv[argv.index("priority") + 1])
        want_by_prio[prio] = argv

    have = {}
    for r in _rules():
        prio = int(r.get("priority", -1))
        if ours_lo <= prio <= ours_hi:
            have[prio] = r

    for prio in sorted(set(have) - set(want_by_prio)):
        try_run(["ip", "rule", "del", "priority", str(prio)])
        log.info("removed stale ip rule priority %d", prio)

    for prio, argv in sorted(want_by_prio.items()):
        if prio in have:
            continue
        run(["ip", "rule", "add", *argv])
        log.info("added ip rule priority %d: %s", prio, " ".join(argv))


def purge_rules() -> None:
    """Remove every rule vpngw owns. Used by ``vpngwctl teardown``."""
    ours_lo = config.RULE_PRIO_LOCAL
    ours_hi = config.RULE_PRIO_MARK + config.POOL_ESID_MAX
    for r in _rules():
        prio = int(r.get("priority", -1))
        if ours_lo <= prio <= ours_hi:
            try_run(["ip", "rule", "del", "priority", str(prio)])


# ---------------------------------------------------------------------------
# conntrack
# ---------------------------------------------------------------------------


def flush_conntrack_mark(mark: int) -> int:
    """Drop established flows pinned to an egress.

    Called on every failover. Without this, a flow that was established through
    the old tunnel keeps its conntrack entry and its reply path stays wrong -
    the client sees a hung connection instead of a clean reconnect, and in the
    worst case a NATed reply escapes through the new path with the old source.
    """
    res = try_run(["conntrack", "-D", "-m", str(mark)])
    # conntrack exits 1 when nothing matched, which is not an error for us.
    deleted = 0
    for line in (res.stderr or "").splitlines():
        if "flow entries have been deleted" in line:
            try:
                deleted = int(line.split()[0])
            except (ValueError, IndexError):
                pass
    if deleted:
        log.info("flushed %d conntrack entries for mark %d", deleted, mark)
    return deleted


# ---------------------------------------------------------------------------
# sysctls
# ---------------------------------------------------------------------------


def set_sysctl(key: str, value: str) -> None:
    try_run(["sysctl", "-w", f"{key}={value}"])


def _all_interface_names() -> list[str]:
    """Every interface with an IPv4 config directory, including ones created
    after boot - tunnels, bridges - which is why this is read each time rather
    than captured once."""
    try:
        return sorted(p.name for p in Path("/proc/sys/net/ipv4/conf").iterdir()
                      if p.is_dir() and p.name not in ("all", "default"))
    except OSError:
        return []


def harden_sysctls(net) -> None:
    """Kernel knobs that close leak paths the firewall cannot see."""
    # IPv6 is disabled wholesale on the client-facing side: a single router
    # advertisement from a rogue client VM would otherwise hand the others a
    # working v6 path that never enters our v4 policy routing.
    for iface in (net.lan_bridge, net.lan_member):
        set_sysctl(f"net.ipv6.conf.{iface}.disable_ipv6", "1")
        set_sysctl(f"net.ipv6.conf.{iface}.accept_ra", "0")
    set_sysctl("net.ipv6.conf.all.forwarding", "0")
    set_sysctl("net.ipv6.conf.default.accept_ra", "0")

    # Never accept or send redirects: an ICMP redirect can install a route that
    # bypasses the policy tables entirely.
    #
    # send_redirects has to be cleared on every interface individually. The
    # kernel ORs it (IN_DEV_ORCONF) rather than ANDing it, so conf.all=0 with
    # conf.eth0=1 - the Debian default - still sends them. That combination is
    # not a hypothetical: where clients share a segment with the real router,
    # the gateway ends up telling a client "do not come through me, go straight
    # to 203.0.113.1". The client obeys, its traffic never reaches this box
    # again, and it is on the internet with its own address. Nothing here can
    # see that happen: no rule is consulted, no counter moves, and the leak
    # test finds nothing, because the packets are not ours to drop. The
    # redirect is emitted by ip_forward() before the FORWARD hook runs, so
    # dropping the packet afterwards does not prevent it.
    set_sysctl("net.ipv4.conf.all.accept_redirects", "0")
    set_sysctl("net.ipv4.conf.default.accept_redirects", "0")
    set_sysctl("net.ipv4.conf.all.send_redirects", "0")
    set_sysctl("net.ipv4.conf.default.send_redirects", "0")
    for iface in _all_interface_names():
        set_sysctl(f"net.ipv4.conf.{iface}.send_redirects", "0")
        set_sysctl(f"net.ipv4.conf.{iface}.accept_redirects", "0")
    set_sysctl("net.ipv4.conf.all.accept_source_route", "0")

    # Loose reverse-path filtering: strict mode breaks legitimate asymmetric
    # paths across per-tunnel tables, loose still discards spoofed sources.
    set_sysctl("net.ipv4.conf.all.rp_filter", "2")

    # ARP flux. With Linux defaults, a host answers an ARP request for *any*
    # of its addresses on *any* interface. A gateway with two adapters on one
    # segment therefore answers the same "who has 10.0.0.1" from both, with a
    # different MAC each time, and the client's cache flaps between them. Half
    # its packets then arrive on the wrong interface and the return path
    # breaks - which looks like an intermittent fault anywhere except ARP.
    #
    #   arp_ignore=1   answer only for addresses configured on the interface
    #                  the request arrived on
    #   arp_announce=2 always source ARP requests from the best local address
    #                  for the target, not whatever the outgoing interface has
    set_sysctl("net.ipv4.conf.all.arp_ignore", "1")
    set_sysctl("net.ipv4.conf.default.arp_ignore", "1")
    set_sysctl("net.ipv4.conf.all.arp_announce", "2")
    set_sysctl("net.ipv4.conf.default.arp_announce", "2")
    # A bridge must not answer for addresses that live behind it either.
    set_sysctl("net.ipv4.conf.all.proxy_arp", "0")

    # Tracking enough connections for 10+ clients behind NAT.
    set_sysctl("net.netfilter.nf_conntrack_max", "131072")


def enable_forwarding(on: bool) -> None:
    """Toggle IPv4 forwarding.

    Left at 0 by /etc/sysctl.d/ at boot and only raised once a complete ruleset
    has been applied, so the window between "interfaces up" and "firewall
    loaded" cannot forward anything even in theory.
    """
    set_sysctl("net.ipv4.ip_forward", "1" if on else "0")
