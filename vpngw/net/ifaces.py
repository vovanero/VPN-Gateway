"""Interface plumbing: the LAN bridge, addresses, and orphan cleanup.

systemd-networkd owns the declarative side of this (see the .network files the
installer writes) so the box comes up correctly with vpngw stopped. What lives
here is verification and repair, plus the one thing networkd cannot do: find
tunnel interfaces belonging to tunnels that no longer exist and remove them.

An orphaned tunnel interface is not a leak - nothing routes to it - but it
keeps a stale name reserved and confuses every diagnostic, so it gets cleaned.
"""

from __future__ import annotations

import ipaddress
import json
import logging

from .. import config
from .shell import run, try_run

log = logging.getLogger("vpngw.ifaces")


def exists(iface: str) -> bool:
    return try_run(["ip", "link", "show", "dev", iface]).ok


def is_up(iface: str) -> bool:
    res = try_run(["ip", "-json", "link", "show", "dev", iface])
    try:
        entries = json.loads(res.stdout or "[]")
    except ValueError:
        return False
    if not entries:
        return False
    return "UP" in (entries[0].get("flags") or [])


def addresses(iface: str) -> set[str]:
    res = try_run(["ip", "-json", "addr", "show", "dev", iface])
    out: set[str] = set()
    try:
        for entry in json.loads(res.stdout or "[]"):
            for addr in entry.get("addr_info", []):
                if addr.get("family") == "inet":
                    out.add(f"{addr['local']}/{addr['prefixlen']}")
    except ValueError:
        pass
    return out


def ensure_bridge(bridge: str, member: str) -> None:
    """Make sure the client-facing bridge exists with its NIC enslaved.

    The client side is a bridge rather than the bare NIC for two reasons: it
    lets a second client-facing adapter be added later without redesigning the
    routing, and it lets `vpngwctl selftest` attach a veth and act as a real
    LAN client - which is what makes the leak test an actual measurement
    instead of a claim.
    """
    if not exists(bridge):
        run(["ip", "link", "add", "name", bridge, "type", "bridge"])
        log.info("created bridge %s", bridge)
    run(["ip", "link", "set", "up", "dev", bridge])

    if not exists(member):
        log.error("LAN member interface %s does not exist; clients cannot "
                  "reach the gateway", member)
        return

    res = try_run(["ip", "-json", "link", "show", "dev", member])
    try:
        entry = json.loads(res.stdout or "[]")[0]
    except (ValueError, IndexError):
        return
    if entry.get("master") != bridge:
        run(["ip", "link", "set", "dev", member, "master", bridge])
        log.info("enslaved %s into %s", member, bridge)
    run(["ip", "link", "set", "up", "dev", member])

    # The bridge speaks with the member's MAC, always. The kernel gives a new
    # bridge a random address, and under Hyper-V that is fatal in a way
    # nothing on this box can see: with MAC spoofing off (the default), the
    # virtual switch silently drops any frame whose source MAC is not the one
    # it assigned to the vNIC. Inbound traffic still arrives, so the gateway
    # sees clients ARP for it - it just cannot answer them. From the client
    # that is "destination host unreachable" to an address that is provably
    # up; from here, nothing is wrong anywhere.
    #
    # Pinning also stops the address drifting when the leak test attaches its
    # veth - an explicitly-set bridge MAC no longer follows the members.
    member_mac = entry.get("address", "")
    if member_mac:
        res = try_run(["ip", "-json", "link", "show", "dev", bridge])
        try:
            bridge_mac = json.loads(res.stdout or "[]")[0].get("address", "")
        except (ValueError, IndexError):
            bridge_mac = ""
        if bridge_mac.lower() != member_mac.lower():
            run(["ip", "link", "set", "dev", bridge, "address", member_mac])
            log.warning("bridge %s MAC pinned to %s (was %s) - a random "
                        "bridge MAC is dropped by Hyper-V unless spoofing "
                        "is enabled", bridge, member_mac, bridge_mac)


def ensure_address(iface: str, cidr: str) -> None:
    if not exists(iface):
        log.error("cannot address %s: interface missing", iface)
        return
    want = str(ipaddress.ip_interface(cidr))
    if want not in addresses(iface):
        run(["ip", "addr", "replace", want, "dev", iface])
        log.info("%s <- %s", iface, want)
    run(["ip", "link", "set", "up", "dev", iface])


def physical_names() -> set[str]:
    """Interfaces backed by real hardware, for the settings UI to offer.

    Filters out everything vpngw creates itself - offering the operator a
    choice of `wg-nl01` as their uplink would be an invitation to break the
    box in an interesting way.
    """
    import os

    out: set[str] = set()
    try:
        for name in os.listdir("/sys/class/net"):
            if name == "lo" or name.startswith(
                    (config.WG_PREFIX, config.OVPN_PREFIX, "veth", "docker",
                     "virbr", config.DUMMY_IFACE)):
                continue
            if os.path.exists(f"/sys/class/net/{name}/device"):
                out.add(name)
    except OSError:
        pass
    return out


def tunnel_ifaces() -> set[str]:
    """Every interface that looks like one of ours."""
    res = try_run(["ip", "-json", "link", "show"])
    out: set[str] = set()
    try:
        for entry in json.loads(res.stdout or "[]"):
            name = entry.get("ifname", "")
            if name.startswith((config.WG_PREFIX, config.OVPN_PREFIX)):
                out.add(name)
    except ValueError:
        pass
    return out


def remove_orphans(expected: set[str]) -> list[str]:
    removed = []
    for iface in sorted(tunnel_ifaces() - expected):
        try_run(["ip", "link", "del", "dev", iface])
        removed.append(iface)
        log.info("removed orphaned tunnel interface %s", iface)
    return removed


def counters(iface: str) -> tuple[int, int]:
    """Bytes received and transmitted on an interface.

    Read straight from sysfs rather than parsing `ip -s link`: it is a syscall
    instead of a process, which matters when this is sampled for every tunnel
    every few seconds.

    The counters reset to zero whenever the interface is recreated, so callers
    computing a rate have to treat a decrease as a restart rather than as
    negative throughput.
    """
    base = f"/sys/class/net/{iface}/statistics"
    try:
        with open(f"{base}/rx_bytes") as fh:
            rx = int(fh.read().strip())
        with open(f"{base}/tx_bytes") as fh:
            tx = int(fh.read().strip())
        return rx, tx
    except (OSError, ValueError):
        return 0, 0


def disable_offloads(iface: str) -> None:
    """Hyper-V's synthetic NIC offloads corrupt checksums on forwarded,
    NAT-ed traffic often enough to be worth turning off on a router. The
    symptom is maddening: most traffic works, some TCP streams stall."""
    for feature in ("tx", "rx", "tso", "gso", "gro", "lro"):
        try_run(["ethtool", "-K", iface, feature, "off"], timeout=10)
