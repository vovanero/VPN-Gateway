"""Finding machines that are using this gateway but are not registered.

An unregistered client is dropped, silently and correctly - "unknown means
blocked" is the whole design. The trouble is that from the operator's side it
looks identical to a machine that is switched off, a typo'd address, or a
cable in the wrong port. Diagnosing it means ssh, tcpdump and reading counters.

So the gateway keeps a list of addresses it has actually seen on a
client-facing interface and does not recognise. Registering one becomes a
click, and a machine that quietly has no internet stops being invisible.

This is discovery, not admission: nothing here grants access. A machine listed
here is still being dropped until somebody assigns it an exit.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from dataclasses import dataclass, field

from .net.shell import try_run

log = logging.getLogger("vpngw.discovery")

# Addresses that are never a client: our own, broadcast, multicast.
IGNORED_LAST_OCTETS = {0, 255}


@dataclass
class Seen:
    ip: str
    mac: str = ""
    iface: str = ""
    hostname: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    # Evidence, so the panel can say *why* this machine is listed rather than
    # just asserting it. "arp" alone may be a stray neighbour; "forwarding"
    # means it is actively pointing its default route at us.
    sources: set[str] = field(default_factory=set)
    packets_blocked: int = 0

    def as_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "iface": self.iface,
            "hostname": self.hostname,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "sources": sorted(self.sources),
            "using_gateway": "forwarding" in self.sources,
        }


class Discovery:
    """Accumulates sightings across reconcile passes.

    Kept in memory rather than the database: this is observation, not
    configuration, and it should not survive a restart as though it were a
    decision somebody made.
    """

    def __init__(self, settings) -> None:
        self.settings = settings
        self.seen: dict[str, Seen] = {}

    # -- collection ---------------------------------------------------------

    def scan(self, registered: set[str]) -> None:
        now = time.time()
        client_ifaces = set(self.settings.net.client_interfaces())
        networks = self.settings.net.client_networks()
        local = self._local_addresses()

        for ip, mac, iface, source in self._sightings(client_ifaces, local):
            if ip in registered or not self._plausible(ip, networks, local):
                continue
            entry = self.seen.get(ip)
            if entry is None:
                entry = Seen(ip=ip, first_seen=now)
                self.seen[ip] = entry
                log.info("unregistered machine seen on %s: %s (%s)",
                         iface or "?", ip, source)
            entry.last_seen = now
            entry.sources.add(source)
            if mac:
                entry.mac = mac
            if iface:
                entry.iface = iface

        # Forget anything that has stopped appearing, and anything that has
        # since been registered - a stale list is worse than none because it
        # invites you to act on something that is no longer true.
        cutoff = now - 900
        for ip in list(self.seen):
            if ip in registered or self.seen[ip].last_seen < cutoff:
                self.seen.pop(ip, None)

    def _local_addresses(self) -> set[str]:
        """Every address this machine holds.

        Recomputed each pass rather than cached: an interface can gain an
        address at any time, and listing the gateway's own address as an
        unregistered client is the kind of noise that makes a list stop being
        read at all.
        """
        import json as _json

        out: set[str] = set()
        res = try_run(["ip", "-json", "addr", "show"])
        try:
            for entry in _json.loads(res.stdout or "[]"):
                for addr in entry.get("addr_info", []):
                    if addr.get("family") == "inet":
                        out.add(addr["local"])
        except ValueError:
            pass
        return out

    def _plausible(self, ip: str, networks, local: set[str]) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.is_multicast or addr.is_loopback or addr.is_link_local:
            return False
        if int(addr) & 0xFF in IGNORED_LAST_OCTETS:
            return False
        if ip in local:
            return False
        return any(addr in n for n in networks)

    def _sightings(self, client_ifaces: set[str], local: set[str]):
        """(ip, mac, iface, source) tuples from every cheap source we have."""
        yield from self._from_neighbours(client_ifaces)
        yield from self._from_conntrack(local)
        yield from self._from_leases()

    def _from_neighbours(self, client_ifaces: set[str]):
        """Neighbours on a *dedicated* client interface.

        On a segment that exists only for clients, a machine appearing there is
        a client by definition and worth listing before it sends anything. On
        the uplink it means nothing - the router, the admin's workstation and
        every other host on that network are neighbours too, and listing them
        turns the panel into noise nobody reads. So ARP counts only where
        presence implies intent; on the uplink we wait for actual forwarded
        traffic instead.
        """
        wan = self.settings.net.wan_iface
        dedicated = {i for i in client_ifaces if i != wan}
        if not dedicated:
            return

        res = try_run(["ip", "-json", "neigh", "show"])
        try:
            entries = json.loads(res.stdout or "[]")
        except ValueError:
            return
        for e in entries:
            iface = e.get("dev", "")
            if iface not in dedicated:
                continue
            state = e.get("state") or []
            if any(s in ("FAILED", "INCOMPLETE") for s in state):
                continue
            ip = e.get("dst", "")
            if ip:
                yield ip, e.get("lladdr", ""), iface, "arp"

    def _from_conntrack(self, local: set[str]):
        """Machines whose packets we are actually *forwarding*.

        Stronger evidence than ARP: it means this machine sent us traffic
        destined somewhere else, which is what pointing a default route at us
        looks like.

        Connections *to* this box - somebody's SSH session, a client's DNS
        query - are skipped. Those are conversations with the gateway, not
        traffic through it, and counting them would list the administrator's
        own workstation as an unregistered client every single pass.
        """
        res = try_run(["conntrack", "-L"], timeout=10)
        if not res.ok:
            return
        for line in (res.stdout or "").splitlines()[:4000]:
            src = re.search(r"\bsrc=(\d+\.\d+\.\d+\.\d+)", line)
            dst = re.search(r"\bdst=(\d+\.\d+\.\d+\.\d+)", line)
            if not src or not dst:
                continue
            if dst.group(1) in local:
                continue
            yield src.group(1), "", "", "forwarding"

    def _from_leases(self):
        from . import dnsmgr

        path = dnsmgr.DHCP_LEASES
        if not path.exists():
            return
        try:
            for line in path.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    yield parts[2], parts[1], "", "dhcp"
        except OSError:
            return

    # -- reporting ----------------------------------------------------------

    def report(self, counters: dict | None = None) -> list[dict]:
        blocked = 0
        if counters:
            blocked = counters.get("unclassified_drop", {}).get("packets", 0)
        out = []
        for entry in sorted(self.seen.values(),
                            key=lambda s: (not ("forwarding" in s.sources),
                                           s.ip)):
            row = entry.as_dict()
            row["blocked_total"] = blocked
            out.append(row)
        return out
