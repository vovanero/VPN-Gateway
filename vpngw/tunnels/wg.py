"""WireGuard driver.

Deliberately does not use ``wg-quick``. wg-quick's convenience is exactly what
this project must not have: it installs default routes into the main table,
sets its own fwmark, and adds a suppress_prefixlength rule. Every one of those
would collide with the policy routing here, and its "Table = auto" behaviour is
what makes naive setups leak when the tunnel flaps.

We build the interface by hand instead: create the link, load the crypto
config, set the address, bring it up. Routes are the routing layer's job.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import stat
import time
from pathlib import Path

from .. import config
from ..models import Tunnel, TunnelKind
from ..net import ifaces
from ..net.shell import CommandError, run, try_run
from .base import LinkInfo, TunnelDriver, link_exists, link_state

log = logging.getLogger("vpngw.wg")

DEFAULT_MTU = 1420
#: IPv4 + UDP + WireGuard headers carried by every encrypted packet.
WG_OVERHEAD = 60
#: Never derive below this. Anything smaller is almost certainly a misread
#: parent rather than a real path, and IPv6 requires 1280 regardless.
MIN_MTU = 1280
#: A packet small enough to cross anything. Its only job is to tell "this
#: endpoint does not answer ICMP" apart from "this path is narrow", which are
#: opposite conclusions from the same silence.
PROBE_PING = 100
#: The smallest outer packet worth measuring: below this the inner MTU would
#: be under MIN_MTU anyway, so there is nothing left to learn.
PROBE_FLOOR = MIN_MTU + WG_OVERHEAD
#: Bisect to the byte. The bracket is only ~140 bytes wide, so exactness
#: costs about three extra probes - worth it, because an MTU that is a few
#: bytes short is indistinguishable from a bug when someone checks it later.
PROBE_GRAIN = 1


#: Sent when a config does not name one. 25 seconds is what every
#: provider that ships the line uses, and it is short enough to hold a
#: NAT binding open on the way out.
DEFAULT_KEEPALIVE = 25


def _split_endpoint(endpoint: str) -> tuple[str, str]:
    """``host:port`` -> (host, port), unwrapping a bracketed IPv6 literal."""
    host, sep, port = (endpoint or "").rpartition(":")
    return (host.strip("[]"), port) if sep else ((endpoint or ""), "")


def _is_name(host: str) -> bool:
    """True for a hostname, False for an address literal or nothing."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


class WireGuardDriver(TunnelDriver):
    kind = TunnelKind.WIREGUARD

    # -- config -------------------------------------------------------------

    def _load(self, t: Tunnel) -> dict:
        path = Path(t.config_path)
        if not path.exists():
            raise FileNotFoundError(f"tunnel {t.slug}: missing {path}")
        return json.loads(path.read_text())

    def _write_setconf(self, t: Tunnel, spec: dict) -> Path:
        """Render the subset of the config that ``wg setconf`` understands.

        Address/DNS/MTU are wg-quick extensions and must not appear here.
        Written to /run (tmpfs) so the private key never lands on disk.
        """
        lines = ["[Interface]", f"PrivateKey = {spec['private_key']}"]
        if spec.get("listen_port"):
            lines.append(f"ListenPort = {spec['listen_port']}")
        # Chained: this tunnel's own encrypted packets carry a mark that an
        # ip rule sends into the parent's routing table. setconf replaces
        # the whole device config, so omitting the line on an unchained
        # tunnel also *clears* a stale mark from an earlier chaining.
        if t.via:
            lines.append(f"FwMark = {t.outer_mark:#x}")
        for peer in spec.get("peers", []):
            lines.append("")
            lines.append("[Peer]")
            lines.append(f"PublicKey = {peer['public_key']}")
            if peer.get("preshared_key"):
                lines.append(f"PresharedKey = {peer['preshared_key']}")
            endpoint = self._endpoint_for(t, peer.get("endpoint", ""), spec)
            if endpoint:
                lines.append(f"Endpoint = {endpoint}")
            allowed = peer.get("allowed_ips") or ["0.0.0.0/0"]
            lines.append("AllowedIPs = " + ", ".join(allowed))
            # Always send one. A client tunnel with no keepalive cannot
            # bootstrap on a gateway that fails closed: WireGuard only
            # handshakes when it has something to send, and nothing has
            # anything to send until the tunnel is healthy - the egress table
            # holds a blackhole until then, so the health probe cannot get out
            # to create the traffic that would complete the handshake. The
            # tunnel sits there, interface up, peer configured, zero bytes
            # transferred, forever.
            #
            # Providers whose configs carry PersistentKeepalive hide this
            # entirely, which is why it went unnoticed: every tunnel imported
            # from Mullvad or NordVPN has the line. A hand-written config, or
            # one from a provider that leaves it out, does not.
            lines.append("PersistentKeepalive = "
                         f"{peer.get('keepalive') or DEFAULT_KEEPALIVE}")

        config.WG_RUNTIME.mkdir(parents=True, exist_ok=True)
        os.chmod(config.WG_RUNTIME, stat.S_IRWXU)
        path = config.WG_RUNTIME / f"{t.slug}.conf"
        # Create with 0600 before writing: never a moment where the key is
        # readable by another local account.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        return path

    # -- lifecycle ----------------------------------------------------------

    #: (slug, endpoint) -> largest outer packet measured, or 0 for "no ICMP".
    #: Keyed by endpoint so a provider moving us to another server re-probes.
    _probed: dict[tuple[str, str], int] = {}

    def up(self, t: Tunnel) -> LinkInfo:
        spec = self._load(t)
        iface = t.iface
        # Before the link exists, so a refusal leaves nothing behind and the
        # reconciler simply tries again next pass.
        self._check_chained_endpoints(t, spec)

        if not link_exists(iface):
            run(["ip", "link", "add", "dev", iface, "type", "wireguard"])

        conf = self._write_setconf(t, spec)
        try:
            run(["wg", "setconf", iface, str(conf)])
        finally:
            conf.unlink(missing_ok=True)

        # Addresses are replaced rather than added so a re-up after a provider
        # rotated our tunnel address does not leave the stale one behind.
        try_run(["ip", "-4", "addr", "flush", "dev", iface])
        for addr in spec.get("addresses", []):
            if ":" in addr:
                continue  # IPv6 inside the tunnel is not wired up; see docs
            run(["ip", "addr", "add", addr, "dev", iface])

        mtu = t.mtu or spec.get("mtu") or self._auto_mtu(t)
        run(["ip", "link", "set", "mtu", str(mtu), "up", "dev", iface])

        info = link_state(iface)
        info.dns = spec.get("dns", [])
        log.info("wireguard %s up (mtu %s, addr %s)", iface, mtu, info.local_ip)
        return info

    def _probe_path_mtu(self, endpoint: str, ceiling: int) -> int:
        """Largest IP packet that reaches ``endpoint`` with DF set, or 0.

        The interface a tunnel leaves through only knows its own size. It
        cannot know that the uplink is itself a client of another gateway
        whose tunnel is narrower - which is exactly the shape of a two-machine
        double VPN, and exactly where the arithmetic gives an answer that is
        80 bytes too generous. Asking the path is the only way to find out.

        Returns 0 when the endpoint does not answer ICMP at all. That is
        common enough that it must never be mistaken for a tiny path: an
        unanswered probe would otherwise clamp every such tunnel to the floor.
        """
        def fits(size: int) -> bool:
            res = try_run(["ping", "-M", "do", "-s", str(size - 28), "-c", "1",
                           "-W", "2", "-n", "-q", endpoint], timeout=5)
            return res.ok

        if not fits(PROBE_PING):
            return 0                      # silent endpoint; nothing to learn
        if fits(ceiling):
            return ceiling
        if not fits(PROBE_FLOOR):
            return PROBE_FLOOR            # narrower than we will go; clamp
        lo, hi = PROBE_FLOOR, ceiling
        while hi - lo > PROBE_GRAIN:
            mid = (lo + hi) // 2
            if fits(mid):
                lo = mid
            else:
                hi = mid
        return lo

    def _auto_mtu(self, t: Tunnel) -> int:
        """The largest inner MTU that still fits what carries this tunnel.

        Encrypted packets are 60 bytes larger than the plaintext inside them
        and have to fit whatever they ride on: the uplink for an ordinary
        tunnel, the parent tunnel for a chained one. A chained tunnel left at
        the flat 1420 default is 1420 inside a 1380 parent - 100 bytes too
        big - and the failure is the nastiest kind: the tunnel comes up, the
        handshake completes, small packets work, and large ones vanish. What
        an operator sees is a download that runs fine and an upload that dies,
        with nothing in any log.

        1420 stays the ceiling rather than becoming a starting point: on a
        plain 1500-byte uplink the arithmetic would allow 1440, but paths lie
        about their size often enough (PPPoE, tunnelled uplinks) that raising
        the default for everyone to gain 20 bytes is a bad trade. This only
        ever moves the MTU *down*, and only when something says it must.
        """
        carrier, path = self._carrier(t)
        ceiling = DEFAULT_MTU if path <= 0 else max(
            MIN_MTU, min(DEFAULT_MTU, path - WG_OVERHEAD))

        # Then ask the path itself, which knows things the interface does not.
        endpoint = (t.endpoints or [""])[0]
        cached = self._probed.get((t.slug, endpoint))
        if endpoint and cached is None:
            cached = self._probe_path_mtu(endpoint, ceiling + WG_OVERHEAD)
            self._probed[(t.slug, endpoint)] = cached
        if cached:
            probed = max(MIN_MTU, min(ceiling, cached - WG_OVERHEAD))
            if probed != ceiling:
                log.info("%s: mtu %d measured to %s (%d bytes was the largest "
                         "that got through; %s says %d)",
                         t.slug, probed, endpoint, cached, carrier, path)
            return probed

        if ceiling != DEFAULT_MTU:
            log.info("%s: mtu %d derived from %s (%d - %d overhead)",
                     t.slug, ceiling, carrier, path, WG_OVERHEAD)
        return ceiling

    @staticmethod
    def _carrier(t: Tunnel) -> tuple[str, int]:
        """Which interface carries this tunnel's encrypted packets, and its MTU."""
        if t.via:
            # The parent's kind is not knowable from its slug, so try both
            # prefixes; only one of them can exist.
            for prefix in (config.WG_PREFIX, config.OVPN_PREFIX):
                name = prefix + t.via
                if ifaces.exists(name):
                    return name, ifaces.mtu_of(name)
            return f"{t.via} (not up)", 0
        wan = config.Settings.load().net.wan_iface
        return wan, ifaces.mtu_of(wan) if ifaces.exists(wan) else 0

    # -- chained endpoints ----------------------------------------------------
    #
    # wg(8) resolves a hostname Endpoint itself, through the system resolver:
    # the bootstrap DNS, over the uplink. For a chained tunnel that asks the
    # ISP, in plaintext, for the exit provider's name every time the tunnel
    # comes up - the second hop's identity, which is what a double VPN exists
    # to hide. So a chained tunnel is handed the address vpngw resolved
    # through its parent, and never a name.

    @staticmethod
    def _resolved_for_names(t: Tunnel, spec: dict) -> list[str]:
        """Addresses in t.endpoints that came from names, not literal peers."""
        literal = {_split_endpoint(p.get("endpoint", ""))[0]
                   for p in spec.get("peers", [])
                   if not _is_name(_split_endpoint(p.get("endpoint", ""))[0])}
        return [e for e in t.endpoints if e not in literal]

    def _check_chained_endpoints(self, t: Tunnel, spec: dict) -> None:
        if not t.via:
            return
        named = [p for p in spec.get("peers", [])
                 if _is_name(_split_endpoint(p.get("endpoint", ""))[0])]
        if not named:
            return
        if len(named) > 1:
            raise RuntimeError(
                f"chained, and {len(named)} peers name their server by "
                f"hostname; there is no telling which resolved address is "
                f"whose, and wg would otherwise look them up over the uplink")
        if not self._resolved_for_names(t, spec):
            host = _split_endpoint(named[0]["endpoint"])[0]
            raise RuntimeError(
                f"chained, and {host} has not been resolved through {t.via} "
                f"yet. Not bringing it up: wg would look the name up over "
                f"the uplink. It comes up by itself once {t.via} can answer")

    def _endpoint_for(self, t: Tunnel, endpoint: str, spec: dict) -> str:
        if not endpoint or not t.via:
            return endpoint
        host, port = _split_endpoint(endpoint)
        if not _is_name(host):
            return endpoint
        resolved = self._resolved_for_names(t, spec)
        # _check_chained_endpoints has already refused the cases where this
        # is empty; the guard keeps a name out of the config regardless.
        return f"{resolved[0]}:{port}" if resolved and port else ""

    def down(self, t: Tunnel) -> None:
        # Deleting the link (rather than just downing it) makes the kernel
        # withdraw its routes, which promotes the blackhole in the policy
        # table. That is the failover path, so it must be unambiguous.
        try_run(["ip", "link", "del", "dev", t.iface])
        log.info("wireguard %s down", t.iface)

    # -- health -------------------------------------------------------------

    def handshake_age(self, t: Tunnel) -> float | None:
        res = try_run(["wg", "show", t.iface, "latest-handshakes"])
        if not res.ok:
            return None
        newest = 0
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2:
                try:
                    newest = max(newest, int(parts[1]))
                except ValueError:
                    pass
        if newest == 0:
            return None  # configured but never completed a handshake
        return time.time() - newest

    def transfer(self, t: Tunnel) -> tuple[int, int]:
        res = try_run(["wg", "show", t.iface, "transfer"])
        rx = tx = 0
        for line in (res.stdout or "").splitlines():
            parts = line.split()
            if len(parts) == 3:
                try:
                    rx += int(parts[1])
                    tx += int(parts[2])
                except ValueError:
                    pass
        return rx, tx

    def healthy_hint(self, t: Tunnel) -> tuple[bool | None, str]:
        if not link_exists(t.iface):
            return False, "interface missing"
        age = self.handshake_age(t)
        if age is None:
            return False, "no handshake yet"
        # A stale handshake means the peer stopped answering. Reporting it as
        # down here is faster than waiting for the probe to time out three
        # times, which matters for how long a pool takes to fail over.
        return (None, "") if age < 180 else (False, f"handshake {int(age)}s old")


def genkey() -> tuple[str, str]:
    """Generate a private/public keypair, for tunnels toward our own servers."""
    try:
        priv = run(["wg", "genkey"]).stdout.strip()
        pub = run(["wg", "pubkey"], input_text=priv).stdout.strip()
    except CommandError as exc:  # pragma: no cover - depends on host tooling
        raise RuntimeError("wireguard tools not installed") from exc
    return priv, pub
