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

import json
import logging
import os
import stat
import time
from pathlib import Path

from .. import config
from ..models import Tunnel, TunnelKind
from ..net.shell import CommandError, run, try_run
from .base import LinkInfo, TunnelDriver, link_exists, link_state

log = logging.getLogger("vpngw.wg")

DEFAULT_MTU = 1420


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
            if peer.get("endpoint"):
                lines.append(f"Endpoint = {peer['endpoint']}")
            allowed = peer.get("allowed_ips") or ["0.0.0.0/0"]
            lines.append("AllowedIPs = " + ", ".join(allowed))
            if peer.get("keepalive"):
                lines.append(f"PersistentKeepalive = {peer['keepalive']}")

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

    def up(self, t: Tunnel) -> LinkInfo:
        spec = self._load(t)
        iface = t.iface

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

        mtu = t.mtu or spec.get("mtu") or DEFAULT_MTU
        run(["ip", "link", "set", "mtu", str(mtu), "up", "dev", iface])

        info = link_state(iface)
        info.dns = spec.get("dns", [])
        log.info("wireguard %s up (mtu %s, addr %s)", iface, mtu, info.local_ip)
        return info

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
