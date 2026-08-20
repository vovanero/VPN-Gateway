"""OpenVPN driver.

The process itself is supervised by systemd (``vpngw-ovpn@<slug>.service``)
rather than by this daemon. That is not just tidiness: it means OpenVPN keeps
retrying a flaky provider while vpngw is restarted for an upgrade, and it means
a crashed vpngw cannot leave an orphaned tunnel with nobody watching it.

The generated config is written to /run - tmpfs - because it may contain
inlined private keys. The imported provider file on disk is 0600 under
/etc/vpngw/secrets.
"""

from __future__ import annotations

import logging
import os
import stat
import time
from pathlib import Path

from .. import config
from ..models import Tunnel, TunnelKind
from ..net.shell import run, try_run
from ..render import openvpn as render_ovpn
from .base import LinkInfo, TunnelDriver, link_exists, link_state

log = logging.getLogger("vpngw.ovpn")

UNIT = "vpngw-ovpn@{slug}.service"
LINK_TIMEOUT = 45  # seconds to wait for the tun device after starting


class OpenVpnDriver(TunnelDriver):
    kind = TunnelKind.OPENVPN

    # -- state file ---------------------------------------------------------

    def _state_file(self, t: Tunnel) -> Path:
        return config.TUNNEL_STATE / f"{t.slug}.env"

    def read_state(self, t: Tunnel) -> dict[str, list[str]]:
        """Parse what the up script reported. Repeated keys accumulate."""
        path = self._state_file(t)
        out: dict[str, list[str]] = {}
        if not path.exists():
            return out
        for line in path.read_text().splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            if value:
                out.setdefault(key.strip(), []).append(value.strip())
        return out

    # -- config -------------------------------------------------------------

    def _write_runtime_config(self, t: Tunnel) -> Path:
        provider = Path(t.config_path)
        if not provider.exists():
            raise FileNotFoundError(f"tunnel {t.slug}: missing {provider}")

        auth = config.SECRETS_DIR / f"{t.slug}.auth"
        text, removed = render_ovpn.render(
            provider.read_text(errors="replace"),
            slug=t.slug,
            iface=t.iface,
            auth_file=str(auth) if auth.exists() else None,
            mtu=t.mtu,
        )
        if removed:
            log.info("%s: neutralised %d provider directives (%s)", t.slug,
                     len(removed), ", ".join(sorted({r.split()[0] for r in removed})))

        config.OVPN_RUNTIME.mkdir(parents=True, exist_ok=True)
        os.chmod(config.OVPN_RUNTIME, stat.S_IRWXU)
        path = config.OVPN_RUNTIME / f"{t.slug}.conf"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        return path

    # -- lifecycle ----------------------------------------------------------

    def up(self, t: Tunnel) -> LinkInfo:
        self._write_runtime_config(t)
        self._state_file(t).unlink(missing_ok=True)

        unit = UNIT.format(slug=t.slug)
        run(["systemctl", "restart", unit])

        deadline = time.time() + LINK_TIMEOUT
        while time.time() < deadline:
            if link_exists(t.iface):
                state = self.read_state(t)
                if state.get("state", [""])[0] == "up":
                    break
            time.sleep(0.5)
        else:
            log.warning("%s: tun device did not appear within %ds",
                        t.slug, LINK_TIMEOUT)
            return LinkInfo(exists=False)

        info = link_state(t.iface)
        state = self.read_state(t)
        # A pushed route-gateway is the reliable next hop; the p2p peer address
        # is the fallback for providers that push nothing.
        if state.get("gateway"):
            info.gateway = state["gateway"][0]
        info.dns = state.get("dns", [])
        if state.get("mtu"):
            try:
                info.mtu = int(state["mtu"][0])
            except ValueError:
                pass
        log.info("openvpn %s up (addr %s, gw %s)", t.iface, info.local_ip,
                 info.gateway)
        return info

    def down(self, t: Tunnel) -> None:
        try_run(["systemctl", "stop", UNIT.format(slug=t.slug)])
        # OpenVPN removes the tun on exit; if it was killed hard, make sure the
        # interface really is gone so the policy table falls to its blackhole.
        if link_exists(t.iface):
            try_run(["ip", "link", "del", "dev", t.iface])
        (config.OVPN_RUNTIME / f"{t.slug}.conf").unlink(missing_ok=True)
        log.info("openvpn %s down", t.iface)

    # -- health -------------------------------------------------------------

    def unit_active(self, t: Tunnel) -> bool:
        res = try_run(["systemctl", "is-active", UNIT.format(slug=t.slug)])
        return res.stdout.strip() == "active"

    def healthy_hint(self, t: Tunnel) -> tuple[bool | None, str]:
        if not self.unit_active(t):
            return False, "openvpn unit not active"
        if not link_exists(t.iface):
            return False, "tun device missing"
        if self.read_state(t).get("state", [""])[0] != "up":
            return False, "tunnel reported down"
        return None, ""
