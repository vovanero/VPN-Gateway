"""Driver interface shared by the WireGuard and OpenVPN backends."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from ..models import Tunnel, TunnelKind
from ..net.shell import try_run

log = logging.getLogger("vpngw.tunnel")


@dataclass
class LinkInfo:
    """What the kernel currently knows about a tunnel interface."""

    exists: bool = False
    up: bool = False
    local_ip: str | None = None
    gateway: str | None = None      # OpenVPN tun in p2p mode needs an explicit via
    mtu: int | None = None
    dns: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)


def link_exists(iface: str) -> bool:
    return try_run(["ip", "link", "show", "dev", iface]).ok


def link_state(iface: str) -> LinkInfo:
    res = try_run(["ip", "-json", "addr", "show", "dev", iface])
    if not res.ok:
        return LinkInfo(exists=False)
    try:
        entries = json.loads(res.stdout or "[]")
    except ValueError:
        return LinkInfo(exists=False)
    if not entries:
        return LinkInfo(exists=False)
    e = entries[0]
    info = LinkInfo(
        exists=True,
        up=e.get("operstate") in ("UP", "UNKNOWN"),
        mtu=e.get("mtu"),
    )
    for addr in e.get("addr_info", []):
        if addr.get("family") == "inet":
            info.local_ip = addr.get("local")
            # A tun in point-to-point mode reports the far side here; that is
            # the only usable next hop for the policy table's default route.
            if addr.get("address"):
                info.gateway = addr["address"]
            break
    return info


class TunnelDriver:
    kind: TunnelKind

    def up(self, t: Tunnel) -> LinkInfo:  # pragma: no cover - interface
        raise NotImplementedError

    def down(self, t: Tunnel) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def state(self, t: Tunnel) -> LinkInfo:
        return link_state(t.iface)

    def healthy_hint(self, t: Tunnel) -> tuple[bool | None, str]:
        """Protocol-specific liveness signal, checked before the active probe.

        Returns ``(verdict, reason)`` where a verdict of ``None`` means "no
        opinion, go ahead and probe".
        """
        return None, ""


def driver_for(t: Tunnel) -> TunnelDriver:
    from .ovpn import OpenVpnDriver
    from .wg import WireGuardDriver

    return (
        WireGuardDriver() if t.kind is TunnelKind.WIREGUARD else OpenVpnDriver()
    )
