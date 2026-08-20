"""Parsers for the config files providers hand out.

Two jobs, and the second one is the one that matters:

1. Extract what the drivers need (keys, addresses, peers, remotes).
2. Extract every remote address the tunnel will ever dial.

Point 2 feeds ``@vpn_endpoints``, the allowlist that strict host egress opens
for. Miss an endpoint and the tunnel silently fails to connect; guess too
broadly and the gateway gets a hole to the open internet. So endpoints are
taken from the config text itself, never from a wildcard.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from dataclasses import dataclass, field

log = logging.getLogger("vpngw.import")


class ImportError_(ValueError):
    """Raised when a config file cannot be understood well enough to run."""


# ---------------------------------------------------------------------------
# WireGuard
# ---------------------------------------------------------------------------

WG_SECTION = re.compile(r"^\[(\w+)\]\s*$")
KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")


@dataclass
class WgPeer:
    public_key: str = ""
    preshared_key: str = ""
    endpoint: str = ""
    allowed_ips: list[str] = field(default_factory=list)
    keepalive: int = 0


@dataclass
class WgSpec:
    private_key: str = ""
    listen_port: int = 0
    addresses: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    mtu: int = 0
    peers: list[WgPeer] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "private_key": self.private_key,
            "listen_port": self.listen_port,
            "addresses": self.addresses,
            "dns": self.dns,
            "mtu": self.mtu,
            "peers": [
                {
                    "public_key": p.public_key,
                    "preshared_key": p.preshared_key,
                    "endpoint": p.endpoint,
                    "allowed_ips": p.allowed_ips,
                    "keepalive": p.keepalive,
                }
                for p in self.peers
            ],
        }


def _split_list(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def parse_wireguard(text: str) -> WgSpec:
    spec = WgSpec()
    section = ""
    peer: WgPeer | None = None

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = WG_SECTION.match(line)
        if m:
            section = m.group(1).lower()
            if section == "peer":
                peer = WgPeer()
                spec.peers.append(peer)
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip().lower(), value.strip()

        if section == "interface":
            if key == "privatekey":
                spec.private_key = value
            elif key == "address":
                spec.addresses = _split_list(value)
            elif key == "dns":
                spec.dns = [d for d in _split_list(value) if ":" not in d]
            elif key == "mtu":
                spec.mtu = int(value) if value.isdigit() else 0
            elif key == "listenport":
                spec.listen_port = int(value) if value.isdigit() else 0
            # Table / PostUp / PreDown are wg-quick directives. Ignored on
            # purpose: routing and firewalling on this box are not negotiable
            # by an imported file.
        elif section == "peer" and peer is not None:
            if key == "publickey":
                peer.public_key = value
            elif key == "presharedkey":
                peer.preshared_key = value
            elif key == "endpoint":
                peer.endpoint = value
            elif key == "allowedips":
                peer.allowed_ips = _split_list(value)
            elif key == "persistentkeepalive":
                peer.keepalive = int(value) if value.isdigit() else 0

    if not spec.private_key:
        raise ImportError_("no PrivateKey in [Interface]")
    if not KEY_RE.match(spec.private_key):
        raise ImportError_("PrivateKey is not a valid 32-byte base64 key")
    if not spec.peers:
        raise ImportError_("no [Peer] section")
    for p in spec.peers:
        if not p.public_key:
            raise ImportError_("a [Peer] has no PublicKey")
        if not p.endpoint:
            raise ImportError_(f"peer {p.public_key[:8]}... has no Endpoint")
    if not any(a for a in spec.addresses if ":" not in a):
        raise ImportError_("no IPv4 Address in [Interface]")

    # A peer that does not carry a default route cannot be a client's exit.
    for p in spec.peers:
        if not p.allowed_ips:
            p.allowed_ips = ["0.0.0.0/0"]
    if not any(
        _covers_default(a) for p in spec.peers for a in p.allowed_ips
    ):
        log.warning(
            "no peer has AllowedIPs covering 0.0.0.0/0; this tunnel can only "
            "reach the prefixes it lists, not the internet"
        )
    return spec


def _covers_default(cidr: str) -> bool:
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen == 0
    except ValueError:
        return False


def wg_endpoint_hosts(spec: WgSpec) -> list[str]:
    hosts = []
    for p in spec.peers:
        host = p.endpoint.rsplit(":", 1)[0].strip("[]")
        if host:
            hosts.append(host)
    return hosts


# ---------------------------------------------------------------------------
# OpenVPN
# ---------------------------------------------------------------------------

REMOTE_RE = re.compile(r"^\s*remote\s+(\S+)(?:\s+(\d+))?(?:\s+(tcp|udp)\S*)?",
                       re.IGNORECASE)
INLINE_OPEN = re.compile(r"^<([a-z0-9-]+)>\s*$", re.IGNORECASE)
INLINE_CLOSE = re.compile(r"^</([a-z0-9-]+)>\s*$", re.IGNORECASE)


@dataclass
class OvpnSpec:
    remotes: list[tuple[str, int, str]] = field(default_factory=list)
    needs_auth: bool = False
    has_ca: bool = False
    dev_type: str = "tun"


def parse_openvpn(text: str) -> OvpnSpec:
    spec = OvpnSpec()
    inside: str | None = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue

        m = INLINE_CLOSE.match(line)
        if m:
            inside = None
            continue
        m = INLINE_OPEN.match(line)
        if m:
            inside = m.group(1).lower()
            if inside == "ca":
                spec.has_ca = True
            continue
        if inside:
            continue

        m = REMOTE_RE.match(line)
        if m:
            host = m.group(1)
            port = int(m.group(2)) if m.group(2) else 1194
            proto = (m.group(3) or "udp").lower()
            spec.remotes.append((host, port, proto))
            continue

        word = line.split()[0].lower()
        if word == "auth-user-pass":
            # Bare directive = prompt interactively, which a daemon cannot do.
            spec.needs_auth = len(line.split()) == 1
        elif word == "ca":
            spec.has_ca = True
        elif word == "dev-type":
            spec.dev_type = line.split()[1].lower()
        elif word == "dev" and len(line.split()) > 1:
            value = line.split()[1].lower()
            if value.startswith("tap"):
                spec.dev_type = "tap"

    if not spec.remotes:
        raise ImportError_("no 'remote' directive found")
    if spec.dev_type == "tap":
        raise ImportError_(
            "this is a tap (layer 2) config; vpngw routes at layer 3 and "
            "cannot use it as a client egress"
        )
    if not spec.has_ca:
        log.warning("no CA found in the config; the server may be unverifiable")
    return spec


def ovpn_endpoint_hosts(spec: OvpnSpec) -> list[str]:
    return [host for host, _, _ in spec.remotes]


# ---------------------------------------------------------------------------
# endpoint resolution
# ---------------------------------------------------------------------------


def resolve_endpoints(hosts: list[str]) -> tuple[list[str], list[str]]:
    """Split hosts into literal addresses and names, resolving the names.

    Returns ``(addresses, unresolved_hostnames)``. Names are kept so the
    reconciler can re-resolve them later: providers rotate the address behind a
    hostname, and a stale allowlist entry means the tunnel stops connecting
    with no obvious cause.
    """
    addrs: set[str] = set()
    names: list[str] = []

    for host in hosts:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            names.append(host)
        else:
            if ":" not in host:  # IPv6 endpoints are not wired up
                addrs.add(host)
            continue

    for name in names:
        try:
            infos = socket.getaddrinfo(name, None, family=socket.AF_INET)
        except socket.gaierror as exc:
            log.warning("cannot resolve endpoint %s: %s", name, exc)
            continue
        for info in infos:
            addrs.add(info[4][0])

    return sorted(addrs), names
