"""Domain model.

Deliberately plain dataclasses over a hand-written sqlite3 layer rather than an
ORM: this runs on a gateway appliance where every extra dependency is another
thing that can fail to import at boot and leave the box without a firewall.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum

from . import config

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,%d}$" % (config.SLUG_MAX_LEN - 1))
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


class ValidationError(ValueError):
    """Raised for user-supplied values that would produce a broken ruleset."""


def validate_slug(slug: str) -> str:
    """Normalise and check a slug.

    Case is folded rather than rejected, so importing "NL01" works - but every
    lookup path has to fold too, or the tunnel would be unreachable by the name
    its owner typed. :func:`normalise_slug` is that shared entry point.
    """
    slug = normalise_slug(slug)
    if not SLUG_RE.match(slug):
        raise ValidationError(
            f"invalid slug {slug!r}: use letters, digits and dashes, "
            f"max {config.SLUG_MAX_LEN} chars, must not start with a dash"
        )
    return slug


def normalise_slug(slug: str) -> str:
    return slug.strip().lower()


# Sentinel meaning "the database has not allocated one yet". The range check
# below only applies once an esid has actually been assigned.
ESID_UNALLOCATED = 0


class TunnelKind(str, Enum):
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"


class HealthState(str, Enum):
    UP = "up"
    DOWN = "down"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class PoolStrategy(str, Enum):
    PRIORITY = "priority"      # lowest priority number that is healthy
    LATENCY = "latency"        # healthy member with the lowest RTT
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"


class EgressKind(str, Enum):
    TUNNEL = "tunnel"
    POOL = "pool"


# ---------------------------------------------------------------------------


@dataclass
class Tunnel:
    slug: str
    name: str
    kind: TunnelKind
    esid: int
    enabled: bool = True
    # Where the imported provider config lives (0600, under SECRETS_DIR).
    config_path: str = ""
    mtu: int = 0                       # 0 = driver default
    dns: list[str] = field(default_factory=list)
    # Every remote address this tunnel dials. Feeds the strict host-egress
    # allowlist; without it a strict ruleset would block the handshake itself.
    endpoints: list[str] = field(default_factory=list)
    endpoint_hosts: list[str] = field(default_factory=list)
    # Chaining. Empty = this tunnel's encrypted packets leave over the WAN,
    # as every tunnel did before v2. A slug = they leave through that tunnel
    # instead, making this the inner hop of a chain. Everything else about
    # the tunnel - esid, table, resolver, clients, pool membership - is
    # untouched by chaining; only where the *outside* goes changes.
    via: str = ""
    notes: str = ""
    id: int | None = None

    def __post_init__(self) -> None:
        self.slug = validate_slug(self.slug)
        self.via = normalise_slug(self.via) if self.via else ""
        if self.via == self.slug:
            raise ValidationError(f"{self.slug!r} cannot route through itself")
        if not isinstance(self.kind, TunnelKind):
            self.kind = TunnelKind(self.kind)
        if self.esid != ESID_UNALLOCATED and not (
            config.TUNNEL_ESID_MIN <= self.esid <= config.TUNNEL_ESID_MAX
        ):
            raise ValidationError(f"tunnel esid {self.esid} out of range")

    @property
    def iface(self) -> str:
        prefix = (
            config.WG_PREFIX
            if self.kind is TunnelKind.WIREGUARD
            else config.OVPN_PREFIX
        )
        return prefix + self.slug

    @property
    def table(self) -> int:
        return config.table_for(self.esid)

    @property
    def mark(self) -> int:
        return self.esid

    @property
    def outer_mark(self) -> int:
        """The mark this tunnel's own encrypted packets carry when chained.

        Disjoint from the client esid space (low 16 bits) by construction:
        bit 16 is always set, so no outer mark can ever satisfy a client
        rule's `/0xffff` match before its own rule has had the chance to.
        """
        return config.OUTER_MARK_BASE | self.esid


@dataclass
class PoolMember:
    tunnel_slug: str
    priority: int = 100

    def __post_init__(self) -> None:
        self.tunnel_slug = normalise_slug(self.tunnel_slug)


@dataclass
class Pool:
    slug: str
    name: str
    esid: int
    strategy: PoolStrategy = PoolStrategy.PRIORITY
    members: list[PoolMember] = field(default_factory=list)
    # Once failed over, do not switch back to a better member until it has been
    # continuously healthy for this long. Stops a flapping tunnel from dragging
    # every client through a reconnect every few seconds.
    sticky_seconds: int = 60
    rotate_seconds: int = 300          # round_robin only
    enabled: bool = True
    notes: str = ""
    id: int | None = None

    def __post_init__(self) -> None:
        self.slug = validate_slug(self.slug)
        if not isinstance(self.strategy, PoolStrategy):
            self.strategy = PoolStrategy(self.strategy)
        if self.esid != ESID_UNALLOCATED and not (
            config.POOL_ESID_MIN <= self.esid <= config.POOL_ESID_MAX
        ):
            raise ValidationError(f"pool esid {self.esid} out of range")

    @property
    def table(self) -> int:
        return config.table_for(self.esid)

    @property
    def mark(self) -> int:
        return self.esid

    def ordered_members(self) -> list[PoolMember]:
        return sorted(self.members, key=lambda m: (m.priority, m.tunnel_slug))


@dataclass
class Client:
    name: str
    ip: str
    egress_kind: EgressKind = EgressKind.TUNNEL
    egress_slug: str = ""
    mac: str = ""
    enabled: bool = True
    notes: str = ""
    id: int | None = None

    def __post_init__(self) -> None:
        try:
            addr = ipaddress.ip_address(self.ip)
        except ValueError as exc:
            raise ValidationError(f"invalid client IP {self.ip!r}") from exc
        if addr.version != 4:
            raise ValidationError("only IPv4 clients are supported")
        self.ip = str(addr)
        if not isinstance(self.egress_kind, EgressKind):
            self.egress_kind = EgressKind(self.egress_kind)
        self.egress_slug = normalise_slug(self.egress_slug)
        if self.mac:
            self.mac = self.mac.strip().lower().replace("-", ":")
            if not MAC_RE.match(self.mac):
                raise ValidationError(f"invalid MAC {self.mac!r}")

    def check_in_lan(self, networks) -> None:
        """Reject an address no client could plausibly have.

        Accepts either one network or several: a gateway can serve an isolated
        client segment, or clients that share the uplink's subnet, or both at
        once, and rejecting the second layout as a typo would be wrong.
        """
        if isinstance(networks, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            networks = [networks]
        networks = list(networks)
        addr = ipaddress.ip_address(self.ip)
        if not any(addr in n for n in networks):
            where = " or ".join(str(n) for n in networks)
            raise ValidationError(
                f"client IP {self.ip} is outside the client network(s) {where}"
            )


@dataclass
class Egress:
    """A resolved routing destination: either a tunnel or a pool.

    The renderer and the routing layer only ever deal in Egress objects, so
    "assign this client to a pool" and "assign it to a tunnel" are the same
    code path.
    """

    kind: EgressKind
    slug: str
    esid: int
    name: str

    @property
    def table(self) -> int:
        return config.table_for(self.esid)

    @property
    def mark(self) -> int:
        return self.esid

    @classmethod
    def of(cls, obj: Tunnel | Pool) -> "Egress":
        kind = EgressKind.TUNNEL if isinstance(obj, Tunnel) else EgressKind.POOL
        return cls(kind=kind, slug=obj.slug, esid=obj.esid, name=obj.name)


@dataclass
class TunnelHealth:
    """Runtime health of one tunnel. Not persisted across restarts."""

    slug: str
    state: HealthState = HealthState.UNKNOWN
    consecutive_ok: int = 0
    consecutive_fail: int = 0
    rtt_ms: float | None = None
    last_change: float = 0.0
    last_probe: float = 0.0
    up_since: float | None = None
    exit_ip: str | None = None
    exit_ip_checked: float = 0.0
    handshake_age: float | None = None
    last_error: str = ""

    @property
    def healthy(self) -> bool:
        return self.state is HealthState.UP
