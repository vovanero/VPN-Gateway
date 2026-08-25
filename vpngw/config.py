"""Static configuration: paths, network layout, mark/table allocation policy.

Everything the daemon needs to know that is *not* user-editable state lives
here. User-editable state (tunnels, clients, pools) lives in the database.

The one file an operator edits by hand is /etc/vpngw/vpngw.toml, loaded into
:class:`Settings`.
"""

from __future__ import annotations

import ipaddress
import os
import secrets
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Filesystem layout
# ---------------------------------------------------------------------------

ETC = Path(os.environ.get("VPNGW_ETC", "/etc/vpngw"))
RUN = Path(os.environ.get("VPNGW_RUN", "/run/vpngw"))
LIB = Path(os.environ.get("VPNGW_LIB", "/var/lib/vpngw"))
LOG = Path(os.environ.get("VPNGW_LOG", "/var/log/vpngw"))

CONFIG_FILE = ETC / "vpngw.toml"
DB_FILE = LIB / "vpngw.db"
SECRETS_DIR = ETC / "secrets"            # 0700, holds private keys / auth files
LOCAL_TOKEN = SECRETS_DIR / "local.token"  # root-only CLI credential
KILLSWITCH_NFT = ETC / "killswitch.nft"  # boot-time fail-closed skeleton
RUNTIME_NFT = RUN / "ruleset.nft"        # full generated ruleset
WG_RUNTIME = RUN / "wg"                  # generated wg setconf files (tmpfs)
OVPN_RUNTIME = RUN / "ovpn"              # generated openvpn configs
TUNNEL_STATE = RUN / "tunnels"           # per-tunnel env written by up scripts

# ---------------------------------------------------------------------------
# Mark / routing-table allocation
# ---------------------------------------------------------------------------
#
# A packet's "egress selector id" (esid) decides which routing table it uses.
# We keep the whole scheme inside the low 16 bits of the fwmark so that other
# subsystems remain free to use the upper bits.
#
#   esid 0             -> unassigned. Forwarding such a packet is a bug; the
#                         forward chain drops it.
#   esid 1    .. 999   -> individual tunnels
#   esid 1000 .. 1999  -> pools
#
# routing table id = TABLE_BASE + esid
#
MARK_MASK = 0xFFFF
TUNNEL_ESID_MIN, TUNNEL_ESID_MAX = 1, 999
POOL_ESID_MIN, POOL_ESID_MAX = 1000, 1999
TABLE_BASE = 100

# ip rule priorities. Lower number = evaluated first.
#
# RULE_PRIO_LOCAL is consulted before anything else and exists to keep locally
# connected destinations out of the tunnel tables. Those tables hold only a
# default route and a blackhole, and a default route matches *everything* -
# including the client sitting on the next interface. Without this rule a
# resolver's reply to a client gets routed into the tunnel instead of back to
# the machine that asked, which presents as "the internet works but no name
# resolves". `suppress_prefixlength 0` means "use the main table, but ignore
# its default route", so specific routes win and genuinely remote traffic still
# falls through to the policy tables below.
RULE_PRIO_LOCAL = 800
RULE_PRIO_RESOLVER = 900   # "from <resolver dummy ip> lookup <table>"
RULE_PRIO_MARK = 1000      # "fwmark <esid>/0xffff lookup <table>"

# Metric of the real default route inside a per-egress table. The blackhole
# route sits at BLACKHOLE_METRIC so it only wins when the real route is gone.
DEFAULT_METRIC = 100
BLACKHOLE_METRIC = 1000

# Interface naming. Linux caps interface names at 15 chars (IFNAMSIZ-1), so
# tunnel slugs are capped at 10 to leave room for the longest prefix.
SLUG_MAX_LEN = 10
WG_PREFIX = "wg-"
OVPN_PREFIX = "tun-"
DUMMY_IFACE = "vpngw0"     # carries the per-egress resolver addresses


def local_token() -> str:
    """The credential the on-box CLI uses to talk to its own daemon.

    Once a panel password exists the API stops answering anonymous callers,
    and vpngwctl would go with it - including ``vpngwctl passwd``, which is
    the documented way back in when the password is lost. That is the wrong
    thing to lock.

    So the daemon keeps a token only root can read. It grants nothing new:
    reading it already requires the account that owns the box. Returns "" if
    it cannot be read, and the caller simply goes without.
    """
    try:
        if LOCAL_TOKEN.exists():
            existing = LOCAL_TOKEN.read_text().strip()
            if existing:
                return existing
    except OSError:
        return ""
    try:
        token = secrets.token_urlsafe(32)
        write_secret(LOCAL_TOKEN, token + '\n')
        return token
    except OSError:
        return ""


def write_secret(path: Path, text: str) -> None:
    """Write a file containing a key or credential.

    Created with mode 0600 by ``os.open`` rather than written and then
    chmod-ed: between those two calls the file exists with whatever the umask
    allows, and for the seconds that window is open a WireGuard private key is
    readable by every account on the box. Small window, complete compromise.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:  # pragma: no cover - not all filesystems support it
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)


def table_for(esid: int) -> int:
    return TABLE_BASE + esid


def esid_is_pool(esid: int) -> bool:
    return POOL_ESID_MIN <= esid <= POOL_ESID_MAX


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

DEFAULT_TOML = '''\
# vpngw gateway configuration.  Restart vpngw.service after editing.

[net]
wan_iface   = "wan0"      # uplink toward the Hyper-V External switch
lan_bridge  = "br-lan"    # bridge holding the client-facing NIC
lan_member  = "lan0"      # physical NIC enslaved into the bridge
lan_cidr    = "10.10.0.1/24"
mgmt_iface  = "mgmt0"     # Internal switch, host <-> web UI only
mgmt_cidr   = "10.20.0.1/24"
# Interfaces SSH and the web panel answer on. Empty = the LAN bridge plus
# mgmt_iface, which is how a home router behaves: managed from inside, never
# from the uplink unless you add it here yourself.
admin_ifaces = []

[dns]
# Every client DNS query is DNAT-ed to a per-egress resolver on this subnet,
# regardless of what the client configured.  Non-negotiable: with static client
# IPs there is no DHCP to hand out a resolver, so we take it by force.
resolver_subnet = "10.99.0.0/21"
# Used only to resolve VPN endpoint hostnames before any tunnel exists.
bootstrap = ["1.1.1.1", "9.9.9.9"]
# Upstream used inside a tunnel when the VPN config does not specify one.
fallback_upstream = ["1.1.1.1", "9.9.9.9"]
block_dot = false          # also block client port 853 (DoT) - see docs

[killswitch]
strict_host_egress = true  # the gateway itself may only reach VPN endpoints
maintenance_minutes = 30   # default duration of "vpngwctl maintenance on"

[health]
probe_interval = 5         # seconds between fast liveness probes
probe_target   = "1.1.1.1"
probe_timeout  = 2
fail_threshold = 3         # consecutive failures before marking down
rise_threshold = 2         # consecutive successes before marking up
handshake_max_age = 180    # wireguard: seconds since last handshake
exitip_interval = 120      # how often to re-check the public IP per tunnel

[api]
bind = "10.20.0.1"
port = 8080
token = ""                 # optional; the firewall already limits this to mgmt
'''


def _toml_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_toml(settings: "Settings") -> str:
    """Serialise settings back to vpngw.toml.

    Hand-written rather than via a TOML library so the file keeps its comments:
    this is a config a person edits at 2am when the panel is unreachable, and a
    machine-flattened version with the explanations stripped out is a worse
    artifact than a slightly more verbose writer.
    """
    lines = [
        "# vpngw gateway configuration.",
        "# Written by vpngw; hand edits are preserved on the next write except",
        "# for comments inside the sections below.",
        "",
    ]
    notes = {
        "net": [
            "# client_ifaces: which interfaces client traffic is accepted from.",
            "# Empty means just lan_bridge (isolated segment). Adding wan_iface",
            "# supports clients that share the uplink's subnet - see docs.",
            "# admin_ifaces: interfaces SSH and the web panel answer on. Empty =",
            "# the LAN bridge plus mgmt_iface (the router default).",
        ],
        "wan": ["# mode = \"dhcp\" or \"static\"."],
        "dhcp": [
            "# DHCP for the client segment. Leave the range blank to derive it",
            "# from lan_cidr.",
        ],
        "dns": [
            "# Every client :53 query is intercepted and answered by the resolver",
            "# belonging to that client's own egress, whatever the client is",
            "# configured with. bootstrap must be reachable before any tunnel is.",
        ],
        "killswitch": [
            "# strict_host_egress: the gateway itself may only reach imported VPN",
            "# endpoints. Client traffic is unaffected either way.",
        ],
        "health": ["# Hysteresis: fail_threshold probes down, rise_threshold up."],
        "api": ["# The firewall already limits this to the management path."],
    }
    for name in settings.__dataclass_fields__:
        section = getattr(settings, name)
        lines.append(f"[{name}]")
        lines.extend(notes.get(name, []))
        for key, value in section.__dict__.items():
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")
    return "\n".join(lines)


@dataclass(frozen=True)
class NetSettings:
    wan_iface: str = "wan0"
    lan_bridge: str = "br-lan"
    lan_member: str = "lan0"
    lan_cidr: str = "10.10.0.1/24"
    mgmt_iface: str = "mgmt0"
    mgmt_cidr: str = "10.20.0.1/24"
    # Interfaces that may reach SSH and the web panel - the way a home router
    # thinks about it: management is a property of which side of the box you
    # are on, not of your source address. Source-range filtering (the old
    # admin_cidr) looked stricter but broke the common case: an operator on
    # the LAN side could not open the panel of their own gateway.
    #
    # Empty means the LAN bridge plus mgmt_iface, which is the router default:
    # manage it from inside, never from the internet side unless you name the
    # uplink here explicitly.
    admin_ifaces: tuple[str, ...] = ()

    def management_ifaces(self) -> tuple[str, ...]:
        """Where SSH and the panel answer, with the router default applied."""
        if self.admin_ifaces:
            return tuple(dict.fromkeys(self.admin_ifaces))
        out = [self.lan_bridge]
        if self.mgmt_iface:
            out.append(self.mgmt_iface)
        return tuple(out)

    # Which interfaces client traffic is accepted from. Empty means "the LAN
    # bridge", which is the isolated-segment design.
    #
    # Adding the uplink here supports the other common layout: clients sharing
    # the uplink's subnet and pointing their default route at this box. That
    # still confines a *registered* client to its tunnel - the forward chain is
    # unchanged - but it gives up one guarantee, and the difference is worth
    # being clear about. On an isolated segment a client has no other way out.
    # On a shared segment it does: it can ARP the real router directly, and
    # nothing here can see that, let alone stop it. The kill switch then covers
    # "traffic that comes to us", not "traffic this machine can send".
    client_ifaces: tuple[str, ...] = ()

    # Networks a client address may belong to. Empty means "the LAN subnet",
    # which is right for the isolated layout. When clients share the uplink's
    # subnet that network belongs here too, or registering one is rejected as a
    # typo. The check exists to catch a mistyped address, so it has to know
    # what correct looks like rather than assuming one answer.
    client_cidrs: tuple[str, ...] = ()

    def client_interfaces(self) -> list[str]:
        return list(self.client_ifaces) or [self.lan_bridge]

    def client_networks(self) -> list[ipaddress.IPv4Network]:
        if self.client_cidrs:
            return [ipaddress.ip_network(c, strict=False)
                    for c in self.client_cidrs]
        return [self.lan_network]

    @property
    def lan_network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_interface(self.lan_cidr).network

    @property
    def lan_address(self) -> ipaddress.IPv4Address:
        return ipaddress.ip_interface(self.lan_cidr).ip

    @property
    def mgmt_network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_interface(self.mgmt_cidr).network

    @property
    def mgmt_address(self) -> ipaddress.IPv4Address:
        return ipaddress.ip_interface(self.mgmt_cidr).ip


@dataclass(frozen=True)
class WanSettings:
    """How the uplink gets its address.

    Editable from the panel, which makes it the one setting that can cut off
    the machine you are editing it from - so applying a WAN change verifies
    connectivity afterwards and rolls back if it broke (see net/apply.py).
    """

    mode: str = "dhcp"              # "dhcp" or "static"
    address: str = ""               # static only, CIDR form
    gateway: str = ""
    dns: tuple[str, ...] = ()


@dataclass(frozen=True)
class DhcpSettings:
    """DHCP for the client segment.

    Off by default: with static client addresses there is nothing to hand out,
    and a DHCP server on a segment that already has one is a good way to break
    a lab. Turned on, it also gives the panel a list of machines that have
    appeared, which is how unregistered clients become visible instead of just
    silently blocked.
    """

    enabled: bool = False
    range_start: str = ""           # blank = derived from the LAN subnet
    range_end: str = ""
    lease_hours: int = 12
    # Hand out the gateway itself as the resolver. Cosmetic either way: every
    # client :53 packet is intercepted regardless of what the client believes.
    announce_dns: bool = True


@dataclass(frozen=True)
class DnsSettings:
    resolver_subnet: str = "10.99.0.0/21"
    bootstrap: tuple[str, ...] = ("1.1.1.1", "9.9.9.9")
    fallback_upstream: tuple[str, ...] = ("1.1.1.1", "9.9.9.9")
    block_dot: bool = False

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.resolver_subnet)

    def resolver_ip(self, esid: int) -> str:
        """Stable per-egress resolver address, derived from the esid.

        Deriving it arithmetically rather than allocating from a table means
        the mapping survives a restart, a database restore, and a
        hand-corrected config without any bookkeeping. The subnet therefore has
        to be wide enough for the whole esid range, which
        :meth:`Settings.validate` checks at startup.
        """
        net = self.network
        if not 0 < esid < net.num_addresses - 1:
            raise ValueError(f"esid {esid} does not fit in {net}")
        return str(net.network_address + esid)


@dataclass(frozen=True)
class KillswitchSettings:
    strict_host_egress: bool = True
    maintenance_minutes: int = 30


@dataclass(frozen=True)
class HealthSettings:
    probe_interval: int = 5
    probe_target: str = "1.1.1.1"
    probe_timeout: int = 2
    fail_threshold: int = 3
    rise_threshold: int = 2
    handshake_max_age: int = 180
    exitip_interval: int = 120


@dataclass(frozen=True)
class ApiSettings:
    bind: str = "10.20.0.1"
    port: int = 8080
    # Optional second lock. The firewall is the real one: the input chain only
    # accepts this port from the management interface, so the UI is reachable
    # from the Hyper-V host and nowhere else. Set a token if the management
    # segment has other machines on it.
    token: str = ""


@dataclass(frozen=True)
class Settings:
    net: NetSettings = field(default_factory=NetSettings)
    wan: WanSettings = field(default_factory=WanSettings)
    dhcp: DhcpSettings = field(default_factory=DhcpSettings)
    dns: DnsSettings = field(default_factory=DnsSettings)
    killswitch: KillswitchSettings = field(default_factory=KillswitchSettings)
    health: HealthSettings = field(default_factory=HealthSettings)
    api: ApiSettings = field(default_factory=ApiSettings)

    # -- serialisation ------------------------------------------------------

    def to_dict(self) -> dict:
        out: dict = {}
        for name in self.__dataclass_fields__:
            section = getattr(self, name)
            out[name] = {
                k: (list(v) if isinstance(v, tuple) else v)
                for k, v in section.__dict__.items()
            }
        return out

    def dhcp_range(self) -> tuple[str, str]:
        """The DHCP pool, derived from the LAN subnet when not set by hand.

        Derived rather than defaulted to a fixed range so that changing the
        client network in the panel does not silently leave the DHCP server
        handing out addresses from the old one.
        """
        net = self.net.lan_network
        gateway = self.net.lan_address
        start = self.dhcp.range_start
        end = self.dhcp.range_end
        if start and end:
            return start, end
        hosts = list(net.hosts())
        pool = [h for h in hosts if h != gateway]
        if len(pool) < 10:
            raise ValueError(f"{net} is too small for a DHCP pool")
        # Leave the low addresses free for machines that are statically
        # numbered - most labs put servers there.
        lo = pool[len(pool) // 2] if len(pool) > 40 else pool[len(pool) // 4]
        return str(lo), str(pool[-2])

    def write(self, path: Path | None = None) -> None:
        """Persist to vpngw.toml.

        Written to a temporary file in the same directory and renamed, so a
        crash mid-write cannot leave the gateway with a config it will refuse
        to parse on the next boot - which on this box means a machine that
        comes up forwarding nothing and cannot be told otherwise.
        """
        import os

        path = path or CONFIG_FILE
        self.validate()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".toml.tmp")
        tmp.write_text(render_toml(self))
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        path = path or CONFIG_FILE
        if not path.exists():
            return cls()
        raw = tomllib.loads(path.read_text())

        def sub(section: str, klass):
            data = dict(raw.get(section, {}))
            # tomllib gives lists; our dataclasses want tuples for hashability
            for k, v in list(data.items()):
                if isinstance(v, list):
                    data[k] = tuple(v)
            allowed = set(klass.__dataclass_fields__)
            # admin_cidr was replaced by admin_ifaces. A config written before
            # the rename must still boot the gateway - refusing to start over
            # a removed option would take the panel down with it, and the
            # panel is where the replacement is configured.
            if section == "net" and "admin_cidr" in data:
                data.pop("admin_cidr")
            unknown = set(data) - allowed
            if unknown:
                raise ValueError(f"[{section}] unknown keys: {sorted(unknown)}")
            return klass(**data)

        settings = cls(
            net=sub("net", NetSettings),
            wan=sub("wan", WanSettings),
            dhcp=sub("dhcp", DhcpSettings),
            dns=sub("dns", DnsSettings),
            killswitch=sub("killswitch", KillswitchSettings),
            health=sub("health", HealthSettings),
            api=sub("api", ApiSettings),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        """Fail at startup rather than halfway through a reconcile.

        A gateway that dies while applying a ruleset is not dangerous - the
        previous ruleset stays loaded and it is fail-closed - but it is
        confusing to debug. Catch the config mistakes that would cause it.
        """
        problems: list[str] = []

        # Every esid must have a resolver address, including the highest pool.
        needed = POOL_ESID_MAX + 2
        if self.dns.network.num_addresses < needed:
            problems.append(
                f"[dns] resolver_subnet {self.dns.resolver_subnet} holds "
                f"{self.dns.network.num_addresses} addresses; the esid range "
                f"needs at least {needed} (use a /21 or wider)"
            )

        lan, mgmt, res = (
            self.net.lan_network,
            self.net.mgmt_network,
            self.dns.network,
        )
        for a, b, na, nb in (
            (lan, mgmt, "lan_cidr", "mgmt_cidr"),
            (lan, res, "lan_cidr", "resolver_subnet"),
            (mgmt, res, "mgmt_cidr", "resolver_subnet"),
        ):
            if a.overlaps(b):
                problems.append(f"{na} {a} overlaps {nb} {b}")

        # Locking yourself out of a fail-closed gateway is not recoverable over
        # the network - by design, nothing else is listening. Refuse to start
        # with no management path at all rather than discover it after the
        # ruleset loads.
        if not self.net.management_ifaces():
            problems.append(
                "[net] no management path: admin_ifaces is empty and there is "
                "no LAN bridge or mgmt_iface to fall back to. Applying the "
                "ruleset would cut off all administrative access."
            )
        known = {self.net.wan_iface, self.net.lan_bridge, self.net.lan_member,
                 self.net.mgmt_iface} - {""}
        for iface in self.net.admin_ifaces:
            if iface not in known:
                problems.append(
                    f"[net] admin_ifaces names {iface!r}, which is not one of "
                    f"this gateway's interfaces ({', '.join(sorted(known))})"
                )

        ifaces = [self.net.wan_iface, self.net.lan_bridge, self.net.lan_member]
        if self.net.mgmt_iface:
            ifaces.append(self.net.mgmt_iface)
        if len(set(ifaces)) != len(ifaces):
            problems.append(f"[net] interface names must be distinct: {ifaces}")

        # The uplink being confused with the client side would point every
        # kill-switch rule at the wrong segment.
        if self.net.wan_iface in (self.net.lan_bridge, self.net.lan_member):
            problems.append("[net] wan_iface must not be part of the LAN bridge")

        if problems:
            raise ValueError(
                "invalid configuration:\n  - " + "\n  - ".join(problems)
            )
