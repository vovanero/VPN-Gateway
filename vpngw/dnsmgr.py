"""Per-egress DNS resolvers.

One dnsmasq instance per tunnel and per pool, each bound to its own address in
the resolver subnet. A client's :53 traffic is DNAT-ed to the instance
belonging to its egress, so a client's lookups travel the same tunnel as its
traffic - and, critically, stop when that tunnel stops.

The trick that makes this work is dnsmasq's ``server=<upstream>@<source>``
syntax, which binds the *outgoing* query socket to a specific source address.
Without it the kernel would pick a source only after choosing a route, the
``from <resolver-ip>`` policy rule would never match, and lookups would fall
back to the main table and leave over the uplink. That would be a DNS leak on a
box whose entire purpose is not to have one.

Resolvers for pools use the generic upstreams rather than a provider's own,
so that a failover between two providers does not require restarting the
resolver and blipping every client's name resolution.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

from . import config
from .models import Egress, EgressKind
from .net.shell import run, try_run

log = logging.getLogger("vpngw.dns")

DNS_RUNTIME = config.RUN / "dns"
UNIT = "vpngw-dns@{slug}.service"
# Written by the client-segment DHCP server when it is enabled. Read by
# discovery, which is why the constant exists even when DHCP is off.
DHCP_LEASES = config.LIB / "dhcp.leases"


def render_config(
    egress: Egress,
    resolver_ip: str,
    upstreams: list[str],
    *,
    cache_size: int = 1000,
) -> str:
    lines = [
        f"# vpngw resolver for {egress.kind.value} '{egress.slug}' ({egress.name})",
        "# GENERATED - do not edit.",
        "",
        f"listen-address={resolver_ip}",
        "bind-interfaces",
        "port=53",
        "",
        "# Never consult /etc/resolv.conf or /etc/hosts: this resolver's whole",
        "# job is to be reachable only through one specific tunnel.",
        "no-resolv",
        "no-poll",
        "no-hosts",
        "domain-needed",
        "bogus-priv",
        "",
        f"cache-size={cache_size}",
        "",
        "# The @source suffix binds outgoing queries to this resolver's own",
        "# address, which is what the 'from <ip> lookup <table>' policy rule",
        "# matches on. Remove it and every lookup leaves via the uplink.",
    ]
    for up in upstreams:
        lines.append(f"server={up}@{resolver_ip}")
    lines += [
        "",
        "log-facility=-",
        f"pid-file={DNS_RUNTIME}/{egress.slug}.pid",
    ]
    return "\n".join(lines) + "\n"


def upstreams_for(
    egress: Egress, settings: config.Settings, tunnel_dns: list[str]
) -> list[str]:
    if egress.kind is EgressKind.POOL:
        return list(settings.dns.fallback_upstream)
    usable = [d for d in tunnel_dns if ":" not in d]
    return usable or list(settings.dns.fallback_upstream)


def write_config(
    egress: Egress, settings: config.Settings, tunnel_dns: list[str]
) -> tuple[Path, str]:
    DNS_RUNTIME.mkdir(parents=True, exist_ok=True)
    os.chmod(DNS_RUNTIME, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
    resolver_ip = settings.dns.resolver_ip(egress.esid)
    text = render_config(
        egress, resolver_ip, upstreams_for(egress, settings, tunnel_dns)
    )
    path = DNS_RUNTIME / f"{egress.slug}.conf"
    previous = path.read_text() if path.exists() else ""
    if previous != text:
        path.write_text(text)
    return path, previous


# ---------------------------------------------------------------------------
# address plumbing
# ---------------------------------------------------------------------------


HOST_RESOLV = Path("/etc/resolv.conf")
HOST_RESOLV_HEADER = "# Managed by vpngw."


def ensure_host_resolver(bootstrap: list[str] | tuple[str, ...]) -> bool:
    """Point the gateway's own resolver at the servers it is allowed to reach.

    Not an opinion about how the machine should be configured - it is the only
    configuration that can work here. Strict host egress permits port 53 to
    @bootstrap_dns and nothing else, so any other nameserver in this file is a
    lookup that will time out rather than fail, which is worse.

    It also has to be written rather than left to the distribution. There is no
    resolvconf on a minimal Debian, so ``dns-nameservers`` in an interfaces
    stanza silently does nothing; and if DHCP ever runs on the uplink, dhcpcd
    overwrites the file with its own empty template. Either way the box ends up
    unable to resolve the hostname of the next VPN endpoint it is asked to
    connect to, and the only symptom is a tunnel that will not come up.

    Returns True if the file was changed.
    """
    servers = [s.strip() for s in bootstrap if s and s.strip()]
    if not servers:
        return False

    wanted = "\n".join([
        HOST_RESOLV_HEADER,
        "# The firewall only lets this machine reach these servers on port 53;",
        "# adding others here produces timeouts, not alternatives.",
        *[f"nameserver {s}" for s in servers],
        "options timeout:2 attempts:2",
        "",
    ])
    try:
        if HOST_RESOLV.exists() and HOST_RESOLV.read_text() == wanted:
            return False
    except OSError:
        pass

    try:
        # dhcpcd and friends like to leave this a symlink into their own state
        # directory; write the real file rather than through their link.
        if HOST_RESOLV.is_symlink():
            HOST_RESOLV.unlink()
        HOST_RESOLV.write_text(wanted)
    except OSError as exc:
        log.warning("could not write %s: %s", HOST_RESOLV, exc)
        return False
    log.info("host resolver set to %s", ", ".join(servers))
    return True


def ensure_dummy_iface() -> None:
    """The resolver addresses live on a dummy interface.

    A dummy device is used rather than the loopback so the addresses can be
    matched by ``iifname``/``oifname`` and so a stray route toward them cannot
    be confused with loopback traffic.
    """
    res = try_run(["ip", "link", "show", "dev", config.DUMMY_IFACE])
    if not res.ok:
        run(["ip", "link", "add", config.DUMMY_IFACE, "type", "dummy"])
    run(["ip", "link", "set", "up", "dev", config.DUMMY_IFACE])


def sync_addresses(settings: config.Settings, egresses: list[Egress]) -> None:
    ensure_dummy_iface()
    want = {settings.dns.resolver_ip(e.esid) for e in egresses}

    import json

    res = try_run(["ip", "-json", "addr", "show", "dev", config.DUMMY_IFACE])
    have: set[str] = set()
    try:
        for entry in json.loads(res.stdout or "[]"):
            for addr in entry.get("addr_info", []):
                if addr.get("family") == "inet":
                    have.add(addr["local"])
    except ValueError:
        pass

    for gone in sorted(have - want):
        try_run(["ip", "addr", "del", f"{gone}/32", "dev", config.DUMMY_IFACE])
    for new in sorted(want - have):
        run(["ip", "addr", "add", f"{new}/32", "dev", config.DUMMY_IFACE])
    if want - have or have - want:
        log.info("resolver addresses: %d active", len(want))


# ---------------------------------------------------------------------------
# process supervision
# ---------------------------------------------------------------------------


def ensure_running(egress: Egress, restart: bool) -> None:
    unit = UNIT.format(slug=egress.slug)
    if restart:
        run(["systemctl", "restart", unit])
        log.info("resolver for %s (re)started", egress.slug)
        return
    if try_run(["systemctl", "is-active", unit]).stdout.strip() != "active":
        run(["systemctl", "start", unit])
        log.info("resolver for %s started", egress.slug)


def stop(slug: str) -> None:
    try_run(["systemctl", "stop", UNIT.format(slug=slug)])
    (DNS_RUNTIME / f"{slug}.conf").unlink(missing_ok=True)


def running_slugs() -> set[str]:
    res = try_run(
        ["systemctl", "list-units", "--plain", "--no-legend", "--state=active",
         "vpngw-dns@*.service"]
    )
    out: set[str] = set()
    for line in (res.stdout or "").splitlines():
        unit = line.split()[0] if line.split() else ""
        if unit.startswith("vpngw-dns@") and unit.endswith(".service"):
            out.add(unit[len("vpngw-dns@"):-len(".service")])
    return out
