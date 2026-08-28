"""vpngwctl - the command line.

Mutating commands write to the database and then nudge the daemon, rather than
touching the kernel themselves. The daemon stays the only writer of nftables
and routing state even when an operator is driving from a shell, so there is
never a question of which process last won.

The exceptions are ``render`` and ``check``, which read only, and ``selftest``,
which is executed inside the daemon over the API for the same reason.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import config
from .db import Database
from .models import (
    Client,
    EgressKind,
    Pool,
    PoolMember,
    PoolStrategy,
    Tunnel,
    TunnelKind,
    ValidationError,
)

GREEN, RED, YELLOW, GREY, BOLD, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[90m", "\033[1m", "\033[0m"
)


def colour(text: str, code: str) -> str:
    return text if not sys.stdout.isatty() else f"{code}{text}{RESET}"


def state_colour(state: str) -> str:
    return {
        "up": GREEN, "down": RED, "disabled": GREY, "unknown": YELLOW,
        "unassigned": RED,
    }.get(state, "")


# ---------------------------------------------------------------------------
# daemon connection
# ---------------------------------------------------------------------------


class Daemon:
    def __init__(self, settings: config.Settings) -> None:
        self.base = f"http://{settings.api.bind}:{settings.api.port}"
        # Configured token first - an operator who set one meant it. Otherwise
        # the root-only local credential, which is what makes this CLI keep
        # working once a panel password is set.
        self.token = settings.api.token or config.local_token()

    def call(self, path: str, method: str = "GET", payload: dict | None = None,
             timeout: int = 300) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Content-Type": "application/json",
                     **({"x-vpngw-token": self.token} if self.token else {})},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            if exc.code == 401:
                raise SystemExit(
                    'the daemon refused this command.\n'
                    f"vpngwctl authenticates with {config.LOCAL_TOKEN}, which "
                    f"only root can read - run it with sudo.")
            raise SystemExit(f"daemon returned {exc.code}: {detail}")
        except urllib.error.URLError as exc:
            raise SystemExit(
                f"cannot reach the vpngw daemon at {self.base} ({exc.reason}).\n"
                f"Is it running?  systemctl status vpngw"
            )
        return json.loads(body) if body else {}

    def nudge(self) -> None:
        try:
            self.call("/api/reconcile", "POST", {})
        except SystemExit:
            print(colour("note: daemon not reachable; the change is saved and "
                         "will apply when it next starts", YELLOW),
                  file=sys.stderr)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def cmd_status(args, db, settings) -> int:
    snap = Daemon(settings).call("/api/status")

    ks = snap["killswitch"]
    leaked = ks["leaked_packets"]
    print(colour("KILL SWITCH", BOLD))
    verdict = (
        colour("armed - 0 packets have ever reached the uplink", GREEN)
        if leaked == 0 else
        colour(f"armed - {leaked} forwarded packet(s) were BLOCKED at the "
               f"uplink (this is the switch working, not a leak)", YELLOW)
    )
    print(f"  {verdict}")
    if ks["maintenance"]:
        mins = ks["maintenance_remaining"] // 60
        print("  " + colour(f"maintenance window open for {mins} more minute(s)"
                            " - the gateway's own egress is unrestricted; "
                            "client traffic is not affected", YELLOW))
    print()

    print(colour("TUNNELS", BOLD))
    if not snap["tunnels"]:
        print(colour("  none configured", GREY))
    for t in snap["tunnels"]:
        state = colour(f"{t['state']:<8}", state_colour(t["state"]))
        rtt = f"{t['rtt_ms']:.0f}ms" if t.get("rtt_ms") else "-"
        exit_ip = t.get("exit_ip") or "-"
        routed = "" if t["routed"] else colour("  [no route]", YELLOW)
        print(f"  {state} {t['slug']:<12} {t['kind']:<9} {t['iface']:<14} "
              f"{rtt:>7}  exit {exit_ip}{routed}")
        if t["state"] == "down" and t.get("last_error"):
            print(colour(f"           {t['last_error']}", GREY))
    print()

    if snap["pools"]:
        print(colour("POOLS", BOLD))
        for p in snap["pools"]:
            active = p["active"] or colour("NONE HEALTHY", RED)
            print(f"  {p['slug']:<12} {p['strategy']:<12} active: {active}"
                  f"   ({p['healthy_members']}/{len(p['members'])} up)")
            if p.get("reason"):
                print(colour(f"           {p['reason']}", GREY))
            for m in p["members"]:
                mark = ">" if m["slug"] == p["active"] else " "
                print(colour(f"         {mark} {m['slug']:<12} prio "
                             f"{m['priority']:<4} {m['state']}", GREY))
        print()

    print(colour("CLIENTS", BOLD))
    if not snap["clients"]:
        print(colour("  none configured", GREY))
    for c in snap["clients"]:
        state = colour(f"{c['egress_state']:<10}", state_colour(c["egress_state"]))
        target = (f"{c['egress_kind']}:{c['egress_slug']}"
                  if c["egress_slug"] else colour("UNASSIGNED (blocked)", RED))
        flag = "" if c["enabled"] else colour("  [disabled]", GREY)
        print(f"  {state} {c['ip']:<16} {c['name']:<14} -> {target}{flag}")

    if snap.get("last_error"):
        print()
        print(colour(f"daemon error: {snap['last_error']}", RED))
    return 0


# ---------------------------------------------------------------------------
# tunnels
# ---------------------------------------------------------------------------


def cmd_tunnel_import(args, db: Database, settings) -> int:
    from .importers import (
        ImportError_,
        ovpn_endpoint_hosts,
        parse_openvpn,
        parse_wireguard,
        resolve_endpoints,
        wg_endpoint_hosts,
    )

    source = Path(args.file)
    if not source.exists():
        raise SystemExit(f"no such file: {source}")
    text = source.read_text(errors="replace")

    kind = TunnelKind(args.kind) if args.kind else _guess_kind(source, text)
    config.SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    config.SECRETS_DIR.chmod(0o700)

    try:
        if kind is TunnelKind.WIREGUARD:
            spec = parse_wireguard(text)
            hosts = wg_endpoint_hosts(spec)
            stored = config.SECRETS_DIR / f"{args.slug}.json"
            config.write_secret(stored, json.dumps(spec.to_dict(), indent=2))
            dns = spec.dns
            mtu = spec.mtu
        else:
            spec = parse_openvpn(text)
            hosts = ovpn_endpoint_hosts(spec)
            stored = config.SECRETS_DIR / f"{args.slug}.ovpn"
            config.write_secret(stored, text)
            dns, mtu = [], 0
            if spec.needs_auth and not args.auth:
                print(colour(
                    "this config expects a username and password. Create "
                    f"{config.SECRETS_DIR}/{args.slug}.auth with the username "
                    "on line 1 and the password on line 2, chmod 600, then "
                    "enable the tunnel.", YELLOW), file=sys.stderr)
    except ImportError_ as exc:
        raise SystemExit(f"cannot import: {exc}")


    if args.auth:
        auth_src = Path(args.auth)
        if not auth_src.exists():
            raise SystemExit(f"no such auth file: {auth_src}")
        config.write_secret(config.SECRETS_DIR / f"{args.slug}.auth",
                            auth_src.read_text())

    addrs, names = resolve_endpoints(hosts)
    if not addrs:
        print(colour(
            "warning: no endpoint address could be resolved. With strict host "
            "egress on, the gateway will refuse to dial this tunnel until at "
            "least one address is known.", YELLOW), file=sys.stderr)

    tunnel = Tunnel(
        slug=args.slug,
        name=args.name or args.slug,
        kind=kind,
        esid=db.next_tunnel_esid(),
        enabled=not args.disabled,
        config_path=str(stored),
        mtu=args.mtu or mtu,
        dns=dns,
        endpoints=addrs,
        endpoint_hosts=names,
    )
    db.add_tunnel(tunnel)
    print(f"imported {colour(tunnel.slug, BOLD)} "
          f"({kind.value}, interface {tunnel.iface}, table {tunnel.table})")
    print(f"  endpoints: {', '.join(addrs) or 'none resolved'}")
    Daemon(settings).nudge()
    return 0


def _guess_kind(path: Path, text: str) -> TunnelKind:
    if path.suffix.lower() in (".ovpn", ".conf") and "remote " in text:
        if "[Interface]" not in text:
            return TunnelKind.OPENVPN
    if "[Interface]" in text and "PrivateKey" in text:
        return TunnelKind.WIREGUARD
    if "remote " in text or "<ca>" in text:
        return TunnelKind.OPENVPN
    raise SystemExit(
        "cannot tell whether this is a WireGuard or OpenVPN config; "
        "pass --kind wireguard|openvpn"
    )


def cmd_tunnel_import_bundle(args, db: Database, settings) -> int:
    """Import a whole provider archive at once."""
    from . import bundle
    from .importers import ImportError_

    path = Path(args.path)
    if not path.exists():
        raise SystemExit(f"no such path: {path}")

    try:
        candidates = bundle.scan(path)
    except ImportError_ as exc:
        raise SystemExit(f"cannot read the bundle: {exc}")

    usable = [c for c in candidates if c.usable]
    skipped = [c for c in candidates if not c.usable]

    if args.filter:
        needle = args.filter.lower()
        usable = [c for c in usable
                  if needle in c.display.lower() or needle in c.source.lower()]
    if args.limit:
        usable = usable[: args.limit]

    if not usable:
        print(colour("nothing to import", YELLOW), file=sys.stderr)
        for c in skipped[:10]:
            print(colour(f"  skipped {c.source}: {c.problem}", GREY),
                  file=sys.stderr)
        return 1

    taken = {t.slug for t in db.tunnels()}
    bundle.assign_slugs(usable, args.prefix, taken)

    print(f"{len(usable)} tunnel(s) to import"
          + (f", {len(skipped)} skipped" if skipped else ""))
    for c in usable:
        print(f"  {colour(c.slug, BOLD):<14} {c.kind.value:<10} {c.display}")
    for c in skipped[:10]:
        print(colour(f"  {'--':<14} skipped: {c.source} — {c.problem}", GREY))
    if len(skipped) > 10:
        print(colour(f"  ... and {len(skipped) - 10} more skipped", GREY))

    if args.dry_run:
        print(colour("\ndry run - nothing written", YELLOW))
        return 0

    auth = Path(args.auth) if args.auth else None
    created = bundle.commit(db, usable, auth_file=auth,
                            enabled=not args.disabled)
    print(colour(f"\nimported {len(created)} tunnel(s)", GREEN))

    without = [t.slug for t in created if not t.endpoints]
    if without:
        print(colour(
            f"warning: no endpoint address resolved for: {', '.join(without)}.\n"
            f"With strict host egress the gateway cannot dial these until an "
            f"address is known.", YELLOW), file=sys.stderr)
    Daemon(settings).nudge()
    return 0


def cmd_tunnel_list(args, db: Database, settings) -> int:
    for t in db.tunnels():
        flag = "" if t.enabled else colour(" [disabled]", GREY)
        print(f"{t.slug:<12} {t.kind.value:<9} {t.iface:<14} "
              f"table {t.table:<5} {t.name}{flag}")
    return 0


def cmd_tunnel_set(args, db: Database, settings) -> int:
    t = db.tunnel(args.slug)
    if not t:
        raise SystemExit(f"unknown tunnel {args.slug!r}")
    if args.enable:
        t.enabled = True
    if args.disable:
        t.enabled = False
    if args.name:
        t.name = args.name
    if args.mtu:
        t.mtu = args.mtu
    if args.via is not None:
        via = "" if args.via in ("-", "none", "off") else args.via
        db.validate_via(t.slug, via)
        t.via = via
    if args.disable and db.riders_of(t.slug):
        names = ", ".join(r.slug for r in db.riders_of(t.slug))
        raise SystemExit(f"{t.slug} still carries {names} - unchain them "
                         f"before disabling it")
    db.update_tunnel(t)
    chain = f" via={t.via}" if t.via else ""
    print(f"{t.slug}: enabled={t.enabled} mtu={t.mtu or 'default'}{chain}")
    Daemon(settings).nudge()
    return 0


def cmd_tunnel_rm(args, db: Database, settings) -> int:
    db.delete_tunnel(args.slug)
    for suffix in (".json", ".ovpn", ".auth"):
        (config.SECRETS_DIR / f"{args.slug}{suffix}").unlink(missing_ok=True)
    print(f"removed {args.slug}")
    Daemon(settings).nudge()
    return 0


# ---------------------------------------------------------------------------
# providers
# ---------------------------------------------------------------------------


def cmd_provider_list(args, db: Database, settings) -> int:
    from . import providers
    from .providers import store

    have = set(store.configured())
    for p in providers.all_providers():
        mark = colour("configured", GREEN) if p.id in have else colour("—", GREY)
        kinds = ", ".join(k.value for k in p.supports)
        print(f"{p.id:<12} {p.name:<14} {kinds:<12} {mark}")
        if p.notes:
            print(colour(f"             {p.notes}", GREY))
    print()
    print(colour(
        "If a provider has no API, or is not listed here, import the\n"
        "configuration archive you downloaded with 'vpngwctl tunnel\n"
        "import-bundle'. The result is the same kind of tunnel.", GREY))
    return 0


def cmd_provider_login(args, db: Database, settings) -> int:
    """Store credentials for a provider.

    The operator types the credential, here or into a file. This command never
    invents, guesses, or transcribes one from anywhere else.
    """
    import getpass

    from . import providers
    from .providers import ProviderError, store

    provider = providers.get(args.provider)
    creds: dict[str, str] = {}

    if args.from_file:
        path = Path(args.from_file)
        if not path.exists():
            raise SystemExit(f"no such file: {path}")
        raw = path.read_text().strip()
        try:
            creds = json.loads(raw)
        except ValueError:
            # A single-field provider (Mullvad) can just be the bare value.
            if len(provider.auth_fields) == 1:
                creds = {provider.auth_fields[0].key: raw}
            else:
                raise SystemExit(
                    f"{path} must be JSON with keys: "
                    f"{', '.join(f.key for f in provider.auth_fields)}")
    else:
        if not sys.stdin.isatty():
            raise SystemExit(
                "no terminal to prompt on. Put the credential in a file and "
                "pass --from-file, or run this from an interactive shell.")
        print(f"{provider.name} — {provider.notes}\n")
        for f in provider.auth_fields:
            if f.help:
                print(colour(f"  {f.help}", GREY))
            prompt = f"  {f.label}: "
            value = getpass.getpass(prompt) if f.secret else input(prompt)
            creds[f.key] = value.strip()

    missing = [f.label for f in provider.auth_fields if not creds.get(f.key)]
    if missing:
        raise SystemExit(f"missing: {', '.join(missing)}")

    # The API host has to be allowed through our own firewall before the very
    # first request, or it is dropped by the output chain with no useful error.
    Daemon(settings).call(f"/api/providers/{provider.id}/enable", "POST", {})

    try:
        session = provider.login(creds)
        info = provider.account_info(session)
    except ProviderError as exc:
        raise SystemExit(colour(f"login failed: {exc}", RED))

    store.save_credentials(provider.id, creds)
    store._save_session(provider.id, session)
    print(colour(f"{provider.name}: signed in", GREEN))
    for k, v in info.items():
        if v not in (None, ""):
            print(f"  {k}: {v}")
    return 0


def cmd_provider_logout(args, db: Database, settings) -> int:
    from .providers import store

    store.forget(args.provider)
    try:
        Daemon(settings).call(f"/api/providers/{args.provider}/disable", "POST", {})
    except SystemExit:
        pass
    print(f"{args.provider}: credentials removed, API access disabled")
    return 0


def cmd_provider_locations(args, db: Database, settings) -> int:
    from . import providers
    from .providers import ProviderError, store

    provider = providers.get(args.provider)
    try:
        # Browsing the catalogue before signing up is useful, so only ask for a
        # session when the provider actually requires one.
        session = store.session_for(provider) if provider.locations_need_auth else None
        locations = provider.locations(session)
    except ProviderError as exc:
        raise SystemExit(colour(str(exc), RED))

    if args.country:
        locations = _filter_country(locations, args.country)
    if args.city:
        needle = args.city.lower()
        locations = [l for l in locations
                     if needle in l.city.lower()
                     or needle == l.extra.get("city_code", "").lower()]

    shown = locations[: args.limit] if args.limit else locations
    for l in shown:
        owned = colour(" (provider-owned hardware)", GREEN) if l.owned else ""
        print(f"{l.id:<22} {l.city + ', ' + l.country:<28} {l.address:<16}{owned}")
    print(colour(f"\n{len(shown)}/{len(locations)} servers shown", GREY))
    return 0


def _filter_country(locations, needle: str):
    """Match a country by code or name, without substring surprises.

    A plain substring search is wrong here in a way that is easy to miss: "nl"
    appears inside "Finland", so asking for the Netherlands quietly returns
    Finnish servers. On a gateway whose whole job is controlling which country
    a machine appears to be in, silently picking the wrong one is worse than
    returning nothing - so a two-letter needle is treated as a country code and
    matched exactly.
    """
    needle = needle.strip().lower()
    if len(needle) == 2:
        exact = [l for l in locations
                 if l.extra.get("country_code", "").lower() == needle]
        if exact:
            return exact
        # Not a known code - fall through and try it as a name fragment, so
        # `--country us` still works if a provider omits country codes.
    return [l for l in locations
            if needle in l.country.lower()
            or l.extra.get("country_code", "").lower() == needle]


def cmd_provider_add(args, db: Database, settings) -> int:
    from . import providers
    from .models import TunnelKind
    from .providers import ProviderError, store

    provider = providers.get(args.provider)
    try:
        session = store.session_for(provider)
        locations = provider.locations(session)
    except ProviderError as exc:
        raise SystemExit(colour(str(exc), RED))

    match = [l for l in locations if l.id == args.location]
    if not match:
        match = [l for l in locations
                 if args.location.lower() in l.id.lower()
                 or args.location.lower() in l.city.lower()]
    if not match:
        raise SystemExit(
            f"no location matching {args.location!r}. "
            f"Try 'vpngwctl provider locations {provider.id}'.")
    if len(match) > 1 and not args.first:
        print(colour(f"{len(match)} servers matched:", YELLOW), file=sys.stderr)
        for l in match[:10]:
            print(f"  {l.id:<22} {l.city}, {l.country}", file=sys.stderr)
        raise SystemExit("be more specific, or pass --first")

    location = match[0]
    slug = args.slug or _next_slug(db, args.prefix or provider.id[:2])

    try:
        remote = provider.provision(session, location, TunnelKind.WIREGUARD)
    except ProviderError as exc:
        raise SystemExit(colour(str(exc), RED))

    tunnel = _tunnel_from_remote(db, slug, args.name or location.label, remote)
    print(colour(f"added: {tunnel.slug}", GREEN)
          + f"  {tunnel.name}  ({tunnel.iface}, table {tunnel.table})")
    print(f"  endpoint: {remote.endpoint}")
    print(f"  address : {', '.join(remote.addresses)}")
    print(f"  DNS     : {', '.join(remote.dns) or 'none supplied by the provider'}")
    Daemon(settings).nudge()
    return 0


def _next_slug(db: Database, prefix: str) -> str:
    import re as _re

    prefix = _re.sub(r"[^a-z0-9]", "", prefix.lower())[:6] or "vpn"
    taken = {t.slug for t in db.tunnels()}
    n = 1
    while f"{prefix}{n:02d}" in taken:
        n += 1
    return f"{prefix}{n:02d}"


def _tunnel_from_remote(db: Database, slug: str, name: str, remote) -> Tunnel:
    """Turn a provisioned RemoteTunnel into a stored tunnel."""
    from .importers import resolve_endpoints
    from .models import TunnelKind

    config.SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    config.SECRETS_DIR.chmod(0o700)

    spec = {
        "private_key": remote.private_key,
        "listen_port": 0,
        "addresses": remote.addresses,
        "dns": remote.dns,
        "mtu": remote.mtu,
        "peers": [{
            "public_key": remote.peer_pubkey,
            "preshared_key": "",
            "endpoint": remote.endpoint,
            "allowed_ips": ["0.0.0.0/0"],
            "keepalive": 25,
        }],
    }
    stored = config.SECRETS_DIR / f"{slug}.json"
    config.write_secret(stored, json.dumps(spec, indent=2))

    host = remote.endpoint.rsplit(":", 1)[0]
    addrs, names = resolve_endpoints([host])

    return db.add_tunnel(Tunnel(
        slug=slug, name=name, kind=TunnelKind.WIREGUARD, esid=0,
        config_path=str(stored), mtu=remote.mtu, dns=remote.dns,
        endpoints=addrs, endpoint_hosts=names,
        notes=remote.notes + (f" [device {remote.remote_id}]"
                              if remote.remote_id else ""),
    ))


def cmd_provider_devices(args, db: Database, settings) -> int:
    from . import providers
    from .providers import ProviderError, store

    provider = providers.get(args.provider)
    try:
        session = store.session_for(provider)
        devices = provider.devices(session)
    except ProviderError as exc:
        raise SystemExit(colour(str(exc), RED))

    if not devices:
        print(colour("no registered devices", GREY))
        return 0
    for d in devices:
        print(f"{d['id']:<38} {d.get('name', ''):<24} {d.get('ipv4', '')}")
    if provider.device_limit:
        used = len(devices)
        tone = RED if used >= provider.device_limit else GREY
        print(colour(f"\n{used}/{provider.device_limit} device slots used", tone))
    return 0


def cmd_provider_device_rm(args, db: Database, settings) -> int:
    from . import providers
    from .providers import ProviderError, store

    provider = providers.get(args.provider)
    try:
        provider.remove_device(store.session_for(provider), args.device_id)
    except ProviderError as exc:
        raise SystemExit(colour(str(exc), RED))
    print(colour(f"device removed: {args.device_id}", GREEN))
    return 0


# ---------------------------------------------------------------------------
# pools
# ---------------------------------------------------------------------------


def cmd_pool_create(args, db: Database, settings) -> int:
    pool = Pool(
        slug=args.slug,
        name=args.name or args.slug,
        esid=db.next_pool_esid(),
        strategy=PoolStrategy(args.strategy),
        sticky_seconds=args.sticky,
        members=[PoolMember(s, (i + 1) * 10)
                 for i, s in enumerate(args.members or [])],
    )
    db.add_pool(pool)
    print(f"created pool {colour(pool.slug, BOLD)} "
          f"({pool.strategy.value}, table {pool.table})")
    for m in pool.ordered_members():
        print(f"  {m.priority:>4}  {m.tunnel_slug}")
    Daemon(settings).nudge()
    return 0


def cmd_pool_members(args, db: Database, settings) -> int:
    pool = db.pool(args.slug)
    if not pool:
        raise SystemExit(f"unknown pool {args.slug!r}")
    members = {m.tunnel_slug: m.priority for m in pool.members}
    for entry in args.add or []:
        slug, _, prio = entry.partition(":")
        members[slug] = int(prio) if prio.isdigit() else 100
    for slug in args.remove or []:
        members.pop(slug, None)
    db.set_pool_members(pool.slug, [PoolMember(s, p) for s, p in members.items()])
    for slug, prio in sorted(members.items(), key=lambda kv: kv[1]):
        print(f"  {prio:>4}  {slug}")
    Daemon(settings).nudge()
    return 0


def cmd_pool_list(args, db: Database, settings) -> int:
    for p in db.pools():
        flag = "" if p.enabled else colour(" [disabled]", GREY)
        print(f"{p.slug:<12} {p.strategy.value:<12} table {p.table:<5} "
              f"{len(p.members)} member(s){flag}")
        for m in p.ordered_members():
            print(colour(f"    {m.priority:>4}  {m.tunnel_slug}", GREY))
    return 0


def cmd_pool_rm(args, db: Database, settings) -> int:
    db.delete_pool(args.slug)
    print(f"removed pool {args.slug}")
    Daemon(settings).nudge()
    return 0


# ---------------------------------------------------------------------------
# clients
# ---------------------------------------------------------------------------


def cmd_client_add(args, db: Database, settings) -> int:
    kind, _, slug = args.egress.partition(":")
    if not slug:
        raise SystemExit("--egress takes the form tunnel:<slug> or pool:<slug>")
    client = Client(
        name=args.name, ip=args.ip, mac=args.mac or "",
        egress_kind=EgressKind(kind), egress_slug=slug, notes=args.notes or "",
    )
    client.check_in_lan(settings.net.client_networks())
    db.add_client(client)
    print(f"{client.ip} ({client.name}) -> {kind}:{slug}")
    print(colour(f"  configure this VM with address {client.ip}/"
                 f"{settings.net.lan_network.prefixlen}, gateway "
                 f"{settings.net.lan_address}, and any DNS server at all - "
                 f"it will be intercepted.", GREY))
    Daemon(settings).nudge()
    return 0


def cmd_client_assign(args, db: Database, settings) -> int:
    client = db.client(args.ip)
    if not client:
        raise SystemExit(f"no client with IP {args.ip}")
    kind, _, slug = args.egress.partition(":")
    if args.egress == "none":
        kind, slug = "tunnel", ""
    elif not slug:
        raise SystemExit("--egress takes the form tunnel:<slug> or pool:<slug>")
    client.egress_kind = EgressKind(kind)
    client.egress_slug = slug
    db.update_client(client)
    target = f"{kind}:{slug}" if slug else colour("nothing (traffic blocked)", RED)
    print(f"{client.ip} -> {target}")
    Daemon(settings).nudge()
    return 0


def cmd_client_list(args, db: Database, settings) -> int:
    for c in db.clients():
        target = (f"{c.egress_kind.value}:{c.egress_slug}"
                  if c.egress_slug else colour("unassigned", RED))
        flag = "" if c.enabled else colour(" [disabled]", GREY)
        print(f"{c.ip:<16} {c.name:<16} -> {target}{flag}")
    return 0


def cmd_client_rm(args, db: Database, settings) -> int:
    db.delete_client(args.ip)
    print(f"removed {args.ip}")
    Daemon(settings).nudge()
    return 0


# ---------------------------------------------------------------------------
# operations
# ---------------------------------------------------------------------------


def cmd_render(args, db: Database, settings) -> int:
    """Print the ruleset without applying it. Works with the daemon stopped."""
    from .render import nftables

    text = nftables.render(settings, db.tunnels(), db.pools(), db.clients())
    if args.output:
        Path(args.output).write_text(text)
        print(f"written to {args.output}")
    else:
        print(text)
    return 0


def cmd_check(args, db: Database, settings) -> int:
    from .net import nft
    from .net.shell import missing_binaries
    from .render import nftables

    problems = 0
    try:
        settings.validate()
        print(colour("PASS", GREEN), "configuration is valid")
    except ValueError as exc:
        print(colour("FAIL", RED), exc)
        problems += 1

    missing = missing_binaries()
    if missing:
        print(colour("FAIL", RED), "missing tools:", ", ".join(missing))
        problems += 1
    else:
        print(colour("PASS", GREEN), "all required tools are installed")

    text = nftables.render(settings, db.tunnels(), db.pools(), db.clients())
    ok, error = nft.check_ruleset(text)
    if ok:
        print(colour("PASS", GREEN), "generated ruleset is accepted by nft")
    else:
        print(colour("FAIL", RED), f"ruleset rejected: {error}")
        problems += 1

    for t in db.tunnels(enabled_only=True):
        if not t.endpoints:
            print(colour("WARN", YELLOW),
                  f"tunnel {t.slug} has no resolved endpoint; with strict host "
                  f"egress it cannot connect")
    return 1 if problems else 0


def cmd_selftest(args, db: Database, settings) -> int:
    daemon = Daemon(settings)
    egress = args.egress
    if not egress:
        tunnels = db.tunnels(enabled_only=True)
        if not tunnels:
            raise SystemExit("no enabled tunnel to test; pass --egress")
        egress = f"tunnel:{tunnels[0].slug}"
    kind, _, slug = egress.partition(":")

    if args.disrupt:
        print(colour(
            "This will take the tunnel down. Clients using it lose "
            "connectivity for roughly 20 seconds.", YELLOW))
        if not args.yes:
            if input("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
                return 1

    print("running, this takes about a minute...\n")
    result = daemon.call("/api/selftest", "POST", {
        "egress_kind": kind, "egress_slug": slug, "disrupt": args.disrupt,
    }, timeout=600)
    print(result["report"])
    return 0 if result["ok"] else 2


def cmd_maintenance(args, db: Database, settings) -> int:
    minutes = None if args.action == "off" else (
        args.minutes or settings.killswitch.maintenance_minutes
    )
    Daemon(settings).call("/api/maintenance", "POST", {"minutes": minutes})
    if minutes:
        print(colour(f"host egress opened for {minutes} minutes. "
                     f"Client traffic is unaffected.", YELLOW))
    else:
        print(colour("host egress closed", GREEN))
    return 0


def cmd_teardown(args, db: Database, settings) -> int:
    """Remove everything vpngw installed in the kernel.

    Separated from `systemctl stop` on purpose. Stopping the service leaves the
    firewall loaded, because a stopped control plane must not become an open
    gate. Actually opening it has to be something an operator typed.
    """
    from .net import ifaces, nft, routing

    print(colour(
        "This removes the firewall, the policy routes and every tunnel "
        "interface.\nAfter it runs, nothing stops a client VM reaching the "
        "internet directly\nthrough this gateway.", YELLOW))
    if not args.yes:
        if input("Type 'teardown' to confirm: ").strip() != "teardown":
            print("aborted")
            return 1

    for t in db.tunnels():
        from .tunnels import driver_for
        try:
            driver_for(t).down(t)
        except Exception as exc:
            print(f"  {t.slug}: {exc}", file=sys.stderr)
    for eg in [*db.tunnels(), *db.pools()]:
        routing.flush_table(eg.table)
    routing.purge_rules()
    routing.enable_forwarding(False)
    nft.delete_table()
    ifaces.remove_orphans(set())
    print(colour("torn down; forwarding is off and the vpngw table is gone", GREY))
    print("Re-arm with: systemctl restart vpngw-killswitch vpngw")
    return 0


def cmd_passwd(args, db: Database, settings) -> int:
    """Set the panel password.

    Typed here, never passed as an argument: a password on the command line
    ends up in the shell history and in every `ps` listing on the box.
    """
    import getpass

    from . import auth

    if not sys.stdin.isatty():
        raise SystemExit(
            "no terminal to prompt on. Run this from an interactive shell - "
            "passing a password as an argument would leave it in your shell "
            "history and in the process list.")

    if auth.is_configured(db) and not args.force:
        current = getpass.getpass("Current password: ")
        if not auth.check_password(db, current):
            raise SystemExit(colour("wrong password", RED))

    new = getpass.getpass("New password: ")
    again = getpass.getpass("Repeat: ")
    if new != again:
        raise SystemExit("the two entries do not match")
    try:
        auth.set_password(db, new)
    except auth.AuthError as exc:
        raise SystemExit(colour(str(exc), RED))

    print(colour("password set", GREEN))
    print(colour("  every open panel session was signed out", GREY))
    try:
        Daemon(settings).call("/api/reconcile", "POST", {})
    except SystemExit:
        pass
    return 0


def cmd_reconcile(args, db: Database, settings) -> int:
    Daemon(settings).call("/api/reconcile", "POST", {})
    print("reconcile requested")
    return 0


def cmd_events(args, db: Database, settings) -> int:
    for e in reversed(db.events(args.limit)):
        stamp = time.strftime("%H:%M:%S", time.localtime(e["ts"]))
        code = {"error": RED, "warning": YELLOW}.get(e["level"], GREY)
        print(f"{colour(stamp, GREY)} {colour(e['level'][:4].upper(), code):<4} "
              f"{e['source']:<14} {e['message']}")
    return 0


def cmd_init(args, db: Database, settings) -> int:
    config.ETC.mkdir(parents=True, exist_ok=True)
    if config.CONFIG_FILE.exists() and not args.force:
        raise SystemExit(f"{config.CONFIG_FILE} exists; pass --force to replace")
    config.CONFIG_FILE.write_text(config.DEFAULT_TOML)
    print(f"wrote {config.CONFIG_FILE}")
    return 0


# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vpngwctl",
        description="Control the vpngw fail-closed multi-VPN gateway.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="show tunnels, pools and clients").set_defaults(
        func=cmd_status)
    sub.add_parser("reconcile", help="ask the daemon to apply state now"
                   ).set_defaults(func=cmd_reconcile)

    ev = sub.add_parser("events", help="recent daemon events")
    ev.add_argument("-n", "--limit", type=int, default=40)
    ev.set_defaults(func=cmd_events)

    ini = sub.add_parser("init", help="write a default /etc/vpngw/vpngw.toml")
    ini.add_argument("--force", action="store_true")
    ini.set_defaults(func=cmd_init)

    # -- tunnel ------------------------------------------------------------
    t = sub.add_parser("tunnel", help="manage VPN tunnels").add_subparsers(
        dest="sub", required=True)

    ti = t.add_parser("import", help="import a .conf or .ovpn file")
    ti.add_argument("slug", help="short name, used for the interface name")
    ti.add_argument("file")
    ti.add_argument("--name", help="human readable label")
    ti.add_argument("--kind", choices=["wireguard", "openvpn"])
    ti.add_argument("--auth", help="file with username on line 1, password on 2")
    ti.add_argument("--mtu", type=int, default=0)
    ti.add_argument("--disabled", action="store_true")
    ti.set_defaults(func=cmd_tunnel_import)

    tb = t.add_parser("import-bundle",
                      help="import a whole folder or zip of configs at once")
    tb.add_argument("path", help="folder, .zip, or a single config file")
    tb.add_argument("--prefix", default="vpn",
                    help="slug prefix; tunnels become <prefix>01, <prefix>02, ...")
    tb.add_argument("--filter", help="only files matching this text")
    tb.add_argument("--limit", type=int, help="import at most this many")
    tb.add_argument("--auth", help="OpenVPN auth file, applied to all of them")
    tb.add_argument("--disabled", action="store_true",
                    help="import but leave every tunnel switched off")
    tb.add_argument("--dry-run", action="store_true",
                    help="show what would be imported and write nothing")
    tb.set_defaults(func=cmd_tunnel_import_bundle)

    t.add_parser("list").set_defaults(func=cmd_tunnel_list)

    ts = t.add_parser("set")
    ts.add_argument("slug")
    ts.add_argument("--enable", action="store_true")
    ts.add_argument("--disable", action="store_true")
    ts.add_argument("--name")
    ts.add_argument("--mtu", type=int)
    ts.add_argument("--via", metavar="TUNNEL|-",
                    help="route this tunnel's encrypted traffic through "
                         "another tunnel (double VPN). '-' unchains it.")
    ts.set_defaults(func=cmd_tunnel_set)

    tr = t.add_parser("rm")
    tr.add_argument("slug")
    tr.set_defaults(func=cmd_tunnel_rm)

    # -- provider ----------------------------------------------------------
    pv = sub.add_parser(
        "provider", help="commercial VPN provider accounts and servers"
    ).add_subparsers(dest="sub", required=True)

    pv.add_parser("list", help="which providers are supported and configured"
                  ).set_defaults(func=cmd_provider_list)

    pvl = pv.add_parser("login", help="store credentials for a provider")
    pvl.add_argument("provider")
    pvl.add_argument("--from-file",
                     help="read the credential from this file instead of "
                          "prompting (JSON, or the bare value for providers "
                          "with a single field)")
    pvl.set_defaults(func=cmd_provider_login)

    pvo = pv.add_parser("logout", help="forget a provider's credentials")
    pvo.add_argument("provider")
    pvo.set_defaults(func=cmd_provider_logout)

    pvc = pv.add_parser("locations", help="list a provider's servers")
    pvc.add_argument("provider")
    pvc.add_argument("--country", help="filter by country name or code")
    pvc.add_argument("--city")
    pvc.add_argument("--limit", type=int, default=40)
    pvc.set_defaults(func=cmd_provider_locations)

    pva = pv.add_parser("add", help="provision a tunnel on one of its servers")
    pva.add_argument("provider")
    pva.add_argument("location", help="server id, or part of a city name")
    pva.add_argument("--slug", help="interface slug; generated if omitted")
    pva.add_argument("--prefix", help="prefix for the generated slug")
    pva.add_argument("--name", help="display name")
    pva.add_argument("--first", action="store_true",
                     help="take the first match instead of asking")
    pva.set_defaults(func=cmd_provider_add)

    pvd = pv.add_parser("devices", help="keys registered on the account")
    pvd.add_argument("provider")
    pvd.set_defaults(func=cmd_provider_devices)

    pvr = pv.add_parser("device-rm", help="remove a registered key")
    pvr.add_argument("provider")
    pvr.add_argument("device_id")
    pvr.set_defaults(func=cmd_provider_device_rm)

    # -- pool --------------------------------------------------------------
    pl = sub.add_parser("pool", help="manage failover pools").add_subparsers(
        dest="sub", required=True)

    pc = pl.add_parser("create")
    pc.add_argument("slug")
    pc.add_argument("--name")
    pc.add_argument("--strategy", default="priority",
                    choices=[s.value for s in PoolStrategy])
    pc.add_argument("--sticky", type=int, default=60,
                    help="seconds to hold a member before switching back")
    pc.add_argument("--members", nargs="*", help="tunnel slugs, best first")
    pc.set_defaults(func=cmd_pool_create)

    pm = pl.add_parser("members")
    pm.add_argument("slug")
    pm.add_argument("--add", nargs="*", metavar="SLUG[:PRIORITY]")
    pm.add_argument("--remove", nargs="*", metavar="SLUG")
    pm.set_defaults(func=cmd_pool_members)

    pl.add_parser("list").set_defaults(func=cmd_pool_list)
    pr = pl.add_parser("rm")
    pr.add_argument("slug")
    pr.set_defaults(func=cmd_pool_rm)

    # -- client ------------------------------------------------------------
    cl = sub.add_parser("client", help="manage LAN clients").add_subparsers(
        dest="sub", required=True)

    ca = cl.add_parser("add")
    ca.add_argument("name")
    ca.add_argument("ip")
    ca.add_argument("--egress", required=True, metavar="tunnel:SLUG|pool:SLUG")
    ca.add_argument("--mac")
    ca.add_argument("--notes")
    ca.set_defaults(func=cmd_client_add)

    cas = cl.add_parser("assign", help="point a client at a different egress")
    cas.add_argument("ip")
    cas.add_argument("egress", metavar="tunnel:SLUG|pool:SLUG|none")
    cas.set_defaults(func=cmd_client_assign)

    cl.add_parser("list").set_defaults(func=cmd_client_list)
    cr = cl.add_parser("rm")
    cr.add_argument("ip")
    cr.set_defaults(func=cmd_client_rm)

    # -- operations --------------------------------------------------------
    rn = sub.add_parser("render", help="print the nftables ruleset, unapplied")
    rn.add_argument("-o", "--output")
    rn.set_defaults(func=cmd_render)

    sub.add_parser("check", help="validate config, tools and ruleset"
                   ).set_defaults(func=cmd_check)

    st = sub.add_parser("selftest", help="prove the kill switch works")
    st.add_argument("--egress", metavar="tunnel:SLUG|pool:SLUG")
    st.add_argument("--disrupt", action="store_true",
                    help="take the tunnel down and measure what escapes")
    st.add_argument("-y", "--yes", action="store_true")
    st.set_defaults(func=cmd_selftest)

    mt = sub.add_parser("maintenance",
                        help="temporarily open the GATEWAY's own egress")
    mt.add_argument("action", choices=["on", "off"])
    mt.add_argument("--minutes", type=int)
    mt.set_defaults(func=cmd_maintenance)

    pw = sub.add_parser("passwd", help="set the web panel password")
    pw.add_argument("--force", action="store_true",
                    help="skip the current-password prompt (recovery)")
    pw.set_defaults(func=cmd_passwd)

    td = sub.add_parser("teardown",
                        help="remove the firewall and routes (dangerous)")
    td.add_argument("-y", "--yes", action="store_true")
    td.set_defaults(func=cmd_teardown)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = config.Settings.load()
    except ValueError as exc:
        print(colour(f"configuration error: {exc}", RED), file=sys.stderr)
        return 1
    db = Database()
    try:
        return args.func(args, db, settings)
    except ValidationError as exc:
        print(colour(f"error: {exc}", RED), file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
