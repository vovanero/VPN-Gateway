"""Bulk import of a provider's config archive.

Every VPN provider, API or not, will hand you a zip or a folder of .ovpn and
.conf files. Importing forty of them one at a time is the single most tedious
thing about running this gateway, and it is also where mistakes creep in - a
mistyped slug, a file that silently failed to parse, a tunnel that was never
actually enabled.

So this does the whole archive at once, validates every file before writing
anything, and reports what it skipped and why. Nothing is imported if the
archive is unusable; a half-imported bundle is worse than none.

This is deliberately the fallback that works everywhere. A provider with a
usable API gets a plugin under providers/; a provider without one gets this,
and the result is the same kind of tunnel.
"""

from __future__ import annotations

import json
import logging
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import config
from .importers import (
    ImportError_,
    ovpn_endpoint_hosts,
    parse_openvpn,
    parse_wireguard,
    resolve_endpoints,
    wg_endpoint_hosts,
)
from .models import Tunnel, TunnelKind

log = logging.getLogger("vpngw.bundle")

CONFIG_SUFFIXES = {".conf", ".ovpn"}
# Providers name files things like "mullvad-nl-ams-wg-001.conf" or
# "de-berlin.prod.surfshark.com.udp.ovpn". Neither fits in a ten-character
# interface slug, so the readable part becomes the display name and the slug is
# generated - predictable beats clever when you are looking at `ip link`.
NOISE = re.compile(
    r"\.(prod|udp|tcp)\b|_(udp|tcp)\b|\b(openvpn|wireguard|wg|ovpn)\b",
    re.IGNORECASE,
)


@dataclass
class Candidate:
    """One config file found in the archive, already parsed and checked."""

    source: str                  # path inside the archive
    display: str                 # human-readable name
    kind: TunnelKind
    text: str
    endpoint_hosts: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    mtu: int = 0
    spec: object = None          # parsed WgSpec, for wireguard
    slug: str = ""               # assigned during planning
    problem: str = ""            # non-empty means "skipped"

    @property
    def usable(self) -> bool:
        return not self.problem


def _read_archive(path: Path) -> list[tuple[str, str]]:
    """Return [(name, text)] for every config file in a folder or zip."""
    out: list[tuple[str, str]] = []

    if path.is_dir():
        for f in sorted(path.rglob("*")):
            if f.is_file() and f.suffix.lower() in CONFIG_SUFFIXES:
                out.append((str(f.relative_to(path)),
                            f.read_text(errors="replace")))
        return out

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for info in sorted(zf.infolist(), key=lambda i: i.filename):
                if info.is_dir():
                    continue
                if Path(info.filename).suffix.lower() not in CONFIG_SUFFIXES:
                    continue
                # A zip from the internet can name entries anything, including
                # ../../etc/shadow. We only ever read them into memory, but the
                # name is also used to build a display string, so flatten it.
                if info.file_size > 2_000_000:
                    continue
                with zf.open(info) as fh:
                    out.append((info.filename,
                                fh.read().decode("utf-8", "replace")))
        return out

    if path.is_file() and path.suffix.lower() in CONFIG_SUFFIXES:
        return [(path.name, path.read_text(errors="replace"))]

    raise ImportError_(
        f"{path} is not a folder, a zip, or a .conf/.ovpn file"
    )


def _display_name(source: str) -> str:
    stem = Path(source).name
    for suffix in CONFIG_SUFFIXES:
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    stem = NOISE.sub(" ", stem)
    stem = re.sub(r"[._\-]+", " ", stem).strip()
    return re.sub(r"\s+", " ", stem) or Path(source).stem


def scan(path: Path) -> list[Candidate]:
    """Parse everything in the archive. Nothing is written."""
    found = _read_archive(path)
    if not found:
        raise ImportError_(f"no .conf or .ovpn files found in {path}")

    candidates: list[Candidate] = []
    for source, text in found:
        display = _display_name(source)
        looks_wg = "[Interface]" in text and "PrivateKey" in text
        kind = TunnelKind.WIREGUARD if looks_wg else TunnelKind.OPENVPN
        c = Candidate(source=source, display=display, kind=kind, text=text)

        try:
            if kind is TunnelKind.WIREGUARD:
                spec = parse_wireguard(text)
                c.spec = spec
                c.endpoint_hosts = wg_endpoint_hosts(spec)
                c.dns = spec.dns
                c.mtu = spec.mtu
            else:
                spec = parse_openvpn(text)
                c.endpoint_hosts = ovpn_endpoint_hosts(spec)
                if spec.needs_auth:
                    c.problem = "needs a username and password (pass --auth)"
        except ImportError_ as exc:
            c.problem = str(exc)

        candidates.append(c)

    log.info("bundle: %d file(s), %d usable",
             len(candidates), sum(1 for c in candidates if c.usable))
    return candidates


def assign_slugs(candidates: list[Candidate], prefix: str,
                 taken: set[str]) -> None:
    """Give every usable candidate a short, unique, predictable slug.

    Generated rather than derived from the filename: provider filenames are
    routinely longer than the ten characters an interface name allows, and two
    of them often differ only past that limit. `nl01`, `nl02` is boring and
    always works.
    """
    prefix = re.sub(r"[^a-z0-9]", "", prefix.lower())[:6] or "vpn"
    width = 2 if len(candidates) < 100 else 3
    n = 1
    for c in candidates:
        if not c.usable:
            continue
        while True:
            slug = f"{prefix}{n:0{width}d}"
            n += 1
            if slug not in taken:
                break
        c.slug = slug
        taken.add(slug)


def commit(db, candidates: list[Candidate], *, auth_file: Path | None = None,
           enabled: bool = True) -> list[Tunnel]:
    """Write the usable candidates to disk and the database.

    Endpoint resolution happens here, once per candidate, because a tunnel with
    no resolved endpoint cannot connect under strict host egress - better to
    record that at import time than to have it fail silently later.
    """
    config.SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    config.SECRETS_DIR.chmod(0o700)

    created: list[Tunnel] = []
    for c in candidates:
        if not c.usable or not c.slug:
            continue

        if c.kind is TunnelKind.WIREGUARD:
            stored = config.SECRETS_DIR / f"{c.slug}.json"
            config.write_secret(stored, json.dumps(c.spec.to_dict(), indent=2))
        else:
            stored = config.SECRETS_DIR / f"{c.slug}.ovpn"
            config.write_secret(stored, c.text)
            if auth_file and auth_file.exists():
                config.write_secret(config.SECRETS_DIR / f"{c.slug}.auth",
                                    auth_file.read_text())

        addrs, names = resolve_endpoints(c.endpoint_hosts)
        tunnel = db.add_tunnel(Tunnel(
            slug=c.slug,
            name=c.display,
            kind=c.kind,
            esid=0,                      # allocated by the database
            enabled=enabled,
            config_path=str(stored),
            mtu=c.mtu,
            dns=c.dns,
            endpoints=addrs,
            endpoint_hosts=names,
            notes=f"imported from {c.source}",
        ))
        created.append(tunnel)

    return created
