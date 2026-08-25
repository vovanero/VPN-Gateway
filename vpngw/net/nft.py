"""nftables application and inspection.

Two levels of change:

* **Structural** - a tunnel was added or removed, settings changed. The whole
  ruleset is re-rendered and swapped in one atomic ``nft -f`` transaction.
* **Element** - a client was reassigned, an endpoint's address changed. Only
  set/map elements move, which keeps the drop counters (and therefore the leak
  evidence) intact across routine edits.

Both are atomic. There is no moment in which the table is absent or a chain has
a permissive policy.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from .. import config
from .shell import CommandError, run, try_run

log = logging.getLogger("vpngw.nft")

TABLE = "vpngw"
FAMILY = "inet"


def apply_ruleset(ruleset: str, *, save_to: Path | None = None) -> None:
    """Replace the vpngw table with ``ruleset`` in a single transaction.

    The rendered text is expected to open with the create/delete/define idiom
    so that the swap cannot leave a gap.
    """
    path = save_to or config.RUNTIME_NFT
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(ruleset)
    try:
        run(["nft", "-f", str(path)])
    except CommandError as exc:
        log.error("ruleset rejected, kernel state unchanged: %s", exc)
        raise
    log.info("applied nftables ruleset (%d bytes)", len(ruleset))


def check_ruleset(ruleset: str) -> tuple[bool, str]:
    """Dry-run a candidate ruleset without touching the kernel."""
    res = try_run(["nft", "--check", "-f", "/dev/stdin"], input_text=ruleset)
    return res.ok, (res.stderr or res.stdout).strip()


def table_exists() -> bool:
    return try_run(["nft", "list", "table", FAMILY, TABLE]).ok


# ---------------------------------------------------------------------------
# sets and maps
# ---------------------------------------------------------------------------


def _list_elements(kind: str, name: str) -> list:
    res = try_run(["nft", "-j", "list", kind, FAMILY, TABLE, name])
    if not res.ok:
        return []
    try:
        doc = json.loads(res.stdout)
    except ValueError:
        return []
    for item in doc.get("nftables", []):
        body = item.get("set") or item.get("map")
        if body and body.get("name") == name:
            return body.get("elem", []) or []
    return []


def set_members(name: str) -> set[str]:
    out: set[str] = set()
    for elem in _list_elements("set", name):
        if isinstance(elem, str):
            out.add(elem)
        elif isinstance(elem, dict) and "prefix" in elem:
            p = elem["prefix"]
            out.add(f"{p['addr']}/{p['len']}")
    return out


def _bare(value: str) -> str:
    """Strip the quoting nftables accepts on input but omits on output.

    Interface names are written as `"wg-nl01"` and read back as `wg-nl01`.
    Comparing the two forms directly means nothing ever matches, so every pass
    deletes and re-adds the same element - and between those two commands the
    interface is absent from the allow-list, which drops client traffic. A
    quoting mismatch turning into a periodic outage is exactly the kind of bug
    that hides in a log line reading "+1 -1".
    """
    return value.strip().strip('"')


def sync_set(name: str, want: set[str]) -> None:
    have = set_members(name)
    have_bare = {_bare(v): v for v in have}
    want_bare = {_bare(v): v for v in want}

    stale = sorted(set(have_bare) - set(want_bare))
    for gone in stale:
        try_run(["nft", "delete", "element", FAMILY, TABLE, name,
                 "{", have_bare[gone], "}"])
    add = [want_bare[k] for k in sorted(set(want_bare) - set(have_bare))]
    if add:
        run(["nft", "add", "element", FAMILY, TABLE, name,
             "{" + ", ".join(add) + "}"])
    if add or stale:
        log.info("set %s: +%d -%d (now %d)", name, len(add), len(stale),
                 len(want))


def map_entries(name: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for elem in _list_elements("map", name):
        if isinstance(elem, dict) and "elem" in elem:
            elem = elem["elem"]
        if isinstance(elem, list) and len(elem) == 2:
            key, val = elem
            key = key if isinstance(key, str) else json.dumps(key)
            if isinstance(val, dict) and "mark" in val:
                val = str(val["mark"])
            out[str(key)] = str(val)
    return out


def _canon_value(value: str) -> str:
    """Map values as comparable text.

    We write marks as `0x0001`; the kernel prints them back as `1`. Comparing
    those spellings directly means every pass sees a difference and rewrites
    the map - the same disease :func:`_bare` cures for set members, moved to
    values. The rewrite is not just log noise: a delete window on cli2mark is
    a moment in which a client's packets carry no mark and are dropped.
    """
    value = _bare(value)
    try:
        return str(int(value, 0))
    except ValueError:
        return value


def sync_map(name: str, want: dict[str, str]) -> None:
    """Reconcile a map's contents.

    Reassignments are done as delete-then-add rather than a replace so that a
    client is never briefly mapped to the wrong egress.
    """
    have = map_entries(name)
    stale = {k for k in have
             if k not in want or _canon_value(have[k]) != _canon_value(want[k])}
    for key in sorted(stale):
        try_run(["nft", "delete", "element", FAMILY, TABLE, name,
                 "{", key, ":", have[key], "}"])
    add = {k: v for k, v in want.items() if k not in have or k in stale}
    if add:
        body = ", ".join(f"{k} : {v}" for k, v in sorted(add.items()))
        run(["nft", "add", "element", FAMILY, TABLE, name, "{" + body + "}"])
    if add or stale:
        log.info("map %s: %d entries (%d changed)", name, len(want), len(add))


# ---------------------------------------------------------------------------
# counters - the evidence the kill switch works
# ---------------------------------------------------------------------------

COUNTERS = [
    "wan_leak_drop",       # forwarded traffic that tried to exit the uplink
    "nontunnel_drop",      # forwarded traffic aimed at any non-tunnel egress
    "unclassified_drop",   # client with no egress assigned
    "invalid_drop",
    "forwarded_new",       # new client flows allowed into a tunnel
    "returned",            # tunnel -> client replies
    "input_drop",
    "host_egress_drop",    # the gateway's own blocked traffic
    "dns_hijacked",
]


def counters() -> dict[str, dict[str, int]]:
    res = try_run(["nft", "-j", "list", "counters", "table", FAMILY, TABLE])
    out: dict[str, dict[str, int]] = {}
    if not res.ok:
        return out
    try:
        doc = json.loads(res.stdout)
    except ValueError:
        return out
    for item in doc.get("nftables", []):
        c = item.get("counter")
        if c and "name" in c:
            out[c["name"]] = {
                "packets": int(c.get("packets", 0)),
                "bytes": int(c.get("bytes", 0)),
            }
    return out


def reset_counters() -> None:
    for name in COUNTERS:
        try_run(["nft", "reset", "counter", FAMILY, TABLE, name])


def delete_table() -> None:
    """Tear the table down. Only ever called by an explicit operator command -
    never on daemon shutdown, because a stopped daemon must not open the gate."""
    try_run(["nft", "delete", "table", FAMILY, TABLE])
