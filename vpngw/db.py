"""SQLite persistence and esid allocation.

The database is the single source of desired state. The reconciler reads it and
makes the kernel match; nothing else writes to the kernel.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from . import config
from .models import (
    Client,
    EgressKind,
    Pool,
    PoolMember,
    PoolStrategy,
    Tunnel,
    TunnelKind,
    ValidationError,
    normalise_slug,
)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS tunnel (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    slug           TEXT    NOT NULL UNIQUE,
    name           TEXT    NOT NULL,
    kind           TEXT    NOT NULL,
    esid           INTEGER NOT NULL UNIQUE,
    enabled        INTEGER NOT NULL DEFAULT 1,
    config_path    TEXT    NOT NULL DEFAULT '',
    mtu            INTEGER NOT NULL DEFAULT 0,
    dns            TEXT    NOT NULL DEFAULT '[]',
    endpoints      TEXT    NOT NULL DEFAULT '[]',
    endpoint_hosts TEXT    NOT NULL DEFAULT '[]',
    via            TEXT    NOT NULL DEFAULT '',
    notes          TEXT    NOT NULL DEFAULT '',
    created_at     REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS pool (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    slug           TEXT    NOT NULL UNIQUE,
    name           TEXT    NOT NULL,
    esid           INTEGER NOT NULL UNIQUE,
    strategy       TEXT    NOT NULL DEFAULT 'priority',
    sticky_seconds INTEGER NOT NULL DEFAULT 60,
    rotate_seconds INTEGER NOT NULL DEFAULT 300,
    enabled        INTEGER NOT NULL DEFAULT 1,
    notes          TEXT    NOT NULL DEFAULT '',
    created_at     REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS pool_member (
    pool_id   INTEGER NOT NULL REFERENCES pool(id)   ON DELETE CASCADE,
    tunnel_id INTEGER NOT NULL REFERENCES tunnel(id) ON DELETE CASCADE,
    priority  INTEGER NOT NULL DEFAULT 100,
    PRIMARY KEY (pool_id, tunnel_id)
);

CREATE TABLE IF NOT EXISTS client (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    ip          TEXT    NOT NULL UNIQUE,
    mac         TEXT    NOT NULL DEFAULT '',
    egress_kind TEXT    NOT NULL DEFAULT 'tunnel',
    egress_slug TEXT    NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    notes       TEXT    NOT NULL DEFAULT '',
    created_at  REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Panel sessions live here rather than in the daemon's memory, so that
-- restarting the service - an upgrade, a settings change, a crash - does not
-- log the operator out. Only a hash of each token is stored: someone who can
-- read this file already owns the box, but they should not also be handed
-- live credentials to whatever else the operator reuses.
CREATE TABLE IF NOT EXISTS session (
    token_hash TEXT PRIMARY KEY,
    expires    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS event (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    level   TEXT NOT NULL,
    source  TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS event_ts ON event(ts DESC);
"""


class Database:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or config.DB_FILE
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.path, check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        # Whether log_event records anything. Driven by [log] level: a
        # privacy gateway's default is to keep no history at all, so the
        # service flips this on only when the operator chose logging.
        self.events_enabled = True
        with self._lock:
            self._conn.executescript(SCHEMA)
            # v2 migration. ALTER is the whole upgrade path for existing
            # gateways, so it must be safe to run on every start.
            cols = {r["name"] for r in
                    self._conn.execute("PRAGMA table_info(tunnel)")}
            if "via" not in cols:
                self._conn.execute(
                    "ALTER TABLE tunnel ADD COLUMN via TEXT NOT NULL DEFAULT ''")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- helpers ------------------------------------------------------------

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, args))

    def _x(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, args)

    # -- esid allocation ----------------------------------------------------

    def _alloc_esid(self, table: str, lo: int, hi: int) -> int:
        used = {r["esid"] for r in self._q(f"SELECT esid FROM {table}")}
        for esid in range(lo, hi + 1):
            if esid not in used:
                return esid
        raise ValidationError(f"no free esid left in {table} ({lo}-{hi})")

    # -- tunnels ------------------------------------------------------------

    def _row_to_tunnel(self, r: sqlite3.Row) -> Tunnel:
        return Tunnel(
            id=r["id"],
            slug=r["slug"],
            name=r["name"],
            kind=TunnelKind(r["kind"]),
            esid=r["esid"],
            enabled=bool(r["enabled"]),
            config_path=r["config_path"],
            mtu=r["mtu"],
            dns=json.loads(r["dns"]),
            endpoints=json.loads(r["endpoints"]),
            endpoint_hosts=json.loads(r["endpoint_hosts"]),
            via=r["via"],
            notes=r["notes"],
        )

    def tunnels(self, enabled_only: bool = False) -> list[Tunnel]:
        sql = "SELECT * FROM tunnel"
        if enabled_only:
            sql += " WHERE enabled = 1"
        return [self._row_to_tunnel(r) for r in self._q(sql + " ORDER BY esid")]

    def tunnel(self, slug: str) -> Tunnel | None:
        # Slugs are stored folded, so lookups have to fold too - otherwise a
        # tunnel imported as "NL01" could never be found again by that name.
        rows = self._q("SELECT * FROM tunnel WHERE slug = ?",
                       (normalise_slug(slug),))
        return self._row_to_tunnel(rows[0]) if rows else None

    def add_tunnel(self, t: Tunnel) -> Tunnel:
        if self.tunnel(t.slug):
            raise ValidationError(f"tunnel {t.slug!r} already exists")
        t.esid = t.esid or self._alloc_esid(
            "tunnel", config.TUNNEL_ESID_MIN, config.TUNNEL_ESID_MAX
        )
        cur = self._x(
            "INSERT INTO tunnel (slug, name, kind, esid, enabled, config_path,"
            " mtu, dns, endpoints, endpoint_hosts, via, notes, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                t.slug, t.name, t.kind.value, t.esid, int(t.enabled),
                t.config_path, t.mtu, json.dumps(t.dns),
                json.dumps(t.endpoints), json.dumps(t.endpoint_hosts),
                t.via, t.notes, time.time(),
            ),
        )
        t.id = cur.lastrowid
        return t

    def update_tunnel(self, t: Tunnel) -> None:
        self._x(
            "UPDATE tunnel SET name=?, enabled=?, config_path=?, mtu=?, dns=?,"
            " endpoints=?, endpoint_hosts=?, via=?, notes=? WHERE slug=?",
            (
                t.name, int(t.enabled), t.config_path, t.mtu, json.dumps(t.dns),
                json.dumps(t.endpoints), json.dumps(t.endpoint_hosts),
                t.via, t.notes, t.slug,
            ),
        )

    def delete_tunnel(self, slug: str) -> None:
        slug = normalise_slug(slug)
        clients = self._q(
            "SELECT name FROM client WHERE egress_kind='tunnel' AND egress_slug=?",
            (slug,),
        )
        if clients:
            names = ", ".join(r["name"] for r in clients)
            raise ValidationError(
                f"tunnel {slug!r} is still the egress for: {names}"
            )
        riders = self.riders_of(slug)
        if riders:
            names = ", ".join(t.slug for t in riders)
            raise ValidationError(
                f"tunnel {slug!r} still carries other tunnels: {names}. "
                f"Unchain them first."
            )
        self._x("DELETE FROM tunnel WHERE slug = ?", (slug,))

    # -- chains (v2) --------------------------------------------------------

    def chain_of(self, tunnel: Tunnel) -> list[Tunnel]:
        """The tunnel and every ancestor it rides through, exit first.

        [exit] for a normal tunnel; [exit, middle, entry] for a chain of
        three. Walks defensively: a broken link (parent deleted out from
        under us) ends the walk rather than raising, because this runs in
        status paths that must never take the panel down.
        """
        out, seen = [tunnel], {tunnel.slug}
        current = tunnel
        while current.via and current.via not in seen:
            parent = self.tunnel(current.via)
            if parent is None:
                break
            out.append(parent)
            seen.add(parent.slug)
            current = parent
        return out

    def riders_of(self, slug: str) -> list[Tunnel]:
        """Tunnels whose encrypted packets leave through this one."""
        slug = normalise_slug(slug)
        return [t for t in self.tunnels() if t.via == slug]

    def validate_via(self, slug: str, via: str) -> None:
        """Refuse a via assignment that cannot work.

        Checked here, against the whole table, because none of these are
        visible from one tunnel alone: a cycle needs the walk, the hop
        ceiling needs the descendants too (inserting a parent under a
        tunnel that already carries riders lengthens *their* chains), and
        the endpoint clash needs every other tunnel's endpoints.
        """
        slug = normalise_slug(slug)
        if not via:
            return
        via = normalise_slug(via)
        if via == slug:
            raise ValidationError(f"{slug!r} cannot route through itself")
        tunnel = self.tunnel(slug)
        parent = self.tunnel(via)
        if tunnel is None:
            raise ValidationError(f"no tunnel named {slug!r}")
        if parent is None:
            raise ValidationError(f"no tunnel named {via!r} to route through")

        ancestry = self.chain_of(parent)
        if any(t.slug == slug for t in ancestry):
            names = " -> ".join(t.slug for t in ancestry)
            raise ValidationError(
                f"that would loop: {via} already routes through {names}")

        # Longest path through this tunnel once linked: everything hanging
        # below it, plus the parent's ancestry above it.
        def depth_below(s: str) -> int:
            kids = self.riders_of(s)
            if not kids:
                return 1
            return 1 + max(depth_below(k.slug) for k in kids)

        total = depth_below(slug) + len(ancestry)
        if total > config.MAX_CHAIN_HOPS:
            raise ValidationError(
                f"a chain of {total} hops - the ceiling is "
                f"{config.MAX_CHAIN_HOPS}. Each hop costs MTU, latency and "
                f"about half the remaining throughput.")

        # A chained tunnel's endpoint must stay OFF the WAN allow-list; an
        # address shared with a WAN-reaching tunnel would have to stay on it.
        chained_eps = set(tunnel.endpoints)
        for other in self.tunnels():
            if other.slug == slug or other.via:
                continue
            clash = chained_eps & set(other.endpoints)
            if clash:
                raise ValidationError(
                    f"{slug} shares endpoint {sorted(clash)[0]} with "
                    f"{other.slug}, which reaches it over the WAN. The "
                    f"shared address would stay on the uplink allow-list "
                    f"and quietly weaken the chain confinement. Use a "
                    f"different server for one of them.")

    def next_tunnel_esid(self) -> int:
        return self._alloc_esid(
            "tunnel", config.TUNNEL_ESID_MIN, config.TUNNEL_ESID_MAX
        )

    # -- pools --------------------------------------------------------------

    def _row_to_pool(self, r: sqlite3.Row) -> Pool:
        members = [
            PoolMember(tunnel_slug=m["slug"], priority=m["priority"])
            for m in self._q(
                "SELECT t.slug AS slug, pm.priority AS priority"
                " FROM pool_member pm JOIN tunnel t ON t.id = pm.tunnel_id"
                " WHERE pm.pool_id = ? ORDER BY pm.priority, t.slug",
                (r["id"],),
            )
        ]
        return Pool(
            id=r["id"],
            slug=r["slug"],
            name=r["name"],
            esid=r["esid"],
            strategy=PoolStrategy(r["strategy"]),
            members=members,
            sticky_seconds=r["sticky_seconds"],
            rotate_seconds=r["rotate_seconds"],
            enabled=bool(r["enabled"]),
            notes=r["notes"],
        )

    def pools(self, enabled_only: bool = False) -> list[Pool]:
        sql = "SELECT * FROM pool"
        if enabled_only:
            sql += " WHERE enabled = 1"
        return [self._row_to_pool(r) for r in self._q(sql + " ORDER BY esid")]

    def pool(self, slug: str) -> Pool | None:
        rows = self._q("SELECT * FROM pool WHERE slug = ?",
                       (normalise_slug(slug),))
        return self._row_to_pool(rows[0]) if rows else None

    def add_pool(self, p: Pool) -> Pool:
        if self.pool(p.slug):
            raise ValidationError(f"pool {p.slug!r} already exists")
        p.esid = p.esid or self._alloc_esid(
            "pool", config.POOL_ESID_MIN, config.POOL_ESID_MAX
        )
        cur = self._x(
            "INSERT INTO pool (slug, name, esid, strategy, sticky_seconds,"
            " rotate_seconds, enabled, notes, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                p.slug, p.name, p.esid, p.strategy.value, p.sticky_seconds,
                p.rotate_seconds, int(p.enabled), p.notes, time.time(),
            ),
        )
        p.id = cur.lastrowid
        self.set_pool_members(p.slug, p.members)
        return p

    def update_pool(self, p: Pool) -> None:
        self._x(
            "UPDATE pool SET name=?, strategy=?, sticky_seconds=?,"
            " rotate_seconds=?, enabled=?, notes=? WHERE slug=?",
            (
                p.name, p.strategy.value, p.sticky_seconds, p.rotate_seconds,
                int(p.enabled), p.notes, p.slug,
            ),
        )
        self.set_pool_members(p.slug, p.members)

    def set_pool_members(self, pool_slug: str, members: list[PoolMember]) -> None:
        pool_slug = normalise_slug(pool_slug)
        rows = self._q("SELECT id FROM pool WHERE slug = ?", (pool_slug,))
        if not rows:
            raise ValidationError(f"unknown pool {pool_slug!r}")
        pool_id = rows[0]["id"]
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                self._conn.execute(
                    "DELETE FROM pool_member WHERE pool_id = ?", (pool_id,)
                )
                for m in members:
                    tr = list(
                        self._conn.execute(
                            "SELECT id FROM tunnel WHERE slug = ?",
                            (m.tunnel_slug,),
                        )
                    )
                    if not tr:
                        raise ValidationError(f"unknown tunnel {m.tunnel_slug!r}")
                    self._conn.execute(
                        "INSERT INTO pool_member (pool_id, tunnel_id, priority)"
                        " VALUES (?,?,?)",
                        (pool_id, tr[0]["id"], m.priority),
                    )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def delete_pool(self, slug: str) -> None:
        slug = normalise_slug(slug)
        clients = self._q(
            "SELECT name FROM client WHERE egress_kind='pool' AND egress_slug=?",
            (slug,),
        )
        if clients:
            names = ", ".join(r["name"] for r in clients)
            raise ValidationError(f"pool {slug!r} is still the egress for: {names}")
        self._x("DELETE FROM pool WHERE slug = ?", (slug,))

    def next_pool_esid(self) -> int:
        return self._alloc_esid("pool", config.POOL_ESID_MIN, config.POOL_ESID_MAX)

    # -- clients ------------------------------------------------------------

    def _row_to_client(self, r: sqlite3.Row) -> Client:
        return Client(
            id=r["id"],
            name=r["name"],
            ip=r["ip"],
            mac=r["mac"],
            egress_kind=EgressKind(r["egress_kind"]),
            egress_slug=r["egress_slug"],
            enabled=bool(r["enabled"]),
            notes=r["notes"],
        )

    def clients(self, enabled_only: bool = False) -> list[Client]:
        sql = "SELECT * FROM client"
        if enabled_only:
            sql += " WHERE enabled = 1"
        return [self._row_to_client(r) for r in self._q(sql + " ORDER BY ip")]

    def client(self, ip: str) -> Client | None:
        rows = self._q("SELECT * FROM client WHERE ip = ?", (ip,))
        return self._row_to_client(rows[0]) if rows else None

    def add_client(self, c: Client) -> Client:
        if self.client(c.ip):
            raise ValidationError(f"a client with IP {c.ip} already exists")
        self._assert_egress_exists(c)
        cur = self._x(
            "INSERT INTO client (name, ip, mac, egress_kind, egress_slug,"
            " enabled, notes, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                c.name, c.ip, c.mac, c.egress_kind.value, c.egress_slug,
                int(c.enabled), c.notes, time.time(),
            ),
        )
        c.id = cur.lastrowid
        return c

    def update_client(self, c: Client) -> None:
        self._assert_egress_exists(c)
        self._x(
            "UPDATE client SET name=?, mac=?, egress_kind=?, egress_slug=?,"
            " enabled=?, notes=? WHERE ip=?",
            (
                c.name, c.mac, c.egress_kind.value, c.egress_slug,
                int(c.enabled), c.notes, c.ip,
            ),
        )

    def delete_client(self, ip: str) -> None:
        self._x("DELETE FROM client WHERE ip = ?", (ip,))

    def _assert_egress_exists(self, c: Client) -> None:
        if not c.egress_slug:
            return  # unassigned: the ruleset will simply drop its traffic
        found = (
            self.tunnel(c.egress_slug)
            if c.egress_kind is EgressKind.TUNNEL
            else self.pool(c.egress_slug)
        )
        if not found:
            raise ValidationError(
                f"unknown {c.egress_kind.value} {c.egress_slug!r}"
            )

    # -- key/value ----------------------------------------------------------

    # -- panel sessions -----------------------------------------------------

    def sessions_load(self) -> dict[str, float]:
        """Every session that has not expired yet, for the daemon to adopt."""
        self._x("DELETE FROM session WHERE expires < ?", (time.time(),))
        return {r["token_hash"]: r["expires"]
                for r in self._q("SELECT token_hash, expires FROM session")}

    def session_put(self, token_hash: str, expires: float) -> None:
        self._x("INSERT INTO session(token_hash, expires) VALUES(?, ?) "
                "ON CONFLICT(token_hash) DO UPDATE SET expires = excluded.expires",
                (token_hash, expires))

    def session_drop(self, token_hash: str) -> None:
        self._x("DELETE FROM session WHERE token_hash = ?", (token_hash,))

    def sessions_clear(self) -> None:
        self._x("DELETE FROM session")

    def get(self, key: str, default: str | None = None) -> str | None:
        rows = self._q("SELECT value FROM kv WHERE key = ?", (key,))
        return rows[0]["value"] if rows else default

    def set(self, key: str, value: str) -> None:
        self._x(
            "INSERT INTO kv (key, value) VALUES (?,?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def unset(self, key: str) -> None:
        self._x("DELETE FROM kv WHERE key = ?", (key,))

    # -- events -------------------------------------------------------------

    def log_event(self, level: str, source: str, message: str) -> None:
        if not self.events_enabled:
            return
        self._x(
            "INSERT INTO event (ts, level, source, message) VALUES (?,?,?,?)",
            (time.time(), level, source, message),
        )
        # keep the table bounded; this box has no log rotation for sqlite
        self._x(
            "DELETE FROM event WHERE id < (SELECT MAX(id) - 5000 FROM event)"
        )

    def events(self, limit: int = 200) -> list[dict]:
        return [
            dict(r)
            for r in self._q(
                "SELECT * FROM event ORDER BY id DESC LIMIT ?", (limit,)
            )
        ]
