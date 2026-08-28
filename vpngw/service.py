"""The daemon.

A single reconcile thread owns all kernel state; the HTTP API runs alongside it
and communicates by setting a flag. Nothing else writes to nftables or the
routing table, which is what keeps "what the box is doing" equal to "what the
database says" rather than to some accumulated history of API calls.

On shutdown the firewall is deliberately left loaded. Stopping the control
plane must not open the gate - `systemctl stop vpngw` should cost you your
management API, not your kill switch.
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
import time
from collections import deque

from . import config
from .db import Database
from .reconciler import Reconciler

log = logging.getLogger("vpngw")

# Roughly fifteen minutes at the default five-second probe interval. Kept in
# the daemon rather than in the browser so a reloaded page still has context,
# and so several people watching the same gateway see the same graph.
HISTORY_SAMPLES = 180


def setup_logging(level: str | None = None) -> None:
    """Quiet by default, on purpose.

    At INFO the journal accumulates a history of the network: which machine
    appeared when (discovery logs client IPs and MACs), every tunnel event,
    every command run. On a privacy gateway with a persistent journal that is
    surveillance of its own users, kept indefinitely, by default. WARNING
    keeps what an operator needs when something is wrong - failures, config
    changes, security-relevant transitions - and records nothing about who
    was on the network while everything was fine.

    Set VPNGW_LOG_LEVEL=info (or debug) while diagnosing; the Events page in
    the panel still shows recent activity either way, from its own bounded
    table.
    """
    import os

    chosen = (level or os.environ.get("VPNGW_LOG_LEVEL") or "SILENT").upper()
    logging.basicConfig(
        format="%(asctime)s %(levelname)-7s %(name)-16s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    apply_log_level(chosen)


#: The operator's words for it -> what the logging module does. "silent" is
#: above CRITICAL so nothing at all is emitted.
_LOG_LEVELS = {
    "NONE": logging.CRITICAL + 10, "SILENT": logging.CRITICAL + 10,
    "NORMAL": logging.WARNING, "WARNING": logging.WARNING,
    "HIGH": logging.INFO, "INFO": logging.INFO, "DEBUG": logging.DEBUG,
}


def apply_log_level(name: str) -> None:
    logging.getLogger().setLevel(
        _LOG_LEVELS.get(name.upper(), logging.CRITICAL + 10))


class Service:
    def __init__(self, settings: config.Settings | None = None) -> None:
        self.settings = settings or config.Settings.load()
        self.db = Database()
        self.db.events_enabled = self.settings.log.level != "none"
        apply_log_level(self.settings.log.level)
        self.reconciler = Reconciler(self.db, self.settings)
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str = ""
        self.started_at = time.time()
        self.history: dict[str, deque] = {}
        self._prev_counters: dict[str, tuple[float, int, int]] = {}

    def reload_settings(self) -> None:
        """Re-read the configuration file into every component holding it.

        Without this the daemon keeps serving whatever it loaded at startup,
        so the panel shows a change as missing the moment it re-reads - which
        looks exactly like the save having failed. Interfaces and DHCP still
        need a restart to take effect; this is about what is reported being
        true.
        """
        self.settings = config.Settings.load()
        self.reconciler.settings = self.settings
        # Both halves of the logging choice, applied immediately: the journal
        # level, and whether the events table records anything new.
        apply_log_level(self.settings.log.level)
        self.db.events_enabled = self.settings.log.level != "none"
        log.info("settings reloaded from %s", config.CONFIG_FILE)

    # -- control ------------------------------------------------------------

    def request_reconcile(self) -> None:
        """Ask the loop to run a pass now. Safe from any thread."""
        self._wake.set()

    def start(self) -> None:
        self.reconciler.bootstrap()
        self._thread = threading.Thread(
            target=self._loop, name="reconcile", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=10)
        log.info("stopped; the firewall stays loaded on purpose")

    # -- loop ---------------------------------------------------------------

    def _loop(self) -> None:
        interval = self.settings.health.probe_interval
        while not self._stop.is_set():
            self._wake.wait(timeout=interval)
            self._wake.clear()
            if self._stop.is_set():
                break
            try:
                self.reconciler.reconcile()
                self.reconciler.refresh_endpoints()
                self.sample_stats()
                self.last_error = ""
            except Exception as exc:  # keep the loop alive no matter what
                self.last_error = str(exc)
                log.exception("reconcile pass failed: %s", exc)
                self.db.log_event("error", "reconcile", str(exc))
                time.sleep(2)

    # -- statistics ---------------------------------------------------------

    def sample_stats(self) -> None:
        """One throughput and latency sample per tunnel, appended to history.

        Sampled here, in the loop, rather than when the UI asks: rates need a
        known interval between readings, and several browsers polling at
        different times would otherwise each compute a different number from
        the same counters.
        """
        from .models import HealthState
        from .net import ifaces

        now = time.time()
        for t in self.db.tunnels():
            rx, tx = ifaces.counters(t.iface)
            prev = self._prev_counters.get(t.slug)
            rx_rate = tx_rate = 0.0
            if prev:
                elapsed = now - prev[0]
                # A decrease means the interface was recreated and its counters
                # restarted at zero; report nothing rather than a huge negative.
                if elapsed > 0 and rx >= prev[1] and tx >= prev[2]:
                    rx_rate = (rx - prev[1]) / elapsed
                    tx_rate = (tx - prev[2]) / elapsed
            self._prev_counters[t.slug] = (now, rx, tx)

            health = self.reconciler.health.get(t.slug)
            self.history.setdefault(
                t.slug, deque(maxlen=HISTORY_SAMPLES)
            ).append({
                "t": round(now),
                "rtt": round(health.rtt_ms, 1) if health.rtt_ms else None,
                "rx": round(rx_rate),
                "tx": round(tx_rate),
                "up": health.state is HealthState.UP,
            })

        for stale in set(self.history) - {t.slug for t in self.db.tunnels()}:
            self.history.pop(stale, None)
            self._prev_counters.pop(stale, None)

    # -- reporting ----------------------------------------------------------

    def snapshot(self) -> dict:
        """Everything the UI and CLI need, from one consistent read."""
        from .models import EgressKind, HealthState
        from .net import nft, routing

        tunnels = self.db.tunnels()
        pools = self.db.pools()
        clients = self.db.clients()
        counters = nft.counters()

        # How many clients each egress carries, so the UI can warn before you
        # disable something ten machines are using.
        load: dict[tuple[str, str], int] = {}
        for c in clients:
            if c.enabled and c.egress_slug:
                key = (c.egress_kind.value, c.egress_slug)
                load[key] = load.get(key, 0) + 1

        tunnel_rows = []
        for t in tunnels:
            h = self.reconciler.health.get(t.slug)
            samples = list(self.history.get(t.slug, ()))
            latest = samples[-1] if samples else {}
            pool_load = sum(
                load.get(("pool", p.slug), 0)
                for p in pools
                if self.reconciler.pools.get(p.slug).active == t.slug
            )
            tunnel_rows.append({
                "slug": t.slug,
                "name": t.name,
                "kind": t.kind.value,
                "iface": t.iface,
                "enabled": t.enabled,
                "esid": t.esid,
                "table": t.table,
                "mark": t.mark,
                "state": h.state.value,
                "via": t.via,
                "rtt_ms": h.rtt_ms,
                "exit_ip": h.exit_ip,
                "up_since": h.up_since,
                "last_change": h.last_change,
                "last_error": h.last_error,
                "endpoints": t.endpoints,
                "endpoint_hosts": t.endpoint_hosts,
                "dns": t.dns,
                "mtu": t.mtu,
                "notes": t.notes,
                "routed": routing.table_default(t.table) == t.iface,
                "rx_rate": latest.get("rx", 0),
                "tx_rate": latest.get("tx", 0),
                "direct_clients": load.get(("tunnel", t.slug), 0),
                "pool_clients": pool_load,
                "in_pools": [p.slug for p in pools
                             if any(m.tunnel_slug == t.slug for m in p.members)],
                "history": samples,
            })

        pool_rows = []
        for p in pools:
            st = self.reconciler.pools.get(p.slug)
            pool_rows.append({
                "slug": p.slug,
                "name": p.name,
                "enabled": p.enabled,
                "strategy": p.strategy.value,
                "esid": p.esid,
                "table": p.table,
                "active": st.active,
                "reason": st.last_reason,
                "since": st.since,
                "members": [
                    {
                        "slug": m.tunnel_slug,
                        "priority": m.priority,
                        "state": self.reconciler.health.get(m.tunnel_slug).state.value,
                        "rtt_ms": self.reconciler.health.get(m.tunnel_slug).rtt_ms,
                    }
                    for m in p.ordered_members()
                ],
                "healthy_members": sum(
                    1 for m in p.members
                    if self.reconciler.health.healthy(m.tunnel_slug)
                ),
                "sticky_seconds": p.sticky_seconds,
                "rotate_seconds": p.rotate_seconds,
                "clients": load.get(("pool", p.slug), 0),
                "notes": p.notes,
            })

        def egress_state(c) -> str:
            if not c.egress_slug:
                return "unassigned"
            if c.egress_kind is EgressKind.TUNNEL:
                return self.reconciler.health.get(c.egress_slug).state.value
            st = self.reconciler.pools.get(c.egress_slug)
            if not st.active:
                return HealthState.DOWN.value
            return self.reconciler.health.get(st.active).state.value

        client_rows = [{
            "name": c.name,
            "ip": c.ip,
            "mac": c.mac,
            "enabled": c.enabled,
            "egress_kind": c.egress_kind.value,
            "egress_slug": c.egress_slug,
            "egress_state": egress_state(c),
            "notes": c.notes,
        } for c in clients]

        net = self.settings.net
        return {
            "tunnels": tunnel_rows,
            "pools": pool_rows,
            "clients": client_rows,
            "counters": counters,
            "killswitch": {
                "leaked_packets": counters.get("wan_leak_drop", {}).get("packets", 0),
                "leaked_bytes": counters.get("wan_leak_drop", {}).get("bytes", 0),
                "blocked_unclassified": counters.get(
                    "unclassified_drop", {}).get("packets", 0),
                "blocked_nontunnel": counters.get(
                    "nontunnel_drop", {}).get("packets", 0),
                "forwarded": counters.get("forwarded_new", {}).get("packets", 0),
                "dns_hijacked": counters.get("dns_hijacked", {}).get("packets", 0),
                "strict_host_egress": self.settings.killswitch.strict_host_egress,
                "maintenance": self.reconciler.maintenance_active(),
                "maintenance_remaining": self.reconciler.maintenance_remaining(),
            },
            "totals": {
                "tunnels_up": sum(1 for t in tunnel_rows if t["state"] == "up"),
                "tunnels_total": sum(1 for t in tunnel_rows if t["enabled"]),
                "pools_degraded": sum(1 for p in pool_rows
                                      if p["enabled"] and not p["active"]),
                "clients_online": sum(1 for c in client_rows
                                      if c["egress_state"] == "up"),
                "clients_blocked": sum(1 for c in client_rows
                                       if c["enabled"] and c["egress_state"] != "up"),
                "clients_total": len(client_rows),
                "rx_rate": sum(t["rx_rate"] for t in tunnel_rows),
                "tx_rate": sum(t["tx_rate"] for t in tunnel_rows),
            },
            "system": {
                "version": __import__("vpngw").__version__,
                "uptime": time.time() - self.started_at,
                "lan_cidr": net.lan_cidr,
                "lan_gateway": str(net.lan_address),
                "wan_iface": net.wan_iface,
                "mgmt_iface": net.mgmt_iface,
                "resolver_subnet": self.settings.dns.resolver_subnet,
                "probe_interval": self.settings.health.probe_interval,
            },
            "last_pass": self.reconciler._last_pass,
            "last_error": self.last_error,
        }


def main() -> int:
    setup_logging()
    try:
        service = Service()
    except Exception as exc:
        log.error("cannot start: %s", exc)
        return 1

    stopping = threading.Event()

    def handle(signum, _frame):
        log.info("signal %d received", signum)
        stopping.set()

    signal.signal(signal.SIGTERM, handle)
    signal.signal(signal.SIGINT, handle)

    try:
        service.start()
    except Exception as exc:
        log.error("bootstrap failed: %s", exc)
        return 1

    from .api import serve

    api_thread = threading.Thread(
        target=serve, args=(service,), name="api", daemon=True
    )
    api_thread.start()

    while not stopping.is_set():
        stopping.wait(timeout=1)

    service.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
