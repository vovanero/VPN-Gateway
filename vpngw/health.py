"""Tunnel liveness.

A tunnel is "up" when packets actually cross it, not when the interface exists.
An interface can sit there perfectly configured while the far end has stopped
answering, and a pool that trusts the interface would never fail over.

Two signals, in order:

* a **protocol hint** - a WireGuard peer whose last handshake is minutes old,
  or an OpenVPN unit that is not running. Cheap, instant, and decisive.
* an **active probe** - an ICMP echo bound to the interface with
  SO_BINDTODEVICE, which forces the packet down that specific tunnel rather
  than wherever the routing table would send it.

Both are wrapped in hysteresis. A single lost packet on a busy tunnel must not
drag every client on it through a failover; that is how a marginally lossy link
turns into a machine that reconnects every five seconds.
"""

from __future__ import annotations

import logging
import re
import time

from .config import HealthSettings
from .models import HealthState, Tunnel, TunnelHealth
from .net.shell import try_run
from .tunnels import driver_for

log = logging.getLogger("vpngw.health")

RTT_RE = re.compile(r"time[=<]([\d.]+)\s*ms")
TRACE_IP_RE = re.compile(r"^ip=(.+)$", re.MULTILINE)

EXIT_IP_URLS = [
    "https://1.1.1.1/cdn-cgi/trace",
    "https://icanhazip.com",
]


def ping_via(iface: str, target: str, timeout: int) -> tuple[bool, float | None]:
    """ICMP echo forced onto one interface.

    ``ping -I <iface>`` uses SO_BINDTODEVICE, which bypasses the routing table
    entirely. That is what we want: it tests the tunnel itself rather than
    testing whether our own policy rules happen to point at it.
    """
    res = try_run(
        ["ping", "-I", iface, "-c", "1", "-W", str(timeout), "-n", "-q", target],
        timeout=timeout + 3,
    )
    if not res.ok:
        return False, None
    m = RTT_RE.search(res.stdout) or re.search(
        r"=\s*[\d.]+/([\d.]+)/", res.stdout
    )
    return True, float(m.group(1)) if m else None


def exit_ip_via(iface: str, timeout: int = 8) -> str | None:
    """The public address the world sees for traffic on this tunnel.

    Displayed in the UI, and the honest answer to "is this client really
    coming out of the Netherlands". Failure here is not a health signal - it
    only means the check endpoint was unreachable.
    """
    for url in EXIT_IP_URLS:
        res = try_run(
            ["curl", "--interface", iface, "--silent", "--fail",
             "--max-time", str(timeout), url],
            timeout=timeout + 3,
        )
        if not res.ok or not res.stdout.strip():
            continue
        body = res.stdout.strip()
        m = TRACE_IP_RE.search(body)
        if m:
            return m.group(1).strip()
        first = body.splitlines()[0].strip()
        if first and len(first) <= 45 and " " not in first:
            return first
    return None


class HealthMonitor:
    def __init__(self, settings: HealthSettings) -> None:
        self.s = settings
        self.state: dict[str, TunnelHealth] = {}

    def get(self, slug: str) -> TunnelHealth:
        if slug not in self.state:
            self.state[slug] = TunnelHealth(slug=slug)
        return self.state[slug]

    def forget(self, slug: str) -> None:
        self.state.pop(slug, None)

    def healthy(self, slug: str) -> bool:
        h = self.state.get(slug)
        return bool(h and h.state is HealthState.UP)

    # -- probing ------------------------------------------------------------

    def probe(self, t: Tunnel) -> TunnelHealth:
        h = self.get(t.slug)
        now = time.time()
        h.last_probe = now

        if not t.enabled:
            return self._transition(h, HealthState.DISABLED, "administratively disabled")

        driver = driver_for(t)
        verdict, reason = driver.healthy_hint(t)

        if verdict is False:
            h.rtt_ms = None
            return self._settle(h, False, reason)

        ok, rtt = ping_via(t.iface, self.s.probe_target, self.s.probe_timeout)
        if ok:
            h.rtt_ms = rtt
        else:
            h.rtt_ms = None
        return self._settle(h, ok, "" if ok else "probe timed out")

    def refresh_exit_ip(self, t: Tunnel) -> None:
        h = self.get(t.slug)
        if h.state is not HealthState.UP:
            return
        if time.time() - h.exit_ip_checked < self.s.exitip_interval:
            return
        h.exit_ip_checked = time.time()
        ip = exit_ip_via(t.iface)
        if ip and ip != h.exit_ip:
            log.info("%s exit address is now %s", t.slug, ip)
        if ip:
            h.exit_ip = ip

    # -- state machine ------------------------------------------------------

    def _settle(self, h: TunnelHealth, ok: bool, reason: str) -> TunnelHealth:
        if ok:
            h.consecutive_ok += 1
            h.consecutive_fail = 0
            h.last_error = ""
            if h.state is not HealthState.UP and h.consecutive_ok >= self.s.rise_threshold:
                return self._transition(h, HealthState.UP, "")
        else:
            h.consecutive_fail += 1
            h.consecutive_ok = 0
            h.last_error = reason
            if h.state is not HealthState.DOWN and h.consecutive_fail >= self.s.fail_threshold:
                return self._transition(h, HealthState.DOWN, reason)
        return h

    def _transition(self, h: TunnelHealth, new: HealthState, reason: str) -> TunnelHealth:
        if h.state is new:
            return h
        old = h.state
        h.state = new
        h.last_change = time.time()
        h.up_since = time.time() if new is HealthState.UP else None
        if new is not HealthState.UP:
            h.exit_ip = None
            h.exit_ip_checked = 0.0
        detail = f" ({reason})" if reason else ""
        log.warning("tunnel %s: %s -> %s%s", h.slug, old.value, new.value, detail)
        return h

    def stable_for(self, slug: str) -> float:
        h = self.state.get(slug)
        if not h or not h.last_change:
            return 0.0
        return time.time() - h.last_change
