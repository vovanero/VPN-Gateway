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
import threading
import time

from .config import HealthSettings
from .models import TunnelKind, HealthState, Tunnel, TunnelHealth
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
    def __init__(self, settings: HealthSettings, *, background: bool = True) -> None:
        self.s = settings
        self.state: dict[str, TunnelHealth] = {}
        # A driver's own probe - a proxy's HTTPS request through two hops,
        # and its diagnosis when that fails - can take half a minute, and the
        # loop that called it is the one every other tunnel's failover waits
        # on. The daemon's API, too, waits on its first pass. So such probes
        # run in a thread of their own; the loop collects the result on a
        # later pass. Found on the reference gateway: four free proxies, two
        # of them slow, and the API did not answer within the updater's 36 s,
        # which rolled the update back.
        self.background = background
        self._inflight: dict[str, tuple[threading.Thread, dict]] = {}

    def get(self, slug: str) -> TunnelHealth:
        if slug not in self.state:
            self.state[slug] = TunnelHealth(slug=slug)
        return self.state[slug]

    def forget(self, slug: str) -> None:
        self.state.pop(slug, None)
        self._inflight.pop(slug, None)       # a running probe just finishes

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

        # A driver can measure less often than the loop runs. Proxy egress
        # does: its probe is a real HTTP request through the proxy, and
        # residential proxies are usually paid for by the byte. Once UP it is
        # re-measured every probe_interval seconds; until then, every pass, so
        # a new proxy comes up promptly. The hint above runs every pass
        # regardless, so a dead relay is still noticed at once.
        #
        # DOWN is rate-limited too: a dead proxy's probe runs to its timeout,
        # and the loop that waits for it is the one every other tunnel's
        # failover runs in. Only a proxy still being measured for the first
        # time is probed every pass, so a new one comes up promptly - and so
        # is one whose state is on its way to changing (see _settled).
        interval = getattr(driver, "probe_interval", 0)
        if interval and self._settled(h) and now - h.last_sample < interval:
            return h
        probe = getattr(driver, "probe", None)
        if probe is not None:
            result = self._collect(t, probe) if self.background else probe(t)
            if result is None:
                return h                    # still measuring: nothing to settle
            ok, rtt, exit_ip, reason = result
        else:
            ok, rtt = ping_via(t.iface, self.s.probe_target, self.s.probe_timeout)
            exit_ip, reason = None, ""
        h.last_sample = now
        h.rtt_ms = rtt if ok else None
        if ok and exit_ip:
            if exit_ip != h.exit_ip:
                log.info("%s exit address is now %s", t.slug, exit_ip)
            h.exit_ip = exit_ip
            h.exit_ip_checked = now
        return self._settle(h, ok, "" if ok else (reason or "probe timed out"))

    def _collect(self, t: Tunnel, probe):
        """Start probe(t) beside the loop, or hand back what it found.

        None while a probe runs - the first call starts it - and its result,
        once, when it has finished.
        """
        running = self._inflight.get(t.slug)
        if running is None:
            box: dict = {}

            def measure() -> None:
                try:
                    box["result"] = probe(t)
                except Exception as exc:     # a probe that throws has failed
                    box["result"] = (False, None, None, f"probe failed: {exc}")

            thread = threading.Thread(target=measure, name=f"probe-{t.slug}",
                                      daemon=True)
            self._inflight[t.slug] = (thread, box)
            thread.start()
            return None
        thread, box = running
        if thread.is_alive():
            return None
        del self._inflight[t.slug]
        return box.get("result")

    @staticmethod
    def _settled(h) -> bool:
        """UP with nothing failing since, or DOWN with nothing succeeding.

        A state on its way to changing is measured every pass until it has
        changed or not. Otherwise a proxy whose login was just fixed would
        sit at "down" for rise_threshold rate-limited intervals - a minute
        and more of the panel contradicting the test that just passed.
        """
        return ((h.state is HealthState.UP and not h.consecutive_fail)
                or (h.state is HealthState.DOWN and not h.consecutive_ok))

    def refresh_exit_ip(self, t: Tunnel) -> None:
        h = self.get(t.slug)
        if h.state is not HealthState.UP:
            return
        if t.kind is TunnelKind.PROXY:
            # Its probe already reports the exit, measured through the relay;
            # curl --interface cannot route on a veth with no default route.
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
