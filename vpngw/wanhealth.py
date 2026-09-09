"""Is this gateway connected, and if not, where does it stop?

The panel could always say a great deal about tunnels and nothing about the
network underneath them. That is the wrong way round for the question an
operator actually asks, which is never "what is the handshake age of nl01"
and always "is this thing on the internet".

The answer is not one boolean. On this box "connected" could mean the cable
is in, or the interface has an address, or the upstream router answers, or
the internet answers, or names resolve, or a client can actually get out -
and those come apart all the time. A single green light would have to pick
one and be wrong about the others, so this measures the chain link by link
and reports which link is the first to fail. That is the sentence the
operator needs: not "something is wrong" but "the cable is out".

Everything here is ICMP or a file in /sys. The output chain permits
`oifname $WAN icmp type { echo-request, echo-reply }` unconditionally, so no
probe here needs a firewall change; a TCP or HTTP probe would be dropped by
the gateway's own strict egress, which is why ping is the instrument.
"""

from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass, field

from . import config
from .health import ping_via
from .net import ifaces, routing

log = logging.getLogger("vpngw.wanhealth")

#: Links in the order a packet meets them. The panel colours the first one
#: that is False and greys everything after it, because a chain that goes
#: entirely red when the cable is out has told nobody anything.
CHAIN = ("carrier", "address", "gateway", "internet", "dns")

#: The links whose success is *evidence that traffic crossed everything
#: before them*. Only these can vouch for an earlier link that failed its own
#: probe. `address` cannot: a static address stays configured with the cable
#: pulled, so "it has an address" says nothing about carrier. Getting this
#: wrong makes a dead uplink report the wrong break, which is worse than
#: reporting none.
PROVES_UPSTREAM = ("gateway", "internet", "dns")

#: What each failure means in one sentence, and what to do about it. Shown
#: verbatim in the panel: an operator reading "internet: false" learns less
#: than one reading where the break is.
EXPLAIN = {
    "carrier": "No cable detected on the uplink. Check the adapter and, on "
               "a VM, that its virtual switch is connected.",
    "address": "The uplink has no IPv4 address. If it is set to DHCP, no "
               "lease arrived; if static, the address was never applied.",
    "gateway": "The upstream router is not answering. The address may be on "
               "the wrong network, or the router itself is down.",
    "internet": "The router answers but the internet does not. The uplink is "
                "connected to something that cannot route out.",
    "dns": "Names do not resolve. The bootstrap resolvers are unreachable, "
           "which stops any tunnel whose endpoint is a hostname.",
}


@dataclass
class WanHealth:
    """One measurement of the uplink, with the same hysteresis as a tunnel.

    Not persisted: it describes the world right now, and a restart re-measures
    within one reconcile pass.
    """

    iface: str = ""
    carrier: bool | None = None
    addresses: list[str] = field(default_factory=list)
    gateway: str = ""
    gateway_dev: str = ""
    gateway_reachable: bool | None = None
    internet_reachable: bool | None = None
    rtt_ms: float | None = None
    dns_ok: bool | None = None
    last_probe: float = 0.0

    # Hysteresis counters for the one link that flaps: reachability.
    _fails: int = 0
    _oks: int = 0
    _settled_internet: bool | None = None

    @property
    def links(self) -> dict[str, bool | None]:
        """Each link's state. None means "not measured", not "broken"."""
        return {
            "carrier": self.carrier,
            "address": bool(self.addresses) if self.iface else None,
            "gateway": self.gateway_reachable,
            "internet": self._settled_internet,
            "dns": self.dns_ok,
        }

    @property
    def first_broken(self) -> str | None:
        """The earliest link that is measurably down, or None.

        Two things do not count as a break.

        A link that could not be measured (None): reporting a probe that
        never ran as a failure would send the operator after a fault that is
        not there.

        And a failed link that a later *reachability* probe vouches for.
        Plenty of routers drop ICMP addressed to themselves while forwarding
        perfectly - the reference gateway's does - so "the router did not
        answer" and "the internet answered through it" are both true at once.
        When that happens the packet demonstrably crossed the link, and the
        silence is a fact about the probe rather than about the network.

        Only PROVES_UPSTREAM links may vouch. Having an address proves
        nothing about the cable, and letting it vouch would make a genuinely
        dead uplink report the wrong break.
        """
        links = self.links
        for index, name in enumerate(CHAIN):
            if links.get(name) is not False:
                continue
            if any(links.get(later) is True
                   for later in CHAIN[index + 1:] if later in PROVES_UPSTREAM):
                continue          # traffic crossed it; the probe just went unanswered
            return name
        return None

    @property
    def online(self) -> bool:
        """The whole chain, for the one place a single word is wanted.

        Anchored on the internet probe rather than on every link passing,
        for the same reason as above: a router that ignores ping does not
        make a working uplink offline.
        """
        return self.first_broken is None and self._settled_internet is True

    def to_dict(self) -> dict:
        broken = self.first_broken
        return {
            "iface": self.iface,
            "addresses": self.addresses,
            "gateway": self.gateway,
            "gateway_dev": self.gateway_dev,
            "rtt_ms": self.rtt_ms,
            "links": self.links,
            "first_broken": broken,
            "explain": EXPLAIN.get(broken or "", ""),
            "online": self.online,
            "last_probe": self.last_probe,
        }


class WanMonitor:
    """Probes the uplink once per reconcile pass.

    Deliberately the same cadence and the same rise/fail thresholds as tunnel
    health: an operator watching both should not have to learn that one of
    them reacts differently from the other.
    """

    def __init__(self, settings: config.Settings) -> None:
        self.s = settings
        self.state = WanHealth()

    def probe(self) -> WanHealth:
        h = self.state
        net, health = self.s.net, self.s.health
        h.iface = net.wan_iface
        h.last_probe = time.time()

        if not h.iface:
            return h

        h.carrier = ifaces.carrier_of(h.iface)
        h.addresses = sorted(ifaces.addresses(h.iface))

        # From the kernel, not from settings: on DHCP there is no configured
        # gateway to ping, which is exactly the case that used to report
        # "unknown" forever.
        h.gateway, h.gateway_dev = routing.default_gateway()

        if h.gateway:
            ok, _ = ping_via(h.iface, h.gateway, health.probe_timeout)
            h.gateway_reachable = ok
        else:
            h.gateway_reachable = None

        reachable, rtt = ping_via(h.iface, health.probe_target,
                                  health.probe_timeout)
        h.rtt_ms = rtt if reachable else None
        self._settle(h, reachable)

        h.dns_ok = self._resolves()
        return h

    def _settle(self, h: WanHealth, reachable: bool) -> None:
        """Hysteresis, so one lost packet does not repaint the dashboard.

        The uplink is the noisiest thing this box measures - a single ICMP
        can go missing on a healthy link - and a status strip that flickers
        is one an operator learns to ignore.
        """
        if reachable:
            h._oks += 1
            h._fails = 0
            if h._settled_internet is not True and h._oks >= self.s.health.rise_threshold:
                h._settled_internet = True
        else:
            h._fails += 1
            h._oks = 0
            if h._settled_internet is not False and h._fails >= self.s.health.fail_threshold:
                h._settled_internet = False
        if h._settled_internet is None and (h._oks or h._fails):
            # First few passes after a start: report what we have rather than
            # nothing, or the panel shows "measuring" for a quarter of a minute
            # on a box that is plainly working.
            h._settled_internet = reachable

    def _resolves(self) -> bool | None:
        """One bootstrap name, briefly.

        Mirrors what `importers.resolve_endpoints` does when a tunnel is
        imported, because that is the lookup that actually matters here: a
        gateway that cannot resolve cannot bring up a tunnel whose endpoint
        is a hostname.
        """
        servers = [s for s in self.s.dns.bootstrap if s]
        if not servers:
            return None
        previous = socket.getdefaulttimeout()
        socket.setdefaulttimeout(max(1, self.s.health.probe_timeout))
        try:
            socket.getaddrinfo("one.one.one.one", None, family=socket.AF_INET)
            return True
        except OSError:
            return False
        finally:
            socket.setdefaulttimeout(previous)
