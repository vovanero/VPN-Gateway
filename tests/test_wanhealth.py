"""The uplink chain: which link is broken, and how sure are we.

The feature's whole claim is that it names the *first* break rather than
turning everything red, and that it does not cry wolf over one lost packet.
Both are logic, and both are worth pinning down.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpngw import config  # noqa: E402
from vpngw.wanhealth import CHAIN, EXPLAIN, WanHealth, WanMonitor  # noqa: E402


def healthy() -> WanHealth:
    return WanHealth(
        iface="eth0", carrier=True, addresses=["10.0.0.5/24"],
        gateway="10.0.0.1", gateway_dev="eth0", gateway_reachable=True,
        internet_reachable=True, dns_ok=True, _settled_internet=True,
    )


class TestFirstBroken(unittest.TestCase):
    def test_a_healthy_chain_reports_no_break(self):
        h = healthy()
        self.assertIsNone(h.first_broken)
        self.assertTrue(h.online)

    def test_each_link_is_found_in_order(self):
        for name in CHAIN:
            with self.subTest(link=name):
                h = healthy()
                # Everything from this link onward fails too, which is what
                # a real break looks like: a downstream success would
                # (correctly) prove the link was crossed after all.
                fields = {
                    "carrier": "carrier",
                    "address": "addresses",
                    "gateway": "gateway_reachable",
                    "internet": "_settled_internet",
                    "dns": "dns_ok",
                }
                for later in CHAIN[CHAIN.index(name):]:
                    setattr(h, fields[later],
                            [] if later == "address" else False)
                self.assertEqual(h.first_broken, name)

    def test_the_earliest_break_wins(self):
        """A pulled cable also fails everything downstream. Reporting the
        last failure, or all of them, would send the operator to the wrong
        end of the problem."""
        h = healthy()
        h.carrier = False
        h.gateway_reachable = False
        h._settled_internet = False
        h.dns_ok = False
        self.assertEqual(h.first_broken, "carrier")

    def test_a_router_that_ignores_ping_is_not_a_broken_link(self):
        """Found by running it: the reference gateway's own router drops ICMP
        addressed to itself while forwarding perfectly, so the strip claimed
        a broken uplink on a box whose internet was demonstrably working.
        Traffic that arrives outranks a probe that does not."""
        h = healthy()
        h.gateway_reachable = False        # router silent
        h._settled_internet = True         # but the internet answers
        self.assertIsNone(h.first_broken)
        self.assertTrue(h.online)

    def test_a_genuinely_dead_uplink_still_names_the_gateway(self):
        h = healthy()
        h.gateway_reachable = False
        h._settled_internet = False
        h.dns_ok = False
        self.assertEqual(h.first_broken, "gateway")
        self.assertFalse(h.online)

    def test_an_unmeasured_link_is_not_a_broken_one(self):
        """None means the probe did not run. Treating that as a failure
        invents faults on a box that is fine."""
        h = healthy()
        h.gateway_reachable = None      # no default route to ping
        self.assertIsNone(h.first_broken)

    def test_every_link_has_something_to_say(self):
        """A status page that reports `internet: false` has told the operator
        less than they already knew."""
        for name in CHAIN:
            with self.subTest(link=name):
                self.assertTrue(EXPLAIN.get(name, "").strip(),
                                f"{name} has no explanation")

    def test_an_address_does_not_vouch_for_the_cable(self):
        """A static address survives the cable being pulled, so `address`
        must not be allowed to prove `carrier`. Letting it would make a dead
        uplink point at the wrong link."""
        h = healthy()
        h.carrier = False
        h.gateway_reachable = False
        h._settled_internet = False
        h.dns_ok = False
        self.assertEqual(h.first_broken, "carrier")

    def test_the_dict_carries_the_explanation_of_the_actual_break(self):
        h = healthy()
        h.gateway_reachable = False
        h._settled_internet = False
        h.dns_ok = False
        out = h.to_dict()
        self.assertEqual(out["first_broken"], "gateway")
        self.assertEqual(out["explain"], EXPLAIN["gateway"])
        self.assertFalse(out["online"])


class TestHysteresis(unittest.TestCase):
    """The uplink is the noisiest thing measured here. A strip that flickers
    on one dropped ICMP is a strip people stop reading."""

    def setUp(self):
        self.s = config.Settings()
        self.m = WanMonitor(self.s)
        self.h = self.m.state

    def test_one_lost_packet_does_not_flip_a_healthy_link(self):
        for _ in range(self.s.health.rise_threshold):
            self.m._settle(self.h, True)
        self.assertTrue(self.h._settled_internet)

        self.m._settle(self.h, False)
        self.assertTrue(self.h._settled_internet,
                        "a single failure changed the verdict")

    def test_it_gives_up_after_the_configured_run(self):
        for _ in range(self.s.health.rise_threshold):
            self.m._settle(self.h, True)
        for _ in range(self.s.health.fail_threshold):
            self.m._settle(self.h, False)
        self.assertFalse(self.h._settled_internet)

    def test_recovery_needs_a_run_too(self):
        for _ in range(self.s.health.fail_threshold):
            self.m._settle(self.h, False)
        self.assertFalse(self.h._settled_internet)
        self.m._settle(self.h, True)
        self.assertFalse(self.h._settled_internet,
                         "one good packet declared recovery")

    def test_the_very_first_probe_reports_what_it_saw(self):
        """Otherwise a plainly working box shows 'measuring' for the first
        several passes, which reads as a fault."""
        self.m._settle(self.h, True)
        self.assertTrue(self.h._settled_internet)


class TestDhcpUplink(unittest.TestCase):
    def test_the_gateway_comes_from_the_kernel_not_the_settings(self):
        """On DHCP `wan.gateway` is empty. The old check pinged that and
        reported 'unknown' forever - on exactly the boxes it was meant to
        reassure. The probe must read the route table instead."""
        import inspect

        from vpngw import wanhealth

        src = inspect.getsource(wanhealth.WanMonitor.probe)
        self.assertIn("routing.default_gateway()", src)
        self.assertNotIn("wan.gateway", src)


if __name__ == "__main__":
    unittest.main()
