"""Proxy egress: SOCKS5 and HTTP CONNECT proxies as an exit.

A proxy egress is a tunnel whose interface is a veth into its own network
namespace, where redsocks relays every TCP connection to the proxy. It is
always chained behind a WireGuard or OpenVPN tunnel - dialled directly, the
proxy provider would see this gateway's real address - and it carries TCP
only.

Written in the style of test_chains.py: the model and the database first,
because every rule elsewhere assumes these invariants hold.
"""

from __future__ import annotations

import ipaddress
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpngw import config  # noqa: E402
from vpngw.db import Database  # noqa: E402
from vpngw.models import (  # noqa: E402
    PoolMember, Tunnel, TunnelKind, ValidationError, validate_proxy,
)


def wg(slug, esid, endpoints=None, via="", enabled=True):
    return Tunnel(slug=slug, name=slug, kind=TunnelKind.WIREGUARD, esid=esid,
                  endpoints=endpoints or [], via=via, enabled=enabled)


def px(slug, esid, via="nl01", host="203.0.113.50", port=1080, kind="socks5"):
    return Tunnel(slug=slug, name=slug, kind=TunnelKind.PROXY, esid=esid,
                  via=via, proxy={"type": kind, "host": host, "port": port})


class TheModel(unittest.TestCase):

    def test_a_proxy_cannot_exist_without_an_entry(self):
        """There is no direct mode, so there is no direct object either."""
        with self.assertRaises(ValidationError):
            px("res-de1", 7, via="")

    def test_types_are_normalised(self):
        p = validate_proxy({"type": "SOCKS5", "host": "gate.example.net",
                            "port": "7000"})
        self.assertEqual(p, {"type": "socks5", "host": "gate.example.net",
                             "port": 7000})

    def test_unknown_types_are_refused(self):
        for kind in ("socks4", "https", "shadowsocks", ""):
            with self.subTest(kind=kind), self.assertRaises(ValidationError):
                validate_proxy({"type": kind, "host": "h", "port": 1})

    def test_ipv6_servers_are_refused(self):
        """The gateway carries no IPv6; a v6 proxy could never be reached."""
        for host in ("2001:db8::1", "[2001:db8::1]"):
            with self.subTest(host=host), self.assertRaises(ValidationError):
                validate_proxy({"type": "http", "host": host, "port": 80})

    def test_ports_are_bounded(self):
        for port in (0, 65536, -1, "x", None):
            with self.subTest(port=port), self.assertRaises(ValidationError):
                validate_proxy({"type": "http", "host": "h", "port": port})

    def test_a_host_is_required(self):
        for host in ("", "   ", "two words"):
            with self.subTest(host=host), self.assertRaises(ValidationError):
                validate_proxy({"type": "http", "host": host, "port": 80})

    def test_names_fit_the_kernel(self):
        t = px("abcdefghij", 7)                     # the longest slug allowed
        self.assertEqual(t.iface, "px-abcdefghij")
        self.assertLessEqual(len(t.iface), 15)      # IFNAMSIZ - 1
        self.assertEqual(t.netns, "vpngw-px-abcdefghij")

    def test_only_proxies_have_a_namespace(self):
        self.assertEqual(wg("nl01", 1).netns, "")


class TheLinkAddresses(unittest.TestCase):

    def test_each_egress_gets_its_own_slash_30(self):
        seen = set()
        for esid in range(config.TUNNEL_ESID_MIN, config.TUNNEL_ESID_MAX + 1):
            host, ns = config.proxy_link(esid)
            net = ipaddress.ip_network(f"{host}/30", strict=False)
            self.assertNotIn(net, seen)
            seen.add(net)
            self.assertTrue(net.subnet_of(config.PROXY_LINK_NET))
            self.assertNotEqual(host, ns)
            self.assertNotIn(ipaddress.ip_address(host),
                             (net.network_address, net.broadcast_address))
            self.assertNotIn(ipaddress.ip_address(ns),
                             (net.network_address, net.broadcast_address))

    def test_a_lan_inside_the_link_range_is_refused(self):
        net = config.NetSettings(lan_cidr="169.254.241.1/24")
        with self.assertRaises(ValueError) as caught:
            config.Settings(net=net).validate()
        self.assertIn("proxy link range", str(caught.exception))


class TheDatabase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Database(Path(tmp.name) / "t.db")
        self.addCleanup(self.db.close)
        self.db.add_tunnel(wg("nl01", 1, ["198.51.100.7"]))

    def test_a_proxy_round_trips(self):
        self.db.add_tunnel(px("res-de1", 7, host="gate.example.net", port=7000))
        t = self.db.tunnel("res-de1")
        self.assertIs(t.kind, TunnelKind.PROXY)
        self.assertEqual(t.via, "nl01")
        self.assertEqual(t.proxy, {"type": "socks5", "host": "gate.example.net",
                                   "port": 7000})
        self.assertEqual(t.iface, "px-res-de1")

    def test_a_proxy_cannot_be_unchained(self):
        self.db.add_tunnel(px("res-de1", 7))
        with self.assertRaises(ValidationError) as caught:
            self.db.validate_via("res-de1", "")
        self.assertIn("real address", str(caught.exception))

    def test_a_proxy_can_move_to_another_entry(self):
        self.db.add_tunnel(wg("se02", 2, ["198.51.100.8"]))
        self.db.add_tunnel(px("res-de1", 7))
        self.db.validate_via("res-de1", "se02")      # no exception

    def test_nothing_rides_a_proxy(self):
        self.db.add_tunnel(px("res-de1", 7))
        self.db.add_tunnel(wg("ch01", 3, ["192.0.2.88"]))
        with self.assertRaises(ValidationError):
            self.db.validate_via("ch01", "res-de1")

    def test_the_entry_must_leave_over_the_uplink(self):
        self.db.add_tunnel(wg("ch01", 3, ["192.0.2.88"], via="nl01"))
        self.db.add_tunnel(px("res-de1", 7))
        with self.assertRaises(ValidationError) as caught:
            self.db.validate_via("res-de1", "ch01")
        self.assertIn("chained", str(caught.exception))

    def test_the_entry_must_be_enabled(self):
        self.db.add_tunnel(wg("off01", 4, ["198.51.100.9"], enabled=False))
        self.db.add_tunnel(px("res-de1", 7))
        with self.assertRaises(ValidationError) as caught:
            self.db.validate_via("res-de1", "off01")
        self.assertIn("switched off", str(caught.exception))

    def test_proxies_cannot_join_a_pool(self):
        from vpngw.models import Pool
        self.db.add_tunnel(px("res-de1", 7))
        self.db.add_pool(Pool(slug="eu", name="EU", esid=1000))
        with self.assertRaises(ValidationError) as caught:
            self.db.set_pool_members("eu", [PoolMember("res-de1", 10)])
        self.assertIn("UDP", str(caught.exception))


class TheHostRuleset(unittest.TestCase):
    """The proxy rules on the gateway, rendered.

    The promise is unchanged: no client packet reaches the internet except
    through a tunnel. These tests are about the four ways a proxy egress
    could have quietly broken it - a new path to the uplink, a new hole in
    the gateway's own egress, a relay reaching past its server, and UDP
    finding a way around the proxy.
    """

    def setUp(self):
        from vpngw.models import Client, EgressKind
        self.nl = wg("nl01", 1, ["198.51.100.7"])
        self.px = px("res-de1", 7)
        self.px.endpoints = ["203.0.113.50"]
        self.clients = [Client(name="pc5", ip="10.10.0.5",
                               egress_kind=EgressKind.TUNNEL,
                               egress_slug="res-de1")]

    def render(self, tunnels=None, clients=None):
        from vpngw.render import nftables
        return nftables.render(config.Settings(),
                               tunnels if tunnels is not None else [self.nl, self.px],
                               [], clients if clients is not None else self.clients)

    @staticmethod
    def chain(text, name):
        body = text[text.index(f"chain {name} {{"):]
        return body[:body.index("\n    }\n")]

    @staticmethod
    def elements(text, decl):
        block = text[text.index(decl):]
        block = block[:block.index("}")]
        return block.split("elements = {", 1)[1] if "elements = {" in block else ""

    def test_the_rules_sit_where_the_kill_switch_needs_them(self):
        fwd = self.chain(self.render(), "forward")
        wan = fwd.index('"wan_leak_drop"')
        nontcp = fwd.index('"proxy_nontcp_drop"')
        accept = fwd.index('"forwarded_new"')
        self.assertLess(wan, nontcp, "the uplink drop must come first")
        self.assertLess(nontcp, accept,
                        "UDP must be refused before client flows are accepted")

    def test_the_gateways_own_egress_is_unchanged(self):
        """No new host egress: a proxy's bytes are forwarded, never output."""
        with_proxy = self.chain(self.render(), "output")
        without = self.chain(self.render([self.nl], []), "output")
        self.assertEqual(with_proxy, without)

    def test_the_proxy_server_is_never_dialable_over_the_uplink(self):
        from vpngw.render.nftables import wan_endpoints
        self.assertNotIn("203.0.113.50", self.elements(self.render(), "set vpn_endpoints"))
        self.assertNotIn("203.0.113.50", wan_endpoints([self.nl, self.px]))

    def test_the_proxy_is_both_a_tunnel_and_a_proxy_interface(self):
        text = self.render()
        self.assertIn('"px-res-de1"', self.elements(text, "set tun_ifaces"))
        self.assertIn('"px-res-de1"', self.elements(text, "set proxy_ifaces"))
        self.assertNotIn('"wg-nl01"', self.elements(text, "set proxy_ifaces"))

    def test_the_relay_is_steered_into_its_entry(self):
        self.assertIn('"px-res-de1" : 0x0001', self.elements(self.render(), "map px_entry"))

    def test_the_relay_may_reach_one_server(self):
        self.assertEqual(self.elements(self.render(), "set px_upstream").strip(" }\n"),
                         '"px-res-de1" . 203.0.113.50 . 1080')

    def test_an_unresolved_server_means_no_way_out(self):
        self.px.endpoints = []
        self.assertEqual(self.elements(self.render(), "set px_upstream"), "")

    def test_a_proxy_without_its_entry_is_left_out(self):
        text = self.render([self.px])
        self.assertEqual(self.elements(text, "set proxy_ifaces"), "")
        self.assertEqual(self.elements(text, "set px_upstream"), "")

    def test_a_disabled_proxy_is_left_out(self):
        self.px.enabled = False
        self.assertEqual(self.elements(self.render(), "set proxy_ifaces"), "")

    def test_only_connections_the_namespace_starts_are_reclassified(self):
        """Replies to clients share the interface; re-marking them would
        overwrite the client flow's conntrack mark, which failover needs."""
        mangle = " ".join(self.chain(self.render(), "mangle_prerouting").split())
        self.assertIn("iifname @proxy_ifaces ct direction original "
                      + chr(92) + " meta mark set iifname map @px_entry", mangle)
        self.assertLess(mangle.index("@px_entry"),
                        mangle.index("iifname != @client_ifaces return"))

    def test_a_moved_server_rebuilds_the_ruleset(self):
        from types import SimpleNamespace
        from vpngw.reconciler import Reconciler
        fake = SimpleNamespace(settings=config.Settings(),
                               maintenance_active=lambda: False)
        before = Reconciler._fingerprint(fake, [self.nl, self.px], [], [])
        self.px.endpoints = ["203.0.113.51"]
        after = Reconciler._fingerprint(fake, [self.nl, self.px], [], [])
        self.assertNotEqual(before, after)


if __name__ == "__main__":
    unittest.main()
