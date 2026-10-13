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


if __name__ == "__main__":
    unittest.main()
