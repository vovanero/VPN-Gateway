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


class TheNamespace(unittest.TestCase):
    """What runs inside vpngw-px-<slug>, and what it is allowed to do."""

    def setUp(self):
        self.t = px("res-de1", 7, host="gate.example.net", port=7000)
        self.t.endpoints = ["203.0.113.50"]

    def test_the_ruleset_replaces_whatever_was_there(self):
        from vpngw.tunnels.proxy import render_namespace_ruleset
        self.assertTrue(render_namespace_ruleset(self.t).startswith("flush ruleset"))

    def test_there_is_exactly_one_way_out(self):
        from vpngw.tunnels.proxy import render_namespace_ruleset
        text = render_namespace_ruleset(self.t)
        out = text[text.index("chain output {"):]
        out = out[:out.index("}")]
        accepts = [l.strip() for l in out.splitlines() if l.strip().endswith("accept")]
        self.assertEqual(accepts, [
            "oif lo accept",
            "ct state established,related accept",
            'oifname "px0" ip daddr 203.0.113.50 tcp dport 7000 accept',
        ])
        self.assertIn("policy drop", out)

    def test_nothing_is_forwarded_inside(self):
        from vpngw.tunnels.proxy import render_namespace_ruleset
        text = render_namespace_ruleset(self.t)
        fwd = text[text.index("chain forward {"):]
        fwd = fwd[:fwd.index("}")]
        self.assertEqual([l.strip() for l in fwd.splitlines()[1:] if l.strip()],
                         ["type filter hook forward priority filter; policy drop;"])

    def test_the_relay_is_not_redirected_into_itself(self):
        from vpngw.tunnels.proxy import render_namespace_ruleset
        text = render_namespace_ruleset(self.t)
        nat = text[text.index("chain out_nat {"):]
        self.assertLess(nat.index("ip daddr 203.0.113.50 tcp dport 7000 return"),
                        nat.index("redirect to :"))

    def test_redsocks_speaks_the_right_protocol(self):
        from vpngw.tunnels.proxy import render_redsocks
        self.assertIn("type = socks5;", render_redsocks(self.t, "", ""))
        self.t.proxy["type"] = "http"
        self.assertIn("type = http-connect;", render_redsocks(self.t, "", ""))

    def test_redsocks_keeps_no_list_of_destinations(self):
        from vpngw.tunnels.proxy import render_redsocks
        conf = render_redsocks(self.t, "", "")
        self.assertIn("log_info = off;", conf)
        self.assertIn("log_debug = off;", conf)

    def test_no_login_lines_without_a_login(self):
        from vpngw.tunnels.proxy import render_redsocks
        conf = render_redsocks(self.t, "", "")
        self.assertNotIn("login", conf)
        self.assertNotIn("password", conf)

    def test_a_login_is_quoted(self):
        from vpngw.tunnels.proxy import render_redsocks
        conf = render_redsocks(self.t, "customer-7f3a", "p4ss-w0rd")
        self.assertIn('login = "customer-7f3a";', conf)
        self.assertIn('password = "p4ss-w0rd";', conf)


class TheCredentials(unittest.TestCase):
    """redsocks has no escaping, so the characters that could break out of a
    quoted string are refused - and the refusal never repeats the value."""

    def test_characters_that_could_inject_a_directive_are_refused(self):
        from vpngw.tunnels.proxy import validate_credentials
        for bad in ('pa"ss', "pa" + chr(92) + "ss", "pa;ss", "pa ss",
                    "pa" + chr(10) + "ss", "pa" + chr(96) + "ss"):
            with self.subTest(bad=bad), self.assertRaises(ValidationError) as caught:
                validate_credentials("user", bad)
            self.assertNotIn(bad, str(caught.exception))

    def test_both_or_neither(self):
        from vpngw.tunnels.proxy import validate_credentials
        for user, pw in (("user", ""), ("", "pass")):
            with self.subTest(user=user), self.assertRaises(ValidationError):
                validate_credentials(user, pw)
        validate_credentials("", "")                 # no auth is fine

    def test_typical_residential_logins_pass(self):
        from vpngw.tunnels.proxy import validate_credentials
        validate_credentials("customer-7f3a_session-91.country-de", "Ab9#x!Qz@2")

    def test_they_round_trip_through_the_secrets_file(self):
        from vpngw.tunnels import proxy
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        saved = config.SECRETS_DIR
        config.SECRETS_DIR = Path(tmp.name)
        self.addCleanup(setattr, config, "SECRETS_DIR", saved)
        proxy.write_credentials("res-de1", "u1", "p1-secret")
        self.assertEqual(proxy.read_credentials("res-de1"), ("u1", "p1-secret"))
        if sys.platform != "win32":
            mode = proxy.credentials_path("res-de1").stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
        proxy.write_credentials("res-de1", "", "")   # clearing removes the file
        self.assertFalse(proxy.credentials_path("res-de1").exists())


class ThePxdnsForwarder(unittest.TestCase):
    """UDP DNS in, TCP out, never a second path."""

    QUERY = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")

    def test_udp_limit_without_edns_is_512(self):
        from vpngw.pxdns import udp_limit
        self.assertEqual(udp_limit(self.QUERY), 512)

    def test_udp_limit_reads_the_opt_record(self):
        from vpngw.pxdns import udp_limit
        q = bytearray(self.QUERY)
        q[10:12] = (1).to_bytes(2, "big")                  # ARCOUNT = 1
        q += bytes.fromhex("00" "0029" "1000" "00000000" "0000")  # OPT, 4096
        self.assertEqual(udp_limit(bytes(q)), 4096)

    def test_truncation_sets_tc_and_keeps_the_question(self):
        from vpngw.pxdns import question_end, truncated
        reply = bytearray(self.QUERY)
        reply[2] |= 0x80                                   # QR
        reply[6:8] = (1).to_bytes(2, "big")                # one answer
        reply += b"\xc0\x0c" + bytes(10) + b"x" * 600
        out = truncated(bytes(reply))
        self.assertTrue(out[2] & 0x02, "TC not set")
        self.assertEqual(out[6:12], bytes(6), "counts other than the question")
        self.assertEqual(out[12:], bytes(reply[12:question_end(bytes(reply))]))

    def test_it_asks_over_tcp_with_length_framing(self):
        import socket
        import socketserver
        import struct
        import threading
        from vpngw import pxdns

        class Answer(socketserver.BaseRequestHandler):
            def handle(self):
                n = struct.unpack("!H", self.request.recv(2))[0]
                q = self.request.recv(n)
                r = bytearray(q)
                r[2] |= 0x80
                self.request.sendall(struct.pack("!H", len(r)) + r)

        srv = socketserver.TCPServer(("127.0.0.1", 0), Answer)
        self.addCleanup(srv.server_close)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        real = socket.create_connection
        port = srv.server_address[1]
        self.addCleanup(setattr, socket, "create_connection", real)
        socket.create_connection = lambda addr, timeout=None: real(("127.0.0.1", port), timeout)
        reply = pxdns.ask_tcp("192.0.2.53", self.QUERY)
        self.assertEqual(reply[:2], self.QUERY[:2])
        self.assertTrue(reply[2] & 0x80)


class TheDriver(unittest.TestCase):

    def test_an_unresolved_server_is_refused_before_anything_runs(self):
        from vpngw.tunnels import proxy
        calls = []
        self.addCleanup(setattr, proxy, "run", proxy.run)
        proxy.run = lambda argv, **kw: calls.append(argv)
        t = px("res-de1", 7)
        with self.assertRaises(RuntimeError) as caught:
            proxy.ProxyDriver().up(t)
        self.assertEqual(calls, [])
        self.assertIn("nl01", str(caught.exception))

    def test_the_next_hop_is_the_namespace_end(self):
        from vpngw.tunnels import proxy
        from vpngw.tunnels.base import LinkInfo
        self.addCleanup(setattr, proxy, "link_state", proxy.link_state)
        proxy.link_state = lambda iface: LinkInfo(exists=True, up=True)
        info = proxy.ProxyDriver().state(px("res-de1", 7))
        self.assertEqual(info.gateway, config.proxy_link(7)[1])

    def test_driver_for_knows_the_kind(self):
        from vpngw.tunnels import driver_for
        from vpngw.tunnels.proxy import ProxyDriver
        self.assertIsInstance(driver_for(px("res-de1", 7)), ProxyDriver)


class TheUnits(unittest.TestCase):

    ROOT = Path(__file__).resolve().parent.parent

    def unit(self, name):
        return (self.ROOT / "systemd" / name).read_text(encoding="utf-8")

    def test_the_relay_is_jailed_and_unprivileged(self):
        u = self.unit("vpngw-proxy@.service")
        for line in ("NetworkNamespacePath=/run/netns/vpngw-px-%i",
                     "DynamicUser=yes", "CapabilityBoundingSet=",
                     "NoNewPrivileges=yes"):
            self.assertIn(line + "\n", u)

    def test_the_login_never_reaches_a_command_line(self):
        u = self.unit("vpngw-proxy@.service")
        self.assertIn("LoadCredential=redsocks.conf:", u)
        exec_line = next(l for l in u.splitlines() if l.startswith("ExecStart="))
        self.assertIn("%d/redsocks.conf", exec_line)
        self.assertNotIn("password", exec_line.lower())

    def test_neither_unit_starts_by_itself(self):
        for name in ("vpngw-proxy@.service", "vpngw-pxdns@.service"):
            with self.subTest(name=name):
                self.assertNotIn("[Install]", self.unit(name))

    def test_the_installer_treats_redsocks_as_optional(self):
        import re
        script = (self.ROOT / "install.sh").read_text(encoding="utf-8")
        required = re.search(r"^PKGS=\((.*?)^\)", script, re.M | re.S).group(1)
        self.assertNotIn("redsocks", required.split(),
                         "a required redsocks would fail every update of an "
                         "armed gateway that lacks it")
        self.assertIn("OPTIONAL_PKGS=(redsocks)", script)
        self.assertIn("systemctl mask redsocks.service", script)
        for unit in ("vpngw-proxy@.service", "vpngw-pxdns@.service"):
            self.assertIn(unit, script)

    def test_updates_fetch_packages_through_the_tunnel(self):
        script = (self.ROOT / "scripts/update.sh").read_text(encoding="utf-8")
        self.assertIn('VPNGW_FETCH_IFACE="$TUN_IFACE"', script)


if __name__ == "__main__":
    unittest.main()
