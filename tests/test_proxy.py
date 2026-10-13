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

    def test_the_resolver_comes_back_with_the_relay(self):
        """BindsTo stops pxdns with the relay; nothing started it again when
        Restart= brought the relay back. Found live: relay up, DNS dead."""
        self.assertIn("BindsTo=vpngw-proxy@%i.service\n", self.unit("vpngw-pxdns@.service"))
        self.assertIn("Upholds=vpngw-pxdns@%i.service\n", self.unit("vpngw-proxy@.service"))

    def test_a_dead_resolver_makes_the_proxy_unhealthy(self):
        """The probe asks for an address, so only the hint can see it."""
        from vpngw.tunnels import proxy
        self.addCleanup(setattr, proxy, "try_run", proxy.try_run)
        self.addCleanup(setattr, proxy, "link_exists", proxy.link_exists)
        proxy.link_exists = lambda iface: True
        proxy.try_run = lambda argv, **kw: type("R", (), {"ok": "vpngw-pxdns@" not in argv[-1]})()
        verdict, reason = proxy.ProxyDriver().healthy_hint(px("res-de1", 7))
        self.assertIs(verdict, False)
        self.assertIn("resolver", reason)

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


class TheHealthProbe(unittest.TestCase):
    """ICMP does not cross a proxy, so its health is an HTTP request through
    the relay - measured at the driver's cadence, never more often."""

    def setUp(self):
        from vpngw.health import HealthMonitor
        from vpngw.tunnels import proxy
        self.mon = HealthMonitor(config.HealthSettings())
        self.t = px("res-de1", 7)
        self.calls = []
        self.reply = (True, 612.0, "203.0.113.50", "")

        def fake_probe(_self, t):
            self.calls.append(t.slug)
            return self.reply

        self.addCleanup(setattr, proxy.ProxyDriver, "probe", proxy.ProxyDriver.probe)
        self.addCleanup(setattr, proxy.ProxyDriver, "healthy_hint",
                        proxy.ProxyDriver.healthy_hint)
        proxy.ProxyDriver.probe = fake_probe
        proxy.ProxyDriver.healthy_hint = lambda _self, t: (None, "")

    def test_the_probe_reports_the_exit_and_the_latency(self):
        h = self.mon.probe(self.t)
        self.assertEqual(h.exit_ip, "203.0.113.50")
        self.assertEqual(h.rtt_ms, 612.0)

    def test_it_comes_up_without_waiting_for_the_slow_cadence(self):
        from vpngw.models import HealthState
        for _ in range(self.mon.s.rise_threshold):
            h = self.mon.probe(self.t)
        self.assertIs(h.state, HealthState.UP)
        self.assertEqual(len(self.calls), self.mon.s.rise_threshold)

    def test_once_up_it_is_not_re_measured_every_pass(self):
        """Every probe is billed bytes through a residential proxy."""
        for _ in range(self.mon.s.rise_threshold):
            self.mon.probe(self.t)
        before = len(self.calls)
        for _ in range(5):
            self.mon.probe(self.t)
        self.assertEqual(len(self.calls), before)

    def test_a_dead_relay_is_noticed_between_measurements(self):
        """The hint runs every pass, so the slow cadence never hides a crash."""
        from vpngw.models import HealthState
        from vpngw.tunnels import proxy
        for _ in range(self.mon.s.rise_threshold):
            self.mon.probe(self.t)
        proxy.ProxyDriver.healthy_hint = lambda _self, t: (False, "relay not running")
        for _ in range(self.mon.s.fail_threshold):
            h = self.mon.probe(self.t)
        self.assertIs(h.state, HealthState.DOWN)

    def test_the_exit_is_not_fetched_a_second_way(self):
        from vpngw import health
        called = []
        self.addCleanup(setattr, health, "exit_ip_via", health.exit_ip_via)
        health.exit_ip_via = lambda *a, **k: called.append(a)
        for _ in range(self.mon.s.rise_threshold):
            self.mon.probe(self.t)
        self.mon.refresh_exit_ip(self.t)
        self.assertEqual(called, [])

    def test_a_state_on_its_way_to_changing_is_measured_every_pass(self):
        """A proxy whose login was just fixed must not sit at "down" for
        rise_threshold slow intervals after its first good probe."""
        from vpngw.models import HealthState
        self.reply = (False, None, None, "The proxy rejected the username or password.")
        for _ in range(self.mon.s.fail_threshold):
            h = self.mon.probe(self.t)
        self.assertIs(h.state, HealthState.DOWN)
        before = len(self.calls)
        for _ in range(3):
            self.mon.probe(self.t)
        self.assertEqual(len(self.calls), before, "a settled DOWN is rate-limited")
        # The login is fixed; rebuilding the relay clears last_sample.
        self.reply = (True, 480.0, "198.51.100.77", "")
        h.last_sample = 0.0
        for _ in range(self.mon.s.rise_threshold):
            h = self.mon.probe(self.t)
        self.assertIs(h.state, HealthState.UP)
        self.assertEqual(len(self.calls), before + self.mon.s.rise_threshold)

    def test_a_failure_while_up_is_followed_up_at_once(self):
        from vpngw.models import HealthState
        for _ in range(self.mon.s.rise_threshold):
            h = self.mon.probe(self.t)
        self.reply = (False, None, None, "The proxy relay stopped.")
        h.last_sample = 0.0                      # its interval has passed
        for _ in range(self.mon.s.fail_threshold):
            h = self.mon.probe(self.t)
        self.assertIs(h.state, HealthState.DOWN)

class TheReconciler(unittest.TestCase):

    def test_a_proxy_gets_no_outer_rule(self):
        """Its relay's traffic is steered by px_entry into the entry's own
        rule; an outer rule would also take the single priority-850 slot."""
        from types import SimpleNamespace
        from vpngw import reconciler
        from vpngw.models import Egress
        seen = {}
        self.addCleanup(setattr, reconciler.routing, "sync_rules",
                        reconciler.routing.sync_rules)
        self.addCleanup(setattr, reconciler.routing, "ensure_blackhole",
                        reconciler.routing.ensure_blackhole)
        reconciler.routing.sync_rules = lambda rules: seen.setdefault("rules", rules)
        reconciler.routing.ensure_blackhole = lambda table: None
        nl, p = wg("nl01", 1, ["198.51.100.7"]), px("res-de1", 7)
        fake = SimpleNamespace(settings=config.Settings())
        reconciler.Reconciler._step_routes(fake, [Egress.of(nl), Egress.of(p)], [nl, p])
        priorities = {int(r[r.index("priority") + 1]) for r in seen["rules"]}
        self.assertNotIn(config.RULE_PRIO_OUTER, priorities)
        # ...while an ordinary chained tunnel still gets one, so this is not
        # passing merely because nothing ever produces an outer rule.
        seen.clear()
        rider = wg("ch01", 3, ["192.0.2.88"], via="nl01")
        reconciler.Reconciler._step_routes(fake, [Egress.of(nl), Egress.of(rider)],
                                           [nl, rider])
        priorities = {int(r[r.index("priority") + 1]) for r in seen["rules"]}
        self.assertIn(config.RULE_PRIO_OUTER, priorities)

    def test_orphaned_namespaces_are_cleared_with_their_units(self):
        from vpngw import reconciler
        stopped = []
        self.addCleanup(setattr, reconciler.os, "listdir", reconciler.os.listdir)
        self.addCleanup(setattr, reconciler, "try_run", reconciler.try_run)
        reconciler.os.listdir = lambda path: ["vpngw-px-old01", "vpngw-px-res-de1",
                                              "vpngw-test", "unrelated"]
        from vpngw.tunnels import proxy
        self.addCleanup(setattr, proxy, "try_run", proxy.try_run)
        reconciler.try_run = lambda argv, **kw: stopped.append(argv)
        proxy.try_run = lambda argv, **kw: stopped.append(argv)
        reconciler.Reconciler._remove_orphan_namespaces({"vpngw-px-res-de1"})
        flat = [" ".join(a) for a in stopped]
        self.assertTrue(any("vpngw-proxy@old01.service" in a for a in flat))
        # In the host's mount namespace - see HOST_MOUNTS - or the mount the
        # daemon cannot see is the one left behind.
        self.assertIn("nsenter --mount=/proc/1/ns/mnt -- ip netns del vpngw-px-old01", flat)
        self.assertFalse(any("res-de1" in a for a in flat), "removed a live proxy")
        self.assertFalse(any("vpngw-test" in a for a in flat),
                         "removed the self-test's namespace")

    def test_no_chain_mtu_is_forced_onto_a_veth(self):
        src = (Path(__file__).resolve().parent.parent
               / "vpngw/reconciler.py").read_text(encoding="utf-8")
        self.assertIn("if t.via and not t.mtu and t.kind is not TunnelKind.PROXY:", src)

    def test_the_updater_never_fetches_through_a_proxy(self):
        src = (Path(__file__).resolve().parent.parent
               / "scripts/update.sh").read_text(encoding="utf-8")
        self.assertIn('if t.kind.value == "proxy":', src)


class TheDiagnosis(unittest.TestCase):
    """proxycheck tells the steps apart, against real sockets.

    "It doesn't work" is not something an operator can fix; "the proxy
    rejected the username or password" is. Each stage is driven here by a
    small fake server speaking just enough of the protocol.
    """

    def serve(self, handler):
        import socketserver
        import threading
        srv = socketserver.TCPServer(("127.0.0.1", 0), handler)
        self.addCleanup(srv.server_close)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def check(self, kind, port, username="u1", password="p1"):
        from vpngw import proxycheck
        return proxycheck.check({"type": kind, "server": "127.0.0.1", "port": port,
                                 "username": username, "password": password})

    def socks(self, auth_ok=True, rep=0):
        import socketserver

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                r = self.request
                r.recv(3)                                # greeting
                r.sendall(bytes([5, 2]))                 # user/pass, please
                head = r.recv(2)
                user = r.recv(head[1]); plen = r.recv(1)[0]; r.recv(plen)
                r.sendall(bytes([1, 0 if auth_ok else 1]))
                if not auth_ok:
                    return
                r.recv(10)                               # CONNECT, IPv4
                r.sendall(bytes([5, rep, 0, 1]) + bytes(6))
        return self.serve(H)

    def http(self, code):
        import socketserver

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(4096)
                self.request.sendall(f"HTTP/1.1 {code} X\r\n\r\n".encode())
        return self.serve(H)

    def test_socks5_that_works(self):
        self.assertEqual(self.check("socks5", self.socks())["stage"], "ok")

    def test_socks5_login_rejected(self):
        r = self.check("socks5", self.socks(auth_ok=False))
        self.assertEqual((r["stage"], r["ok"]), ("auth", False))

    def test_socks5_refusing_to_connect_onward(self):
        r = self.check("socks5", self.socks(rep=2))
        self.assertEqual(r["stage"], "tunnel")
        self.assertIn("not allowed", r["detail"])

    def test_http_proxy_stages(self):
        for code, stage in ((200, "ok"), (407, "auth"), (403, "tunnel")):
            with self.subTest(code=code):
                self.assertEqual(self.check("http", self.http(code))["stage"], stage)

    def test_nothing_listening_is_a_connect_failure(self):
        import socket
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
        s.close()                                        # a port nobody holds
        self.assertEqual(self.check("socks5", port)["stage"], "connect")

    def test_the_messages_never_carry_the_login(self):
        from vpngw.tunnels.proxy import ProxyDriver
        t = px("res-de1", 7, host="gate.example.net", port=7000)
        for stage in ("resolve", "connect", "auth", "tunnel", "ok", "relay"):
            msg = ProxyDriver().explain(t, {"stage": stage, "detail": "x"})
            self.assertNotIn("p1-secret", msg)
            self.assertTrue(msg.endswith("."), msg)


class TheCommandLine(unittest.TestCase):

    def test_a_proxy_url_becomes_fields(self):
        from vpngw.cli import parse_proxy_url
        self.assertEqual(parse_proxy_url("socks5://customer-7f3a@gate.example.net:7000"),
                         {"type": "socks5", "host": "gate.example.net",
                          "port": 7000, "username": "customer-7f3a"})
        self.assertEqual(parse_proxy_url("http://u%40x@198.51.100.9:8080")["username"],
                         "u@x")

    def test_a_password_on_the_command_line_is_refused(self):
        from vpngw.cli import parse_proxy_url
        with self.assertRaises(SystemExit) as caught:
            parse_proxy_url("socks5://user:hunter2@gate.example.net:7000")
        self.assertNotIn("hunter2", str(caught.exception))

    def test_unsupported_urls_are_refused(self):
        from vpngw.cli import parse_proxy_url
        for url in ("https://u@h:1", "socks4://h:1", "socks5://h", "h:1080"):
            with self.subTest(url=url), self.assertRaises(SystemExit):
                parse_proxy_url(url)


class TheApi(unittest.TestCase):
    """api.py imports FastAPI, which a development machine need not have, so
    the invariants that matter are checked in its source."""

    ROOT = Path(__file__).resolve().parent.parent

    def src(self, rel):
        return (self.ROOT / rel).read_text(encoding="utf-8")

    def test_deleting_a_tunnel_removes_its_login_too(self):
        self.assertIn(".proxy", config.SECRET_SUFFIXES)
        for rel in ("vpngw/api.py", "vpngw/cli.py"):
            with self.subTest(rel=rel):
                self.assertIn("for suffix in config.SECRET_SUFFIXES:", self.src(rel))
                self.assertNotIn('(".json", ".ovpn", ".auth")', self.src(rel))

    def test_a_new_proxy_is_validated_before_it_is_enabled(self):
        api = self.src("vpngw/api.py")
        body = api[api.index("def add_proxy("):api.index("def test_tunnel(")]
        order = [body.index(step) for step in (
            "db.add_tunnel(t)", "db.validate_via(t.slug, t.via)",
            "proxy_mod.write_credentials(", "t.enabled = True")]
        self.assertEqual(order, sorted(order))
        self.assertIn("enabled=False", body)

    def test_the_server_name_is_looked_up_through_the_entry(self):
        api = self.src("vpngw/api.py")
        body = api[api.index("def _resolve_proxy("):api.index("def add_proxy(")]
        self.assertIn("via_resolver=", body)
        self.assertNotIn("getaddrinfo", body)

    def test_no_endpoint_returns_the_password(self):
        api = self.src("vpngw/api.py")
        for fn in ("def add_proxy(", "def test_tunnel("):
            start = api.index(fn)
            body = api[start:api.index("\n    @app.", start)]
            for ret in [l for l in body.splitlines() if "return {" in l or '"password"' in l]:
                self.assertNotIn('"password":', ret, f"{fn} returns a password")



class TheNamespaceIsMadeWhereEveryoneCanSeeIt(unittest.TestCase):
    """Found on the reference gateway: created from the sandboxed daemon, the
    namespace's mount stayed in the daemon's private mount namespace, and the
    relay units failed with "Failed to open network namespace path ...
    Invalid argument". It must be made, and removed, in the host's."""

    def setUp(self):
        from vpngw.tunnels import proxy
        self.proxy = proxy
        self.calls = []
        for name in ("run", "try_run"):
            self.addCleanup(setattr, proxy, name, getattr(proxy, name))
            setattr(proxy, name, lambda argv, **kw: self.calls.append(argv))
        self.addCleanup(setattr, proxy.ProxyDriver, "_netns_ready",
                        proxy.ProxyDriver._netns_ready)

    def test_it_is_added_in_the_host_mount_namespace(self):
        self.proxy.ProxyDriver._netns_ready = staticmethod(lambda name: False)
        self.proxy.ProxyDriver()._netns_add("vpngw-px-res-de1")
        self.assertIn(self.proxy.HOST_MOUNTS + ["ip", "netns", "add", "vpngw-px-res-de1"],
                      self.calls)

    def test_a_ready_namespace_is_left_alone(self):
        self.proxy.ProxyDriver._netns_ready = staticmethod(lambda name: True)
        self.proxy.ProxyDriver()._netns_add("vpngw-px-res-de1")
        self.assertEqual(self.calls, [])

    def test_removal_is_in_the_host_mount_namespace_too(self):
        self.proxy.netns_del("vpngw-px-res-de1")
        self.assertTrue(all(c[:len(self.proxy.HOST_MOUNTS)] == self.proxy.HOST_MOUNTS
                            for c in self.calls))


class TheLoginProblems(unittest.TestCase):
    """"Wrong password" and "wants a password" and "takes no password" are
    three different fixes, so they are three different messages."""

    def serve(self, reply):
        import socketserver
        import threading

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(4096)
                self.request.sendall(reply)
        srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        self.addCleanup(srv.server_close)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def check(self, kind, port, username):
        from vpngw import proxycheck
        return proxycheck.check({"type": kind, "server": "127.0.0.1", "port": port,
                                 "username": username,
                                 "password": "p1-secret" if username else ""})

    def test_socks5_refusing_every_offered_method(self):
        refuse = bytes([5, 0xFF])
        self.assertEqual(self.check("socks5", self.serve(refuse), "")["detail"],
                         "needs a login")
        self.assertEqual(self.check("socks5", self.serve(refuse), "u1")["detail"],
                         "refuses a username and password")

    def test_http_407(self):
        reply = b"HTTP/1.1 407 Proxy Authentication Required" + bytes([13, 10, 13, 10])
        self.assertEqual(self.check("http", self.serve(reply), "")["detail"], "needs a login")
        self.assertEqual(self.check("http", self.serve(reply), "u1")["detail"], "login rejected")

    def test_each_says_its_own_fix(self):
        from vpngw.tunnels.proxy import ProxyDriver
        t = px("res-de1", 7)
        say = lambda detail: ProxyDriver().explain(t, {"stage": "auth", "detail": detail})
        self.assertIn("none is set", say("needs a login"))
        self.assertIn("admit callers by address", say("refuses a username and password"))
        self.assertEqual(say("login rejected"), "The proxy rejected the username or password.")


class TheStatusRow(unittest.TestCase):

    def test_it_names_the_failed_step_and_never_the_password(self):
        import json
        import time
        from vpngw import service
        from vpngw.tunnels import proxy
        self.addCleanup(setattr, proxy, "read_credentials", proxy.read_credentials)
        proxy.read_credentials = lambda slug: ("u1", "p1-secret")
        self.addCleanup(proxy._diagnoses.pop, "res-de1", None)
        proxy._diagnoses["res-de1"] = (time.time(), {"stage": "auth", "ok": False})
        row = service._proxy_row(px("res-de1", 7))
        self.assertEqual(row["proxy_stage"], "auth")
        self.assertTrue(row["has_password"])
        self.assertNotIn("p1-secret", json.dumps(row))


class AfterAChange(unittest.TestCase):
    """A relay rebuilt with a new login, address or entry is measured at once,
    so the state shown beside a passed test agrees with it."""

    ROOT = Path(__file__).resolve().parent.parent

    def src(self, rel):
        return (self.ROOT / rel).read_text(encoding="utf-8")

    def test_a_rebuilt_relay_is_measured_on_the_same_pass(self):
        src = self.src("vpngw/reconciler.py")
        body = src[src.index("if t.slug in self._reapply:"):]
        body = body[:body.index("if not ifaces.exists(t.iface):")]
        self.assertIn("last_sample = 0.0", body)

    def test_a_passed_test_is_followed_by_a_measurement(self):
        api = self.src("vpngw/api.py")
        body = api[api.index("def test_tunnel("):api.index("def delete_tunnel(")]
        self.assertLess(body.index("last_sample = 0.0"), body.index('"stage": "ok"'))
        self.assertIn("service.request_reconcile()", body)

    def test_a_new_entry_means_a_new_lookup(self):
        """The old entry's answer was for where that tunnel exits."""
        api = self.src("vpngw/api.py")
        body = api[api.index("def patch_tunnel("):api.index("def _resolve_proxy(")]
        self.assertIn('("host" in proxy_fields or moved)', body)

class ThePanel(unittest.TestCase):
    """The panel's half of proxy egress. Where a check needs JavaScript to
    run, node runs it, and the check is skipped on a machine without one."""

    ROOT = Path(__file__).resolve().parent.parent

    def js(self):
        return (self.ROOT / "vpngw/web/static/app.js").read_text(encoding="utf-8")

    def html(self):
        return (self.ROOT / "vpngw/web/templates/index.html").read_text(encoding="utf-8")

    def fn(self, name):
        src = self.js()
        start = src.index(f"function {name}(")
        return src[start:src.index("\n}\n", start) + 2]

    def node(self, script):
        import subprocess
        res = subprocess.run(["node", "-e", script], capture_output=True,
                             text=True, encoding="utf-8")
        self.assertEqual(res.returncode, 0, res.stderr)
        return res.stdout

    @unittest.skipUnless(__import__("shutil").which("node"), "node is not installed")
    def test_it_parses(self):
        """A syntax error anywhere blanks the whole panel, with no message
        anywhere an operator would look."""
        import subprocess
        res = subprocess.run(["node", "--check", str(self.ROOT / "vpngw/web/static/app.js")],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)

    @unittest.skipUnless(__import__("shutil").which("node"), "node is not installed")
    def test_a_pasted_address_becomes_fields_and_loses_its_password(self):
        import json
        src = self.js()
        start = src.index("const proxyUrlOf =")
        url_of = src[start:src.index(";\n", start) + 2]
        cases = ["socks5://user:pass@gate.example.net:7000",
                 "gate.example.net:7000:user:pa:ss",
                 "http://u%40x:p%3Aw@198.51.100.9:8080",
                 "user:pass@gate.example.net:1080",
                 "gate.example.net:1080",
                 "https://u:p@h.example:443",
                 "socks4://h.example:1080",
                 "gate.example.net",
                 "gate.example.net:99999"]
        got = json.loads(self.node(
            self.fn("parseProxyUrl") + url_of
            + "console.log(JSON.stringify(" + json.dumps(cases) + ".map((c) => {"
            + " const r = parseProxyUrl(c);"
            + " return [r, r && !r.error ? proxyUrlOf({ ...r, type: r.type || 'socks5' }) : null];"
            + " })));"))
        first, shown = got[0]
        self.assertEqual([first[k] for k in ("type", "host", "port", "username", "password")],
                         ["socks5", "gate.example.net", 7000, "user", "pass"])
        self.assertEqual(shown, "socks5://user@gate.example.net:7000")
        self.assertEqual([got[1][0][k] for k in ("type", "host", "port", "username", "password")],
                         [None, "gate.example.net", 7000, "user", "pa:ss"])
        self.assertEqual((got[2][0]["username"], got[2][0]["password"]), ("u@x", "p:w"))
        self.assertEqual((got[3][0]["username"], got[3][0]["password"]), ("user", "pass"))
        self.assertEqual((got[4][0]["host"], got[4][0]["username"]), ("gate.example.net", ""))
        self.assertIn("not supported", got[5][0]["error"])
        self.assertIn("socks5://", got[6][0]["error"])
        self.assertEqual((got[7][0], got[8][0]), (None, None))
        for parsed, shown in got:
            if parsed and not parsed.get("error") and parsed["password"]:
                self.assertNotIn(parsed["password"], shown)

    @unittest.skipUnless(__import__("shutil").which("node"), "node is not installed")
    def test_every_field_pattern_compiles_as_the_browser_compiles_it(self):
        """Chrome compiles pattern="" with the v flag. There a bare "-" in a
        character class is a syntax error, the pattern is dropped without a
        word, and the field validates nothing."""
        import json
        import re
        patterns = re.findall(r'pattern="([^"]+)"', self.html())
        self.assertGreaterEqual(len(patterns), 3)
        self.node("for (const p of " + json.dumps(patterns) + ")"
                  " new RegExp('^(?:' + p + ')$', 'v'); console.log('ok')")

    def test_no_login_goes_into_a_url(self):
        """A query string ends up in history and in logs; a login never
        belongs in one."""
        import re
        js = self.js()
        for block in re.findall(r"new URLSearchParams[(][{](.*?)[}][)]", js, re.S):
            self.assertNotRegex(block, r"(?i)pass|auth", block)
        start = js.index('$("#formTunnel").addEventListener("submit"')
        handler = js[start:js.index("\n});\n", start)]
        self.assertIn('body.append("auth_pass"', handler)

    def test_the_import_reads_the_login_from_the_body(self):
        api = (self.ROOT / "vpngw/api.py").read_text(encoding="utf-8")
        start = api.index("async def import_tunnel(")
        sig = api[start:api.index(") -> dict:", start)]
        self.assertIn('auth_user: str = Form("")', sig)
        self.assertIn('auth_pass: str = Form("")', sig)

    def test_a_proxy_that_fails_its_test_is_not_kept(self):
        body = self.fn("addProxy")
        tested = body.index("await testProxy(")
        removed = body.index('"DELETE"')
        shown = body.index("say({ ok: false, message: v.message + tail })")
        self.assertLess(tested, removed)
        self.assertLess(removed, shown)

    def test_a_proxy_is_offered_only_where_it_can_go(self):
        self.assertIn("filter((t) => !isProxy(t))", self.fn("openPoolDialog"))
        self.assertIn("!t.via && !isProxy(t)", self.fn("openTunnelDialog"))
        self.assertIn("const tunnels = s.tunnels.filter((t) => !isProxy(t));",
                      self.fn("openChainDialog"))
        self.assertIn('label: "Proxies"', self.fn("egressOptions"))
        # ...and never with a way to dial it directly.
        self.assertNotIn('value: ""', self.fn("entryOption"))

class TheProxySelfTest(unittest.TestCase):
    """The self-test's proxy checks, fed what tcpdump would print.

    Each scenario is the capture a real fault would produce; the check must
    name it, and an inconclusive capture must warn rather than cry wolf.
    """

    SERVER = "192.0.2.44"

    def run_checks(self, scenario, *, exit_ip="198.51.100.77", entry_exit="43.229.76.126",
                   refused=3, answered=True):
        from types import SimpleNamespace
        from vpngw import leaktest

        t = px("res-de1", 7, via="vpn1", host="gate.example.net", port=7000)
        t.endpoints = [self.SERVER]
        entry = wg("vpn1", 1)
        seen_label = {}

        class FakeWatch:
            def __init__(fw, iface, bpf, needles, *, payload=False, count=2000):
                fw.iface, fw.bpf, fw.needles, fw.payload = iface, bpf, needles, payload
                if payload:
                    seen_label["label"] = needles[0]

            def __enter__(fw):
                return fw

            def __exit__(fw, *exc):
                return None

            def captured(fw):
                lines = scenario(fw.iface, fw.payload, seen_label.get("label", ""))
                return [l for l in lines if any(n in l for n in fw.needles)]

        counters = iter([{"proxy_nontcp_drop": {"packets": 10}},
                         {"proxy_nontcp_drop": {"packets": 10 + refused}}])
        self.addCleanup(setattr, leaktest.nft, "counters", leaktest.nft.counters)
        leaktest.nft.counters = lambda: next(counters)
        self.addCleanup(setattr, leaktest.LeakTest, "_Watch", leaktest.LeakTest._Watch)
        leaktest.LeakTest._Watch = FakeWatch

        test = object.__new__(leaktest.LeakTest)
        test.settings = SimpleNamespace(
            net=SimpleNamespace(wan_iface="eth0"),
            dns=SimpleNamespace(resolver_ip=lambda esid: "10.99.0.9"))
        test.db = SimpleNamespace(tunnel=lambda slug: entry if slug == "vpn1" else t)
        health = SimpleNamespace(get=lambda slug: SimpleNamespace(exit_ip=entry_exit))
        test.service = SimpleNamespace(reconciler=SimpleNamespace(health=health))
        test._reaches_internet = lambda timeout=8: exit_ip
        test._canary = lambda count=5: None
        test._ns = lambda *argv, timeout=20: SimpleNamespace(
            ok=answered, stdout=";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN"
            if answered else "")
        report = leaktest.Report()
        test._check_proxy(report, t, exit_ip)
        return {c.id: c for c in report.checks}

    def clean(self, iface, payload, label):
        if iface == "wg-vpn1":
            return [f"12:00:00.000000 IP 10.64.0.2.40000 > {self.SERVER}.7000: Flags [S], seq 1"]
        if iface == "px-res-de1" and payload:
            return [f"E..<..@.@....{label}.example.com....."]
        return []

    def test_a_sound_proxy_passes_all_four(self):
        checks = self.run_checks(self.clean)
        for cid in ("proxy_exit_not_entry", "proxy_server_via_entry",
                    "proxy_udp_refused", "proxy_dns_through_proxy"):
            with self.subTest(check=cid):
                self.assertTrue(checks[cid].passed, checks[cid].detail)
        self.assertIn("over TCP", checks["proxy_dns_through_proxy"].detail)

    def test_the_proxy_dialled_over_the_uplink_is_critical(self):
        def scenario(iface, payload, label):
            if iface == "eth0":
                return [f"12:00:00.000000 IP 100.200.50.100.40000 > {self.SERVER}.7000: Flags [S]"]
            return self.clean(iface, payload, label)
        c = self.run_checks(scenario)["proxy_server_via_entry"]
        self.assertEqual((c.passed, c.critical), (False, True))
        self.assertIn("LEAKED", c.detail)

    def test_udp_inside_the_entry_is_critical(self):
        def scenario(iface, payload, label):
            extra = (["12:00:00.000000 IP 10.64.0.2.5000 > 203.0.113.9.51999: UDP, length 13"]
                     if iface == "wg-vpn1" else [])
            return self.clean(iface, payload, label) + extra
        c = self.run_checks(scenario)["proxy_udp_refused"]
        self.assertEqual((c.passed, c.critical), (False, True))

    def test_udp_into_the_namespace_is_critical(self):
        def scenario(iface, payload, label):
            extra = (["12:00:00.000000 IP 10.10.0.250.5000 > 203.0.113.9.51999: UDP, length 13"]
                     if iface == "px-res-de1" and not payload else [])
            return self.clean(iface, payload, label) + extra
        c = self.run_checks(scenario)["proxy_udp_refused"]
        self.assertEqual((c.passed, c.critical), (False, True))

    def test_dns_around_the_proxy_is_critical(self):
        def scenario(iface, payload, label):
            extra = ([f"12:00:00.000000 IP 10.64.0.2.5353 > 10.64.0.1.53: 1+ A? {label}.example.com. (40)"]
                     if iface == "wg-vpn1" else [])
            return self.clean(iface, payload, label) + extra
        c = self.run_checks(scenario)["proxy_dns_through_proxy"]
        self.assertEqual((c.passed, c.critical), (False, True))

    def test_the_resolver_talking_to_pxdns_is_not_a_leak(self):
        """dnsmasq asks over UDP into the namespace, where pxdns turns it
        into TCP through the relay. That UDP leg is the design."""
        def scenario(iface, payload, label):
            extra = ([f"12:00:00.000000 IP 10.99.0.7.4321 > 1.1.1.1.53: 1+ A? {label}.example.com. (40)"]
                     if iface == "px-res-de1" and not payload else [])
            return self.clean(iface, payload, label) + extra
        checks = self.run_checks(scenario)
        self.assertTrue(checks["proxy_dns_through_proxy"].passed)
        self.assertTrue(checks["proxy_udp_refused"].passed)

    def test_the_client_exiting_as_the_entry_is_critical(self):
        c = self.run_checks(self.clean, exit_ip="43.229.76.126")["proxy_exit_not_entry"]
        self.assertEqual((c.passed, c.critical), (False, True))
        self.assertIn("AROUND THE PROXY", c.detail)

    def test_a_capture_that_saw_nothing_warns_rather_than_fails(self):
        checks = self.run_checks(lambda iface, payload, label: [], refused=0)
        for cid in ("proxy_server_via_entry", "proxy_udp_refused"):
            with self.subTest(check=cid):
                self.assertEqual((checks[cid].passed, checks[cid].critical), (False, False))

    def test_no_answer_proves_nothing_about_dns(self):
        c = self.run_checks(self.clean, answered=False)["proxy_dns_through_proxy"]
        self.assertEqual((c.passed, c.critical), (False, False))


class TheProxyDisruption(unittest.TestCase):
    """Held tunnels lose their routes; the proxy's must be put back, or the
    relay-stopped and entry-down phases only re-test the blackhole."""

    def test_the_route_into_the_namespace_is_restored_inside_each_hold(self):
        src = (Path(__file__).resolve().parent.parent / "vpngw/leaktest.py"
               ).read_text(encoding="utf-8")
        body = src[src.index("def _check_disrupted_proxy("):src.index("def _check_disrupted(")]
        holds = body.split("with self.service.reconciler.hold(")[1:]
        self.assertEqual(len(holds), 2)
        for phase in holds:
            with self.subTest(phase=phase.splitlines()[0]):
                self.assertLess(phase.index("routing.set_default_via(*into_namespace)"),
                                phase.index("self._reaches_internet("))

if __name__ == "__main__":
    unittest.main()
