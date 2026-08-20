"""Tests for everything that can be checked without a kernel.

Deliberately stdlib-only (unittest, not pytest) so this runs on the gateway
itself with nothing extra installed - being able to verify a box in the field
matters more than nicer assertion output.

The kernel-facing half is covered by `vpngwctl selftest`, which measures the
real thing instead of simulating it.
"""

from __future__ import annotations

import ipaddress
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpngw import config  # noqa: E402
from vpngw.db import Database  # noqa: E402
from vpngw.health import HealthMonitor  # noqa: E402
from vpngw.importers import (  # noqa: E402
    ImportError_,
    ovpn_endpoint_hosts,
    parse_openvpn,
    parse_wireguard,
    wg_endpoint_hosts,
)
from vpngw.models import (  # noqa: E402
    Client,
    EgressKind,
    HealthState,
    Pool,
    PoolMember,
    PoolStrategy,
    Tunnel,
    TunnelKind,
    ValidationError,
)
from vpngw.pools import PoolManager  # noqa: E402
from vpngw.render import nftables, openvpn  # noqa: E402

WG_CONFIG = """\
[Interface]
PrivateKey = QFXFQ3M5tHBGzXK1jvKm1LiRgFPtLQXsVvJ0nO2kBnk=
Address = 10.64.222.11/32, fc00:bbbb::1/128
DNS = 10.64.0.1
MTU = 1380

[Peer]
PublicKey = OG9pKUq1RiQNTBLxlm6y8XkMHu3nJlqZLQrVvHmU3Wc=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 185.65.134.66:51820
PersistentKeepalive = 25
"""

OVPN_CONFIG = """\
client
dev tun
proto udp
remote nl-ams.example.net 1194 udp
remote 149.88.104.10 443 tcp
resolv-retry infinite
redirect-gateway def1 bypass-dhcp
route 10.0.0.0 255.0.0.0
auth-user-pass
persist-tun
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
script-security 2
cipher AES-256-GCM
<ca>
-----BEGIN CERTIFICATE-----
dev tun this line is inside the cert block and must survive verbatim
redirect-gateway so is this
-----END CERTIFICATE-----
</ca>
"""


class TestConfig(unittest.TestCase):
    def test_resolver_subnet_must_cover_every_esid(self):
        settings = config.Settings(dns=config.DnsSettings(resolver_subnet="10.99.0.0/24"))
        with self.assertRaises(ValueError) as cm:
            settings.validate()
        self.assertIn("resolver_subnet", str(cm.exception))

    def test_default_settings_are_valid(self):
        config.Settings().validate()  # must not raise

    def test_overlapping_subnets_rejected(self):
        settings = config.Settings(
            net=config.NetSettings(lan_cidr="10.99.0.1/24"),
        )
        with self.assertRaises(ValueError) as cm:
            settings.validate()
        self.assertIn("overlaps", str(cm.exception))

    def test_uplink_may_not_be_the_lan(self):
        settings = config.Settings(net=config.NetSettings(wan_iface="br-lan"))
        with self.assertRaises(ValueError):
            settings.validate()

    def test_a_config_with_no_management_path_is_refused(self):
        # Applying the ruleset with nowhere to administer from is not
        # recoverable over the network - nothing else is listening by design.
        settings = config.Settings(
            net=config.NetSettings(mgmt_iface="", admin_cidr=""))
        with self.assertRaises(ValueError) as cm:
            settings.validate()
        self.assertIn("no management path", str(cm.exception))

    def test_admin_cidr_alone_is_a_valid_management_path(self):
        config.Settings(net=config.NetSettings(
            mgmt_iface="", admin_cidr="192.168.1.0/24")).validate()

    def test_admin_cidr_may_not_be_the_whole_internet(self):
        settings = config.Settings(
            net=config.NetSettings(mgmt_iface="", admin_cidr="0.0.0.0/0"))
        with self.assertRaises(ValueError) as cm:
            settings.validate()
        self.assertIn("whole internet", str(cm.exception))

    def test_malformed_admin_cidr_is_refused(self):
        settings = config.Settings(
            net=config.NetSettings(mgmt_iface="", admin_cidr="not-a-network"))
        with self.assertRaises(ValueError):
            settings.validate()

    def test_resolver_ip_is_derived_and_unique(self):
        dns = config.DnsSettings()
        seen = {dns.resolver_ip(e) for e in (1, 2, 999, 1000, 1999)}
        self.assertEqual(len(seen), 5)
        self.assertEqual(dns.resolver_ip(1), "10.99.0.1")
        # The highest pool esid must still fit; this is the case that broke
        # the original /24 and is the reason validate() exists.
        self.assertTrue(
            ipaddress.ip_address(dns.resolver_ip(1999)) in dns.network
        )


class TestModels(unittest.TestCase):
    def test_slug_length_keeps_iface_name_legal(self):
        t = Tunnel(slug="a" * config.SLUG_MAX_LEN, name="x",
                   kind=TunnelKind.OPENVPN, esid=1)
        # IFNAMSIZ is 16 including the NUL, so 15 usable characters.
        self.assertLessEqual(len(t.iface), 15)

    def test_bad_slugs_rejected(self):
        for bad in ("-lead", "way-too-long-name", "has space", "", "a_b"):
            with self.subTest(slug=bad), self.assertRaises(ValidationError):
                Tunnel(slug=bad, name="x", kind=TunnelKind.WIREGUARD, esid=1)

    def test_slug_case_is_folded_not_rejected(self):
        t = Tunnel(slug="NL01", name="x", kind=TunnelKind.WIREGUARD, esid=1)
        self.assertEqual(t.slug, "nl01")

    def test_esid_zero_means_unallocated(self):
        # The database assigns the real value; the model must let the sentinel
        # through or the auto-allocation path could never be used.
        t = Tunnel(slug="a", name="A", kind=TunnelKind.WIREGUARD, esid=0)
        self.assertEqual(t.esid, 0)
        with self.assertRaises(ValidationError):
            Tunnel(slug="b", name="B", kind=TunnelKind.WIREGUARD, esid=5000)

    def test_table_and_mark_derive_from_esid(self):
        t = Tunnel(slug="a", name="A", kind=TunnelKind.WIREGUARD, esid=7)
        p = Pool(slug="p", name="P", esid=1007)
        self.assertEqual(t.table, config.TABLE_BASE + 7)
        self.assertEqual(t.mark, 7)
        self.assertNotEqual(t.table, p.table)

    def test_pool_esid_must_be_in_pool_range(self):
        with self.assertRaises(ValidationError):
            Pool(slug="p", name="P", esid=5)

    def test_client_rejects_ipv6_and_bad_mac(self):
        with self.assertRaises(ValidationError):
            Client(name="x", ip="fc00::1")
        with self.assertRaises(ValidationError):
            Client(name="x", ip="10.10.0.5", mac="zz:zz:zz:zz:zz:zz")
        c = Client(name="x", ip="10.10.0.5", mac="00-15-5D-0A-F0-01")
        self.assertEqual(c.mac, "00:15:5d:0a:f0:01")

    def test_client_must_be_inside_the_lan(self):
        c = Client(name="x", ip="192.168.1.5")
        with self.assertRaises(ValidationError):
            c.check_in_lan(ipaddress.ip_network("10.10.0.0/24"))


class TestWireGuardImport(unittest.TestCase):
    def test_parses_a_real_config(self):
        spec = parse_wireguard(WG_CONFIG)
        self.assertEqual(spec.mtu, 1380)
        self.assertEqual(spec.dns, ["10.64.0.1"])          # v6 DNS dropped
        self.assertEqual(len(spec.peers), 1)
        self.assertEqual(spec.peers[0].keepalive, 25)
        self.assertEqual(wg_endpoint_hosts(spec), ["185.65.134.66"])

    def test_wg_quick_directives_are_ignored(self):
        # Table/PostUp are how wg-quick installs its own routing and firewall
        # rules. Honouring them on this box would let an imported file
        # reconfigure the kill switch.
        spec = parse_wireguard(
            WG_CONFIG + "\n[Interface]\nTable = auto\nPostUp = iptables -F\n"
        )
        self.assertTrue(spec.private_key)

    def test_missing_private_key_rejected(self):
        with self.assertRaises(ImportError_):
            parse_wireguard("[Peer]\nPublicKey = x\nEndpoint = 1.2.3.4:1\n")

    def test_malformed_key_rejected(self):
        broken = WG_CONFIG.replace(
            "QFXFQ3M5tHBGzXK1jvKm1LiRgFPtLQXsVvJ0nO2kBnk=", "not-a-key")
        with self.assertRaises(ImportError_):
            parse_wireguard(broken)

    def test_peer_without_endpoint_rejected(self):
        broken = WG_CONFIG.replace("Endpoint = 185.65.134.66:51820", "")
        with self.assertRaises(ImportError_):
            parse_wireguard(broken)


class TestOpenVpnImport(unittest.TestCase):
    def test_collects_every_remote(self):
        spec = parse_openvpn(OVPN_CONFIG)
        self.assertEqual(len(spec.remotes), 2)
        self.assertEqual(
            ovpn_endpoint_hosts(spec), ["nl-ams.example.net", "149.88.104.10"]
        )
        self.assertTrue(spec.needs_auth)
        self.assertTrue(spec.has_ca)

    def test_directives_inside_inline_blocks_are_not_parsed(self):
        # The cert body contains the words "dev tun" and "redirect-gateway".
        # Treating those as directives would corrupt the certificate.
        spec = parse_openvpn(OVPN_CONFIG)
        self.assertEqual(spec.dev_type, "tun")

    def test_tap_configs_rejected(self):
        with self.assertRaises(ImportError_):
            parse_openvpn("client\ndev tap\nremote x.example 1194\n")

    def test_config_without_remote_rejected(self):
        with self.assertRaises(ImportError_):
            parse_openvpn("client\ndev tun\n")


class TestOpenVpnRender(unittest.TestCase):
    def setUp(self):
        self.text, self.removed = openvpn.render(
            OVPN_CONFIG, slug="nl01", iface="tun-nl01",
            auth_file="/etc/vpngw/secrets/nl01.auth",
        )

    def test_routing_directives_are_neutralised(self):
        for directive in ("redirect-gateway def1", "route 10.0.0.0",
                          "persist-tun", "up /etc/openvpn"):
            with self.subTest(directive=directive):
                self.assertIn(f"# vpngw removed: {directive}", self.text)

    def test_inline_certificate_survives_untouched(self):
        self.assertIn(
            "dev tun this line is inside the cert block and must survive verbatim",
            self.text,
        )
        self.assertIn("-----BEGIN CERTIFICATE-----", self.text)

    def test_our_directives_are_appended(self):
        self.assertIn("dev tun-nl01", self.text)
        self.assertIn('pull-filter ignore "redirect-gateway"', self.text)
        self.assertIn("auth-user-pass /etc/vpngw/secrets/nl01.auth", self.text)

    def test_pushed_dns_is_still_accepted(self):
        # route-nopull would also discard pushed DNS servers, which several
        # providers require you to use. We filter routes specifically instead.
        self.assertNotIn("\nroute-nopull", self.text)

    def test_unknown_provider_options_pass_through(self):
        self.assertIn("cipher AES-256-GCM", self.text)


class TestNftRender(unittest.TestCase):
    def setUp(self):
        self.settings = config.Settings()
        self.tunnels = [
            Tunnel(slug="nl01", name="NL", kind=TunnelKind.WIREGUARD, esid=1,
                   endpoints=["185.65.134.66"]),
            Tunnel(slug="us01", name="US", kind=TunnelKind.OPENVPN, esid=2,
                   endpoints=["149.88.104.10"]),
        ]
        self.pools = [Pool(slug="eu", name="EU", esid=1000,
                           members=[PoolMember("nl01", 10)])]

    def render(self, clients):
        return nftables.render(self.settings, self.tunnels, self.pools, clients)

    def test_kill_switch_rules_are_present(self):
        text = self.render([])
        self.assertIn("type filter hook forward priority filter; policy drop;", text)
        self.assertIn('oifname $WAN counter name "wan_leak_drop" drop', text)
        self.assertIn('oifname != @tun_ifaces counter name "nontunnel_drop" drop', text)

    def test_empty_state_is_valid_and_forwards_nothing(self):
        # A fresh install has no tunnels; nft rejects "elements = { }", so this
        # is the case that must not emit one.
        text = nftables.render(config.Settings(), [], [], [])
        self.assertNotIn("elements = {  }", text)
        self.assertNotIn("elements = { }", text)
        self.assertIn("set tun_ifaces", text)

    def test_assigned_client_is_mapped_to_its_egress(self):
        text = self.render([
            Client(name="pc01", ip="10.10.0.11",
                   egress_kind=EgressKind.TUNNEL, egress_slug="nl01"),
        ])
        self.assertIn("10.10.0.11 : 0x0001", text)
        self.assertIn("10.10.0.11 : 10.99.0.1", text)

    def test_pool_client_gets_the_pool_mark(self):
        text = self.render([
            Client(name="pc02", ip="10.10.0.12",
                   egress_kind=EgressKind.POOL, egress_slug="eu"),
        ])
        self.assertIn(f"10.10.0.12 : {1000:#06x}", text)

    def test_unassigned_client_gets_no_mapping(self):
        text = self.render([Client(name="pc03", ip="10.10.0.13")])
        self.assertNotIn("10.10.0.13 :", text)

    def test_client_of_a_disabled_tunnel_gets_no_mapping(self):
        self.tunnels[0].enabled = False
        text = self.render([
            Client(name="pc01", ip="10.10.0.11",
                   egress_kind=EgressKind.TUNNEL, egress_slug="nl01"),
        ])
        self.assertNotIn("10.10.0.11 :", text)
        self.assertNotIn('"wg-nl01"', text)

    def test_maintenance_never_touches_the_forward_chain(self):
        normal = nftables.render(self.settings, self.tunnels, self.pools, [])
        maint = nftables.render(self.settings, self.tunnels, self.pools, [],
                                maintenance=True)
        for text in (normal, maint):
            self.assertIn('oifname $WAN counter name "wan_leak_drop" drop', text)
        self.assertIn("hook output priority filter; policy drop;", normal)
        self.assertIn("hook output priority filter; policy accept;", maint)

    def test_boot_skeleton_drops_by_default(self):
        text = nftables.render_killswitch(config.Settings())
        self.assertIn("type filter hook forward priority filter; policy drop;", text)
        self.assertIn('oifname "wan0"', text)

    @staticmethod
    def _forward_chain(text: str) -> list[str]:
        lines, inside = [], False
        for raw in text.splitlines():
            if "chain forward {" in raw:
                inside = True
                continue
            if inside:
                if raw.strip() == "}":
                    break
                lines.append(raw.strip())
        return lines

    def test_forward_chain_has_no_destination_based_exception(self):
        """Regression guard against split tunnelling being reintroduced.

        The whole guarantee is that a forwarded packet can only leave through a
        tunnel. Any accept in this chain that is not gated on @tun_ifaces is a
        hole, and a hole makes the leak test unassertable - it could no longer
        say "zero packets on the uplink", only "zero except the expected ones".
        See docs/killswitch.md.
        """
        text = self.render([
            Client(name="pc01", ip="10.10.0.11",
                   egress_kind=EgressKind.TUNNEL, egress_slug="nl01"),
        ])
        chain = self._forward_chain(text)
        self.assertTrue(chain, "forward chain not found in the rendered ruleset")

        joined, accepts = "", []
        for line in chain:
            joined = (joined + " " + line).strip() if joined else line
            if line.endswith("\\"):          # rule continues on the next line
                joined = joined[:-1].strip()
                continue
            if joined.startswith("#") or not joined:
                joined = ""
                continue
            if " accept" in joined or joined.endswith("accept"):
                accepts.append(joined)
            joined = ""

        self.assertTrue(accepts, "no accept rules found - the chain parse is wrong")
        for rule in accepts:
            with self.subTest(rule=rule):
                self.assertIn(
                    "@tun_ifaces", rule,
                    "an accept in the forward chain is not restricted to tunnel "
                    "interfaces; this is how a split-tunnel hole gets introduced",
                )
        # And nothing may match on a destination address, which is the shape a
        # bypass list would take.
        for rule in chain:
            self.assertNotIn("ip daddr", rule)

    def test_management_over_uplink_is_restricted_to_the_admin_range(self):
        settings = config.Settings(net=config.NetSettings(
            mgmt_iface="", admin_cidr="100.200.50.0/24"))
        text = nftables.render(settings, self.tunnels, self.pools, [])
        self.assertIn("define ADMIN_NET   = 100.200.50.0/24", text)
        self.assertIn(
            "iifname $WAN ip saddr $ADMIN_NET tcp dport { 22, 8080 } accept", text)
        # $MGMT must not survive as a dangling reference - nft would reject it.
        self.assertNotIn("$MGMT", text)
        self.assertNotIn("define MGMT", text)

    def test_boot_skeleton_keeps_the_same_door_open(self):
        # If the skeleton locked the operator out, a boot where vpngw fails to
        # start would leave a box nobody can log in to fix.
        settings = config.Settings(net=config.NetSettings(
            mgmt_iface="", admin_cidr="100.200.50.0/24"))
        text = nftables.render_killswitch(settings)
        self.assertIn(
            'iifname "wan0" ip saddr 100.200.50.0/24 tcp dport { 22 } accept',
            text)

    def test_clients_can_never_reach_the_management_ports(self):
        for net in (config.NetSettings(),
                    config.NetSettings(mgmt_iface="", admin_cidr="10.0.0.0/24")):
            with self.subTest(mgmt=net.mgmt_iface or "admin_cidr"):
                text = nftables.render(config.Settings(net=net),
                                       self.tunnels, self.pools, [])
                chain, inside = [], False
                for raw in text.splitlines():
                    if "chain input {" in raw:
                        inside = True
                        continue
                    if inside:
                        if raw.strip() == "}":
                            break
                        chain.append(raw.strip())
                for rule in chain:
                    if "@client_ifaces" in rule and "accept" in rule:
                        self.assertNotIn("22", rule)
                        self.assertNotIn("8080", rule)

    def test_clients_on_the_uplink_segment_are_still_confined(self):
        """The other supported layout: clients sharing the uplink's subnet.

        The guarantee that changes is what happens *outside* this box - such a
        client can ARP the real router directly, and nothing here sees that.
        What must not change is the guarantee inside it: traffic that does
        arrive still leaves only through a tunnel.
        """
        settings = config.Settings(net=config.NetSettings(
            client_ifaces=("br-lan", "wan0"), admin_cidr="10.0.0.0/24"))
        text = nftables.render(settings, self.tunnels, self.pools, [])
        self.assertIn('elements = { "br-lan", "wan0" }', text)

        chain = self._forward_chain(text)
        joined, accepts = "", []
        for line in chain:
            joined = (joined + " " + line).strip() if joined else line
            if line.endswith("\\"):
                joined = joined[:-1].strip()
                continue
            if joined and not joined.startswith("#") and "accept" in joined:
                accepts.append(joined)
            joined = ""
        for rule in accepts:
            with self.subTest(rule=rule):
                self.assertIn("@tun_ifaces", rule)
        # The uplink drop still stands, so a client packet routed back out of
        # the uplink is caught exactly as before.
        self.assertIn('oifname $WAN counter name "wan_leak_drop" drop', text)

    def test_forward_chain_policy_is_drop(self):
        for clients in ([], [Client(name="pc01", ip="10.10.0.11")]):
            text = self.render(clients)
            self.assertIn(
                "chain forward {\n        type filter hook forward priority "
                "filter; policy drop;", text)


class TestPoolSelection(unittest.TestCase):
    def setUp(self):
        self.health = HealthMonitor(config.HealthSettings())
        self.mgr = PoolManager()
        self.pool = Pool(
            slug="eu", name="EU", esid=1000, sticky_seconds=0,
            members=[PoolMember("a", 10), PoolMember("b", 20),
                     PoolMember("c", 30)],
        )

    def mark(self, slug, state, rtt=None):
        h = self.health.get(slug)
        h.state = state
        h.rtt_ms = rtt

    def test_priority_picks_the_best_healthy_member(self):
        self.mark("a", HealthState.UP)
        self.mark("b", HealthState.UP)
        chosen, _ = self.mgr.select(self.pool, self.health)
        self.assertEqual(chosen, "a")

    def test_fails_over_when_the_best_goes_down(self):
        self.mark("a", HealthState.UP)
        self.mark("b", HealthState.UP)
        self.mgr.commit(self.pool, *self.mgr.select(self.pool, self.health))
        self.mark("a", HealthState.DOWN)
        chosen, reason = self.mgr.select(self.pool, self.health)
        self.assertEqual(chosen, "b")
        self.assertIn("failing over", reason)

    def test_everything_down_returns_none(self):
        for slug in "abc":
            self.mark(slug, HealthState.DOWN)
        chosen, reason = self.mgr.select(self.pool, self.health)
        # None means the caller blackholes the pool. It must never fall back to
        # "just use the first member anyway" - that is the leak.
        self.assertIsNone(chosen)
        self.assertIn("no healthy members", reason)

    def test_stickiness_prevents_flapping_back(self):
        self.pool.sticky_seconds = 300
        self.mark("a", HealthState.UP)
        self.mark("b", HealthState.UP)
        self.mgr.commit(self.pool, *self.mgr.select(self.pool, self.health))
        self.mark("a", HealthState.DOWN)
        self.mgr.commit(self.pool, *self.mgr.select(self.pool, self.health))
        self.assertEqual(self.mgr.get("eu").active, "b")

        # 'a' comes back immediately. With stickiness we stay on 'b'.
        self.mark("a", HealthState.UP)
        chosen, reason = self.mgr.select(self.pool, self.health)
        self.assertEqual(chosen, "b")
        self.assertIn("sticky", reason)

    def test_latency_strategy_picks_the_fastest(self):
        self.pool.strategy = PoolStrategy.LATENCY
        self.mark("a", HealthState.UP, rtt=210.0)
        self.mark("b", HealthState.UP, rtt=32.0)
        self.mark("c", HealthState.UP, rtt=95.0)
        chosen, _ = self.mgr.select(self.pool, self.health)
        self.assertEqual(chosen, "b")

    def test_random_strategy_is_stable_while_healthy(self):
        self.pool.strategy = PoolStrategy.RANDOM
        for slug in "abc":
            self.mark(slug, HealthState.UP)
        first, _ = self.mgr.select(self.pool, self.health)
        self.mgr.commit(self.pool, first, "")
        for _ in range(20):
            again, _ = self.mgr.select(self.pool, self.health)
            self.assertEqual(again, first)

    def test_disabled_pool_selects_nothing(self):
        self.pool.enabled = False
        self.mark("a", HealthState.UP)
        chosen, _ = self.mgr.select(self.pool, self.health)
        self.assertIsNone(chosen)


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = Database(Path(self.tmp.name))

    def tearDown(self):
        self.db.close()
        os.unlink(self.tmp.name)

    def add_tunnel(self, slug="nl01"):
        return self.db.add_tunnel(Tunnel(
            slug=slug, name=slug.upper(), kind=TunnelKind.WIREGUARD, esid=0))

    def test_esids_are_allocated_without_collisions(self):
        esids = {self.add_tunnel(f"t{i}").esid for i in range(5)}
        self.assertEqual(len(esids), 5)
        self.assertTrue(all(config.TUNNEL_ESID_MIN <= e <= config.TUNNEL_ESID_MAX
                            for e in esids))

    def test_tunnel_and_pool_esids_never_collide(self):
        t = self.add_tunnel()
        p = self.db.add_pool(Pool(slug="eu", name="EU", esid=0,
                                  members=[PoolMember(t.slug, 10)]))
        self.assertNotEqual(t.table, p.table)
        self.assertNotEqual(t.mark, p.mark)

    def test_freed_esid_is_reused(self):
        first = self.add_tunnel("a").esid
        self.db.delete_tunnel("a")
        self.assertEqual(self.add_tunnel("b").esid, first)

    def test_duplicate_slug_rejected(self):
        self.add_tunnel("a")
        with self.assertRaises(ValidationError):
            self.add_tunnel("a")

    def test_cannot_delete_a_tunnel_a_client_still_uses(self):
        # Deleting it silently would leave that client mapped to nothing, which
        # blocks it - safe, but a confusing way to lose connectivity.
        t = self.add_tunnel()
        self.db.add_client(Client(name="pc01", ip="10.10.0.11",
                                  egress_kind=EgressKind.TUNNEL,
                                  egress_slug=t.slug))
        with self.assertRaises(ValidationError) as cm:
            self.db.delete_tunnel(t.slug)
        self.assertIn("pc01", str(cm.exception))

    def test_client_cannot_point_at_an_unknown_egress(self):
        with self.assertRaises(ValidationError):
            self.db.add_client(Client(name="pc01", ip="10.10.0.11",
                                      egress_kind=EgressKind.TUNNEL,
                                      egress_slug="nope"))

    def test_duplicate_client_ip_rejected(self):
        t = self.add_tunnel()
        self.db.add_client(Client(name="a", ip="10.10.0.11",
                                  egress_kind=EgressKind.TUNNEL,
                                  egress_slug=t.slug))
        with self.assertRaises(ValidationError):
            self.db.add_client(Client(name="b", ip="10.10.0.11",
                                      egress_kind=EgressKind.TUNNEL,
                                      egress_slug=t.slug))

    def test_pool_membership_roundtrips_in_priority_order(self):
        for slug in ("a", "b", "c"):
            self.add_tunnel(slug)
        self.db.add_pool(Pool(slug="eu", name="EU", esid=0, members=[
            PoolMember("c", 30), PoolMember("a", 10), PoolMember("b", 20)]))
        loaded = self.db.pool("eu")
        self.assertEqual([m.tunnel_slug for m in loaded.ordered_members()],
                         ["a", "b", "c"])

    def test_pool_with_unknown_member_is_rejected_atomically(self):
        self.add_tunnel("a")
        with self.assertRaises(ValidationError):
            self.db.add_pool(Pool(slug="eu", name="EU", esid=0, members=[
                PoolMember("a", 10), PoolMember("ghost", 20)]))

    def test_events_are_bounded(self):
        for i in range(20):
            self.db.log_event("info", "test", f"event {i}")
        self.assertEqual(len(self.db.events(limit=5)), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
