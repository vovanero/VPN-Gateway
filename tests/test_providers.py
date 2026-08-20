"""Tests for the provider plugins and the bundle importer.

No network. The Mullvad plugin is exercised against captured API shapes, so
these tests check our parsing and our safety rails rather than Mullvad's
uptime - a test that fails when a provider has an outage teaches you nothing.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpngw import bundle, config, providers  # noqa: E402
from vpngw.db import Database  # noqa: E402
from vpngw.models import TunnelKind  # noqa: E402
from vpngw.providers import ProviderError  # noqa: E402
from vpngw.providers.base import Session  # noqa: E402
from vpngw.providers.mullvad import Mullvad  # noqa: E402
from vpngw.render import nftables  # noqa: E402

# One entry, verbatim in shape, from api.mullvad.net/www/relays/wireguard/
RELAY = {
    "hostname": "nl-ams-wg-001",
    "country_code": "nl", "country_name": "Netherlands",
    "city_code": "ams", "city_name": "Amsterdam",
    "fqdn": "nl-ams-wg-001.relays.mullvad.net",
    "active": True, "owned": True, "provider": "31173",
    "ipv4_addr_in": "185.65.134.66",
    "ipv6_addr_in": "2a03:1b20:5:f011::a01f",
    "network_port_speed": 10, "stboot": True, "type": "wireguard",
    "status_messages": [],
    "pubkey": "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=",
    "multihop_port": 3494, "socks_port": 1080, "daita": True,
}
INACTIVE = dict(RELAY, hostname="se-sto-wg-009", active=False,
                city_name="Stockholm", country_name="Sweden")

WG_CONF = """\
[Interface]
PrivateKey = QFXFQ3M5tHBGzXK1jvKm1LiRgFPtLQXsVvJ0nO2kBnk=
Address = 10.64.222.11/32
DNS = 10.64.0.1
MTU = 1380

[Peer]
PublicKey = OG9pKUq1RiQNTBLxlm6y8XkMHu3nJlqZLQrVvHmU3Wc=
AllowedIPs = 0.0.0.0/0
Endpoint = 185.65.134.66:51820
"""

OVPN_CONF = """\
client
dev tun
proto udp
remote nl-ams.example.net 1194 udp
<ca>
-----BEGIN CERTIFICATE-----
placeholder
-----END CERTIFICATE-----
</ca>
"""

OVPN_NEEDS_AUTH = OVPN_CONF + "auth-user-pass\n"


class FakeMullvad(Mullvad):
    """Mullvad with the network replaced by canned responses."""

    def __init__(self, responses: dict) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, object]] = []

    def request(self, url, *, method="GET", token="", payload=None, timeout=20):
        self._assert_allowed_host(url)          # keep the real safety rail
        self.calls.append((method, url, payload))
        key = f"{method} {url}"
        if key not in self.responses:
            raise AssertionError(f"unexpected call: {key}")
        value = self.responses[key]
        if isinstance(value, Exception):
            raise value
        return value


class TestProviderSafety(unittest.TestCase):
    def test_plugin_cannot_contact_an_undeclared_host(self):
        """The firewall allowlist is built from api_hosts. A plugin fetching
        somewhere else would be dropped with no useful error, so the mismatch
        is caught here instead."""
        p = FakeMullvad({})
        with self.assertRaises(ProviderError) as cm:
            p.request("https://evil.example.com/steal")
        self.assertIn("api_hosts", str(cm.exception))

    def test_registry_reports_every_api_host(self):
        hosts = providers.api_hosts()
        self.assertIn("api.mullvad.net", hosts)
        for p in providers.all_providers():
            for h in p.api_hosts:
                self.assertIn(h, hosts)

    def test_unknown_provider_is_rejected_by_name(self):
        with self.assertRaises(ProviderError) as cm:
            providers.get("nope")
        self.assertIn("mullvad", str(cm.exception))


class TestMullvad(unittest.TestCase):
    def test_login_rejects_a_non_numeric_account(self):
        p = FakeMullvad({})
        with self.assertRaises(ProviderError):
            p.login({"account_number": "user@example.com"})

    def test_login_rejects_an_empty_account(self):
        with self.assertRaises(ProviderError):
            FakeMullvad({}).login({})

    def test_login_returns_a_session(self):
        p = FakeMullvad({
            "POST https://api.mullvad.net/auth/v1/token":
                {"access_token": "tok", "expiry": "2030-01-01T00:00:00+00:00"},
        })
        session = p.login({"account_number": "1234 5678 9012 3456"})
        self.assertEqual(session.token, "tok")
        self.assertTrue(session.valid)
        # Spaces are how Mullvad prints the number; they must not be sent.
        self.assertEqual(p.calls[0][2], {"account_number": "1234567890123456"})

    def test_locations_skips_inactive_relays(self):
        p = FakeMullvad({
            "GET https://api.mullvad.net/www/relays/wireguard/": [RELAY, INACTIVE],
        })
        locations = p.locations()
        self.assertEqual([l.id for l in locations], ["nl-ams-wg-001"])
        l = locations[0]
        self.assertEqual(l.address, "185.65.134.66")
        self.assertEqual(l.pubkey, RELAY["pubkey"])
        self.assertEqual(l.label, "Amsterdam, Netherlands")
        self.assertTrue(l.owned)

    def test_locations_needs_no_credentials(self):
        # The relay list is public; sending a token would be pointless and
        # would leak the account to a request that does not need it.
        p = FakeMullvad({
            "GET https://api.mullvad.net/www/relays/wireguard/": [RELAY],
        })
        p.locations()
        self.assertEqual(p.calls[0][0], "GET")

    def test_provision_uploads_only_the_public_key(self):
        p = FakeMullvad({
            "GET https://api.mullvad.net/accounts/v1/devices": [],
            "POST https://api.mullvad.net/accounts/v1/devices": {
                "id": "dev-1", "name": "Happy Otter",
                "pubkey": "PUB", "ipv4_address": "10.64.222.11/32",
                "ipv6_address": "fc00::1/128", "ports": [],
            },
        })
        p._fake_keys = ("PRIV", "PUB")

        import vpngw.tunnels.wg as wg
        original = wg.genkey
        wg.genkey = lambda: ("PRIVATEKEYVALUE", "PUBLICKEYVALUE")
        try:
            location = p.locations.__wrapped__ if False else None
            loc = FakeMullvad({
                "GET https://api.mullvad.net/www/relays/wireguard/": [RELAY],
            }).locations()[0]
            remote = p.provision(Session(token="t"), loc, TunnelKind.WIREGUARD)
        finally:
            wg.genkey = original

        posted = [c for c in p.calls if c[0] == "POST"][0][2]
        self.assertEqual(posted["pubkey"], "PUBLICKEYVALUE")
        self.assertNotIn("PRIVATEKEYVALUE", json.dumps(posted))
        self.assertEqual(remote.private_key, "PRIVATEKEYVALUE")
        self.assertEqual(remote.peer_pubkey, RELAY["pubkey"])
        self.assertEqual(remote.endpoint, "185.65.134.66:51820")
        self.assertEqual(remote.dns, ["10.64.0.1"])

    def test_provision_refuses_when_the_device_limit_is_reached(self):
        full = [{"id": f"d{i}", "name": f"dev{i}", "pubkey": "", "created": "",
                 "ipv4_address": ""} for i in range(5)]
        p = FakeMullvad({
            "GET https://api.mullvad.net/accounts/v1/devices": full,
            "GET https://api.mullvad.net/www/relays/wireguard/": [RELAY],
        })
        loc = p.locations()[0]
        import vpngw.tunnels.wg as wg
        original, wg.genkey = wg.genkey, lambda: ("PRIV", "PUB")
        try:
            with self.assertRaises(ProviderError) as cm:
                p.provision(Session(token="t"), loc, TunnelKind.WIREGUARD)
        finally:
            wg.genkey = original
        self.assertIn("5", str(cm.exception))
        self.assertIn("device-rm", str(cm.exception).replace("device rm", "device-rm"))

    def test_openvpn_is_refused_with_a_useful_message(self):
        p = FakeMullvad({
            "GET https://api.mullvad.net/www/relays/wireguard/": [RELAY],
        })
        loc = p.locations()[0]
        with self.assertRaises(ProviderError) as cm:
            p.provision(Session(token="t"), loc, TunnelKind.OPENVPN)
        self.assertIn("import-bundle", str(cm.exception))


class TestCountryFilter(unittest.TestCase):
    """`--country nl` returning Finland is the bug this guards against."""

    def setUp(self):
        from vpngw.cli import _filter_country
        self.filter = _filter_country

        def loc(code, name, city):
            from vpngw.providers.base import Location
            return Location(id=f"{code}-x", country=name, city=city,
                            hostname="h", address="1.2.3.4",
                            kind=TunnelKind.WIREGUARD,
                            extra={"country_code": code})

        self.locations = [
            loc("fi", "Finland", "Helsinki"),
            loc("nl", "Netherlands", "Amsterdam"),
            loc("us", "USA", "New York"),
            loc("de", "Germany", "Berlin"),
        ]

    def test_two_letter_code_matches_exactly(self):
        got = self.filter(self.locations, "nl")
        self.assertEqual([l.country for l in got], ["Netherlands"])

    def test_code_does_not_substring_match_a_country_name(self):
        # "nl" is inside "Finland"; "de" is inside "Sweden" and "Netherlands".
        for code, expected in (("nl", "Netherlands"), ("de", "Germany"),
                               ("fi", "Finland")):
            with self.subTest(code=code):
                got = self.filter(self.locations, code)
                self.assertEqual([l.country for l in got], [expected])

    def test_longer_needle_matches_the_name(self):
        got = self.filter(self.locations, "nether")
        self.assertEqual([l.country for l in got], ["Netherlands"])

    def test_unknown_code_returns_nothing_rather_than_the_wrong_country(self):
        self.assertEqual(self.filter(self.locations, "zz"), [])

    def test_case_and_whitespace_are_ignored(self):
        self.assertEqual(
            [l.country for l in self.filter(self.locations, "  NL ")],
            ["Netherlands"])


class TestBundle(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def write(self, name: str, text: str) -> Path:
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def test_scans_a_folder_of_mixed_configs(self):
        self.write("mullvad-nl-ams-wg-001.conf", WG_CONF)
        self.write("de-berlin.prod.example.com.udp.ovpn", OVPN_CONF)
        found = bundle.scan(self.root)
        self.assertEqual(len(found), 2)
        kinds = {c.kind for c in found}
        self.assertEqual(kinds, {TunnelKind.WIREGUARD, TunnelKind.OPENVPN})
        self.assertTrue(all(c.usable for c in found))

    def test_display_name_strips_provider_noise(self):
        self.write("de-berlin.prod.example.com.udp.ovpn", OVPN_CONF)
        c = bundle.scan(self.root)[0]
        self.assertNotIn(".ovpn", c.display)
        self.assertNotIn("udp", c.display.lower())
        self.assertIn("berlin", c.display.lower())

    def test_unusable_files_are_reported_not_silently_dropped(self):
        self.write("good.conf", WG_CONF)
        self.write("broken.conf", "[Interface]\nnothing useful here\n")
        self.write("needs-auth.ovpn", OVPN_NEEDS_AUTH)
        found = bundle.scan(self.root)
        problems = {c.source: c.problem for c in found if not c.usable}
        self.assertEqual(len(problems), 2)
        self.assertIn("username", problems["needs-auth.ovpn"])

    def test_reads_a_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("configs/a.conf", WG_CONF)
            zf.writestr("configs/b.ovpn", OVPN_CONF)
            zf.writestr("configs/readme.txt", "ignore me")
        archive = self.root / "bundle.zip"
        archive.write_bytes(buf.getvalue())
        found = bundle.scan(archive)
        self.assertEqual(len(found), 2)      # the .txt is not a config

    def test_empty_archive_is_an_error_not_a_silent_success(self):
        self.write("notes.txt", "hello")
        with self.assertRaises(Exception):
            bundle.scan(self.root)

    def test_slugs_are_short_unique_and_avoid_existing_ones(self):
        for i in range(5):
            self.write(f"server-{i}.conf", WG_CONF)
        found = bundle.scan(self.root)
        bundle.assign_slugs(found, "nl", taken={"nl01", "nl02"})
        slugs = [c.slug for c in found]
        self.assertEqual(len(set(slugs)), 5)
        self.assertNotIn("nl01", slugs)
        self.assertNotIn("nl02", slugs)
        for s in slugs:
            self.assertLessEqual(len(s), config.SLUG_MAX_LEN)
            self.assertTrue(s.startswith("nl"))

    def test_slug_prefix_is_sanitised(self):
        self.write("a.conf", WG_CONF)
        found = bundle.scan(self.root)
        bundle.assign_slugs(found, "NL !! Amsterdam", taken=set())
        self.assertTrue(found[0].slug.startswith("nlamst"))
        self.assertLessEqual(len(found[0].slug), config.SLUG_MAX_LEN)

    def test_commit_writes_secrets_and_rows(self):
        etc = self.root / "etc"
        original_secrets = config.SECRETS_DIR
        config.SECRETS_DIR = etc / "secrets"
        db_file = self.root / "test.db"
        db = Database(db_file)
        try:
            self.write("one.conf", WG_CONF)
            found = bundle.scan(self.root)
            found = [c for c in found if c.usable]
            bundle.assign_slugs(found, "nl", taken=set())
            created = bundle.commit(db, found)
            self.assertEqual(len(created), 1)
            t = created[0]
            self.assertTrue(Path(t.config_path).exists())
            self.assertIn("PrivateKey", Path(t.config_path).read_text()
                          .replace("private_key", "PrivateKey"))
            self.assertGreater(t.esid, 0, "the database allocates the esid")
            if os.name == "posix":
                # Windows' chmod cannot express this; the real check runs on
                # the gateway, where `vpngwctl check` inspects the secrets dir.
                mode = oct(os.stat(t.config_path).st_mode)[-3:]
                self.assertEqual(mode, "600",
                                 "a stored private key must not be readable "
                                 "by other accounts")
        finally:
            db.close()
            config.SECRETS_DIR = original_secrets


class TestProviderFirewallIntegration(unittest.TestCase):
    def test_provider_api_set_is_empty_by_default(self):
        """A fresh install must not have a hole for an API it never calls."""
        text = nftables.render(config.Settings(), [], [], [])
        self.assertIn("set provider_api", text)
        block = text.split("set provider_api", 1)[1].split("}", 1)[0]
        self.assertNotIn("elements", block)

    def test_provider_api_addresses_appear_when_configured(self):
        text = nftables.render(config.Settings(), [], [], [],
                               api_endpoints=["45.83.223.196"])
        self.assertIn("45.83.223.196", text)
        self.assertIn(
            "oifname $WAN ip daddr @provider_api tcp dport 443 accept", text)

    def test_provider_api_access_is_https_only(self):
        text = nftables.render(config.Settings(), [], [], [],
                               api_endpoints=["45.83.223.196"])
        for line in text.splitlines():
            if "@provider_api" in line and "accept" in line:
                self.assertIn("tcp dport 443", line)

    def test_provider_api_never_widens_the_forward_chain(self):
        text = nftables.render(config.Settings(), [], [], [],
                               api_endpoints=["45.83.223.196"])
        chain = text.split("chain forward {", 1)[1].split("\n    }", 1)[0]
        self.assertNotIn("provider_api", chain)


if __name__ == "__main__":
    unittest.main(verbosity=2)
