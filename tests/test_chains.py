"""Chained tunnels (double VPN).

The property everything here defends: a chained tunnel's encrypted packets
leave through its parent and *nowhere else* - not the WAN, not another
tunnel - and the machinery that enforces it (mark, rule, endpoint
confinement) is generated correctly for exactly the tunnels that are
chained.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpngw import config  # noqa: E402
from vpngw.db import Database  # noqa: E402
from vpngw.models import Tunnel, TunnelKind, ValidationError  # noqa: E402
from vpngw.net import routing  # noqa: E402


def wg(slug, esid, endpoints=None, via=""):
    return Tunnel(slug=slug, name=slug, kind=TunnelKind.WIREGUARD,
                  esid=esid, endpoints=endpoints or [], via=via)


class ChainDb(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Database(Path(tmp.name) / "t.db")
        self.addCleanup(self.db.close)
        self.a = self.db.add_tunnel(wg("aa01", 1, ["1.2.3.4"]))
        self.b = self.db.add_tunnel(wg("bb01", 2, ["5.6.7.8"]))

    def chain(self, child, parent):
        self.db.validate_via(child, parent)
        t = self.db.tunnel(child)
        t.via = parent
        self.db.update_tunnel(t)


class TestViaValidation(ChainDb):
    def test_a_valid_chain_is_accepted_and_stored(self):
        self.chain("bb01", "aa01")
        self.assertEqual(self.db.tunnel("bb01").via, "aa01")

    def test_self_reference_is_refused(self):
        with self.assertRaises(ValidationError):
            self.db.validate_via("aa01", "aa01")

    def test_a_cycle_is_refused(self):
        """a->b->a would orbit forever; neither packet ever reaches the WAN."""
        self.chain("bb01", "aa01")
        with self.assertRaises(ValidationError) as cm:
            self.db.validate_via("aa01", "bb01")
        self.assertIn("loop", str(cm.exception))

    def test_the_hop_ceiling_is_two(self):
        """Double VPN is the product: entry + exit and no deeper."""
        self.db.add_tunnel(wg("cc01", 3, ["9.9.9.9"]))
        self.chain("bb01", "aa01")
        with self.assertRaises(ValidationError) as cm:
            self.db.validate_via("cc01", "bb01")
        self.assertIn("ceiling", str(cm.exception))

    def test_the_ceiling_also_counts_riders_below(self):
        """Chaining a tunnel that itself carries riders lengthens *their*
        chains - the check must see the whole path, not just upward."""
        self.db.add_tunnel(wg("cc01", 3, ["9.9.9.9"]))
        self.chain("cc01", "bb01")             # cc rides bb (2 hops)
        with self.assertRaises(ValidationError):
            self.db.validate_via("bb01", "aa01")   # would make cc 3 hops

    def test_unknown_parent_is_refused(self):
        with self.assertRaises(ValidationError):
            self.db.validate_via("aa01", "ghost")

    def test_clearing_via_is_always_fine(self):
        self.db.validate_via("aa01", "")

    def test_shared_endpoint_with_a_wan_tunnel_is_refused(self):
        """The shared address would have to stay on the WAN allow-list,
        which quietly weakens the chained tunnel's confinement."""
        self.db.add_tunnel(wg("cc01", 3, ["5.6.7.8"]))   # same ep as bb01
        with self.assertRaises(ValidationError) as cm:
            self.db.validate_via("bb01", "aa01")
        self.assertIn("allow-list", str(cm.exception))

    def test_deleting_a_carrier_is_refused(self):
        self.chain("bb01", "aa01")
        with self.assertRaises(ValidationError) as cm:
            self.db.delete_tunnel("aa01")
        self.assertIn("carries", str(cm.exception))

    def test_chain_of_walks_exit_first(self):
        self.chain("bb01", "aa01")
        slugs = [t.slug for t in self.db.chain_of(self.db.tunnel("bb01"))]
        self.assertEqual(slugs, ["bb01", "aa01"])

    def test_chain_of_survives_a_dangling_parent(self):
        """A broken link ends the walk; status paths must never raise."""
        t = self.db.tunnel("bb01")
        t.via = "aa01"
        self.db.update_tunnel(t)
        self.db._x("DELETE FROM tunnel WHERE slug='aa01'")  # bypass guards
        slugs = [x.slug for x in self.db.chain_of(self.db.tunnel("bb01"))]
        self.assertEqual(slugs, ["bb01"])


class TestMigration(unittest.TestCase):
    def test_a_v1_database_gains_the_via_column(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "old.db"

        import sqlite3
        conn = sqlite3.connect(path)
        conn.execute("""CREATE TABLE tunnel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
            kind TEXT NOT NULL, esid INTEGER NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 1,
            config_path TEXT NOT NULL DEFAULT '',
            mtu INTEGER NOT NULL DEFAULT 0,
            dns TEXT NOT NULL DEFAULT '[]',
            endpoints TEXT NOT NULL DEFAULT '[]',
            endpoint_hosts TEXT NOT NULL DEFAULT '[]',
            notes TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL)""")
        conn.execute("INSERT INTO tunnel (slug,name,kind,esid,created_at)"
                     " VALUES ('old1','old','wireguard',7,0)")
        conn.commit()
        conn.close()

        db = Database(path)
        self.addCleanup(db.close)
        t = db.tunnel("old1")
        self.assertEqual(t.via, "", "migrated tunnel is unchained")
        # And a second open must not fail on the already-added column.
        db.close()
        Database(path).close()


class TestOuterMark(unittest.TestCase):
    def test_disjoint_from_every_client_mark(self):
        """No outer mark may satisfy a client rule's /0xffff match value
        AND its own /0x1ffff rule at the same priority band - disjointness
        is what lets the outer rule at 850 always win."""
        t = wg("x", 999)
        self.assertEqual(t.outer_mark & ~config.MARK_MASK,
                         config.OUTER_MARK_BASE)
        self.assertNotEqual(t.outer_mark & config.OUTER_MARK_MASK,
                            t.mark & config.OUTER_MARK_MASK)

    def test_rule_generated_only_for_chained_tunnels(self):
        a, b = wg("a", 1), wg("b", 2, via="a")
        rules = routing.desired_rules([], lambda esid: "10.99.0.1",
                                      chained=[(b, a)])
        outer = [r for r in rules if str(config.RULE_PRIO_OUTER) in r]
        self.assertEqual(len(outer), 1)
        rule = outer[0]
        self.assertIn(f"{b.outer_mark:#x}/{config.OUTER_MARK_MASK:#x}", rule)
        self.assertIn(str(a.table), rule)

    def test_no_chains_means_no_outer_rules(self):
        rules = routing.desired_rules([], lambda esid: "10.99.0.1", chained=[])
        self.assertFalse([r for r in rules
                          if str(config.RULE_PRIO_OUTER) in r])

    def test_outer_rule_priority_beats_every_client_rule(self):
        self.assertLess(config.RULE_PRIO_OUTER, config.RULE_PRIO_MARK + 1)
        self.assertGreater(config.RULE_PRIO_OUTER, config.RULE_PRIO_LOCAL)


class TestWireguardFwmark(unittest.TestCase):
    def _setconf(self, tunnel):
        from vpngw.tunnels.wg import WireGuardDriver
        import vpngw.tunnels.wg as wgmod

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        saved = config.WG_RUNTIME
        config.WG_RUNTIME = Path(tmp.name)
        self.addCleanup(lambda: setattr(config, "WG_RUNTIME", saved))

        drv = WireGuardDriver()
        path = drv._write_setconf(tunnel, {
            "private_key": "k" * 43 + "=",
            "peers": [{"public_key": "p" * 43 + "=",
                       "endpoint": "1.2.3.4:51820"}],
        })
        text = path.read_text()
        path.unlink()
        return text

    def test_chained_tunnel_carries_its_fwmark(self):
        t = wg("bb01", 2, via="aa01")
        self.assertIn(f"FwMark = {t.outer_mark:#x}", self._setconf(t))

    def test_unchained_tunnel_carries_none(self):
        """setconf replaces the whole device config, so the absent line is
        also what *clears* the mark when a chain is dissolved."""
        self.assertNotIn("FwMark", self._setconf(wg("aa01", 1)))


class TestOpenvpnMark(unittest.TestCase):
    def test_mark_directive_present_exactly_when_chained(self):
        from vpngw.render import openvpn as r

        base = "remote 1.2.3.4 1194\ndev tun\n"
        marked, _ = r.render(base, slug="x", iface="tun-x", fwmark=0x10005)
        plain, _ = r.render(base, slug="x", iface="tun-x", fwmark=0)
        self.assertIn("mark 65541", marked)
        self.assertNotIn("\nmark ", plain)


if __name__ == "__main__":
    unittest.main()


class TestProviderLogoutRoute(unittest.TestCase):
    """The panel's Remove account button had no endpoint behind it.

    It answered 404 for the life of the project, so a provider account
    could be added from the panel but never removed there - and since a
    second account cannot be stored while the first one is, the operator
    was stuck with whichever account they first typed in. The route is
    trivial; that it was missing was invisible because nothing tested that
    the paths the UI calls actually exist.
    """

    def test_every_provider_path_the_panel_calls_exists(self):
        import re
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        js = (root / "vpngw" / "web" / "static" / "app.js").read_text(
            encoding="utf-8")
        api = (root / "vpngw" / "api.py").read_text(encoding="utf-8")

        # Paths the panel calls, as template literals: /api/providers/${x}/verb
        called = set(re.findall(
            r'/api/providers/\$\{[^}]+\}/([a-z_]+)', js))
        declared = set(re.findall(
            r'@app\.\w+\("/api/providers/\{provider_id\}/([a-z_]+)"', api))

        missing = sorted(called - declared)
        self.assertFalse(
            missing,
            f"the panel calls provider endpoints that do not exist: {missing}")


class TestDeleteRoutesAreHonest(unittest.TestCase):
    """Deleting something that is not there must not report success.

    Every delete endpoint used to answer 200 for an unknown id, so the
    panel said "Pool deleted" and refreshed while nothing had happened.
    A false success is worst exactly when something else is already wrong -
    a stale page, a slug that is not what the operator thinks it is.
    """

    def test_each_delete_checks_the_resource_exists_first(self):
        import re
        from pathlib import Path

        api = (Path(__file__).resolve().parent.parent / "vpngw" / "api.py"
               ).read_text(encoding="utf-8")

        for resource, lookup in (("tunnels", "db.tunnel("),
                                 ("pools", "db.pool("),
                                 ("clients", "db.client(")):
            with self.subTest(resource=resource):
                m = re.search(
                    r'@app\.delete\("/api/' + resource + r'/\{[^}]+\}"\)'
                    r'(.*?)(?=\n    @app\.|\Z)', api, re.S)
                self.assertIsNotNone(m, f"no delete route for {resource}")
                body = m.group(1)
                self.assertIn(lookup, body,
                              f"{resource} delete does not look the resource up")
                self.assertIn("404", body,
                              f"{resource} delete does not 404 on an unknown id")
