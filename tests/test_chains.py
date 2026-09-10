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
    def _setconf(self, tunnel, spec=None):
        from vpngw.tunnels.wg import WireGuardDriver
        import vpngw.tunnels.wg as wgmod

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        saved = config.WG_RUNTIME
        config.WG_RUNTIME = Path(tmp.name)
        self.addCleanup(lambda: setattr(config, "WG_RUNTIME", saved))

        drv = WireGuardDriver()
        path = drv._write_setconf(tunnel, spec or {
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


class TestKeepaliveIsAlwaysSent(TestWireguardFwmark):
    """A client tunnel without one cannot come up on this box.

    Found on a live gateway: a hand-written config with no
    PersistentKeepalive line produced an interface that was up, a peer that
    was configured, and zero bytes transferred - forever. WireGuard only
    handshakes when it has something to send; nothing has anything to send
    until the tunnel is healthy; the egress table holds a blackhole until
    then, so the health probe cannot get out to make the traffic that would
    complete the handshake.

    Every provider config we had shipped the line, which is exactly why this
    survived so long.
    """

    def _peer(self, **extra):
        return {"private_key": "k" * 43 + "=",
                "peers": [dict({"public_key": "p" * 43 + "=",
                                "endpoint": "1.2.3.4:51820"}, **extra)]}

    def test_a_config_without_one_still_gets_a_keepalive(self):
        from vpngw.tunnels.wg import DEFAULT_KEEPALIVE
        text = self._setconf(wg("aa01", 1), self._peer())
        self.assertIn(f"PersistentKeepalive = {DEFAULT_KEEPALIVE}", text)

    def test_zero_is_treated_as_absent(self):
        """0 is what the importer stores when the line was missing."""
        from vpngw.tunnels.wg import DEFAULT_KEEPALIVE
        text = self._setconf(wg("aa01", 1), self._peer(keepalive=0))
        self.assertIn(f"PersistentKeepalive = {DEFAULT_KEEPALIVE}", text)

    def test_the_provider_s_own_value_wins(self):
        text = self._setconf(wg("aa01", 1), self._peer(keepalive=15))
        self.assertIn("PersistentKeepalive = 15", text)
        self.assertNotIn("PersistentKeepalive = 25", text)


class TestAutoMtu(unittest.TestCase):
    """A chained tunnel must not be wider than the tunnel carrying it.

    1420 inside a 1380 parent comes up, handshakes, passes small packets and
    silently drops large ones. What that looks like from a chair is a download
    that runs at full speed and an upload that does not move, with nothing in
    any log to say why - so this is worth pinning.
    """

    def setUp(self):
        from vpngw.tunnels.wg import WireGuardDriver
        import vpngw.tunnels.wg as wgmod
        import vpngw.net.ifaces as ifmod

        self.drv = WireGuardDriver()
        self.mtus = {}
        self.addCleanup(setattr, wgmod.ifaces, "exists", wgmod.ifaces.exists)
        self.addCleanup(setattr, wgmod.ifaces, "mtu_of", wgmod.ifaces.mtu_of)
        wgmod.ifaces.exists = lambda n: n in self.mtus
        wgmod.ifaces.mtu_of = lambda n: self.mtus.get(n, 0)

    def test_a_chained_tunnel_shrinks_to_fit_its_parent(self):
        from vpngw.tunnels.wg import WG_OVERHEAD
        self.mtus["wg-aa01"] = 1380
        self.assertEqual(self.drv._auto_mtu(wg("bb01", 2, via="aa01")),
                         1380 - WG_OVERHEAD)

    def test_1420_stays_the_ceiling_on_a_roomy_parent(self):
        """A 1500-byte path would allow 1440; we do not take it."""
        from vpngw.tunnels.wg import DEFAULT_MTU
        self.mtus["wg-aa01"] = 1500
        self.assertEqual(self.drv._auto_mtu(wg("bb01", 2, via="aa01")),
                         DEFAULT_MTU)

    def test_a_parent_that_is_not_up_falls_back(self):
        from vpngw.tunnels.wg import DEFAULT_MTU
        self.assertEqual(self.drv._auto_mtu(wg("bb01", 2, via="aa01")),
                         DEFAULT_MTU)

    def test_never_below_the_floor(self):
        from vpngw.tunnels.wg import MIN_MTU
        self.mtus["wg-aa01"] = 600
        self.assertEqual(self.drv._auto_mtu(wg("bb01", 2, via="aa01")),
                         MIN_MTU)

    def test_an_explicit_mtu_is_never_overridden(self):
        """The operator measured something; do not argue with them."""
        self.mtus["wg-aa01"] = 1380
        t = wg("bb01", 2, via="aa01")
        t.mtu = 1200
        self.assertEqual(t.mtu or self.drv._auto_mtu(t), 1200)


class TestProbedMtu(unittest.TestCase):
    """Ask the path, because the interface cannot see past the next hop.

    A gateway whose uplink is itself a client of another gateway sits behind
    a tunnel it has no way to inspect. Locally everything says 1500; the real
    limit was 1380, and a tunnel built on the local answer was completely dead
    - not slow, dead. Measured on the reference pair: at 1420 the tunnel moved
    0.00 Mbps in both directions, at 1320 it moved 7.4.
    """

    def setUp(self):
        from vpngw.tunnels.wg import WireGuardDriver
        import vpngw.tunnels.wg as wgmod

        self.drv = WireGuardDriver()
        self.drv._probed = {}
        self.limit = 10_000        # largest outer packet the fake path passes
        self.silent = False
        self.sizes = []

        def fake_try_run(argv, **kw):
            size = int(argv[argv.index("-s") + 1]) + 28
            self.sizes.append(size)
            return type("R", (), {"ok": not self.silent and size <= self.limit})

        self.addCleanup(setattr, wgmod, "try_run", wgmod.try_run)
        wgmod.try_run = fake_try_run
        wgmod.ifaces.exists = lambda n: True
        wgmod.ifaces.mtu_of = lambda n: 1500
        self.addCleanup(setattr, wgmod.ifaces, "exists", wgmod.ifaces.exists)
        self.addCleanup(setattr, wgmod.ifaces, "mtu_of", wgmod.ifaces.mtu_of)

    def _tunnel(self):
        t = wg("bb01", 2, via="aa01")
        t.endpoints = ["203.0.113.9"]
        return t

    def test_it_finds_the_real_limit_behind_a_lying_interface(self):
        from vpngw.tunnels.wg import WG_OVERHEAD
        self.limit = 1380                       # what the reference pair had
        self.assertEqual(self._tunnel().mtu or self.drv._auto_mtu(self._tunnel()),
                         1380 - WG_OVERHEAD)    # 1320, measured by hand too

    def test_a_roomy_path_keeps_the_ceiling(self):
        from vpngw.tunnels.wg import DEFAULT_MTU
        self.limit = 1500
        self.assertEqual(self.drv._auto_mtu(self._tunnel()), DEFAULT_MTU)

    def test_a_silent_endpoint_is_not_read_as_a_tiny_path(self):
        """Plenty of hosts drop ICMP. That must not clamp the tunnel."""
        from vpngw.tunnels.wg import DEFAULT_MTU
        self.silent = True
        self.assertEqual(self.drv._auto_mtu(self._tunnel()), DEFAULT_MTU)

    def test_a_path_narrower_than_the_floor_clamps_rather_than_bisects(self):
        from vpngw.tunnels.wg import MIN_MTU
        self.limit = 900
        self.assertEqual(self.drv._auto_mtu(self._tunnel()), MIN_MTU)

    def test_the_result_is_cached_per_endpoint(self):
        self.limit = 1380
        t = self._tunnel()
        self.drv._auto_mtu(t)
        first = len(self.sizes)
        self.drv._auto_mtu(t)
        self.assertEqual(len(self.sizes), first, "re-probed a known endpoint")
        t.endpoints = ["203.0.113.10"]          # provider moved us
        self.drv._auto_mtu(t)
        self.assertGreater(len(self.sizes), first, "did not re-probe a new one")

    def test_probing_is_bounded(self):
        self.limit = 1380
        self.drv._auto_mtu(self._tunnel())
        self.assertLess(len(self.sizes), 12,
                        "too many pings at tunnel bring-up")


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


class TestImportBornChained(unittest.TestCase):
    """A tunnel that is to be chained must never be enabled unchained.

    The reason is one packet: an enabled, unchained tunnel handshakes over
    the uplink on the reconcile loop's next pass, and the new provider's
    relay logs the real address. For a double VPN that is the single thing
    the operator was avoiding, and no later chaining takes the record back.
    So the import creates it disabled, chains it, and only then enables it -
    inside one request, where no reconcile pass can see the gap.
    """

    def test_the_import_handler_enables_only_after_chaining(self):
        import re
        from pathlib import Path

        api = (Path(__file__).resolve().parent.parent / "vpngw" / "api.py"
               ).read_text(encoding="utf-8")
        m = re.search(r'@app\.post\("/api/tunnels/import"\)(.*?)'
                      r'(?=\n    @app\.)', api, re.S)
        self.assertIsNotNone(m, "no import route")
        body = m.group(1)

        self.assertIn("enabled=not via", body,
                      "import does not create a to-be-chained tunnel disabled")
        create = body.index("db.add_tunnel")
        enable = body.find("tunnel.enabled = True")
        self.assertGreater(enable, create,
                           "the tunnel is enabled before it is chained")
        via_set = body.find("tunnel.via =")
        self.assertLess(via_set, enable,
                        "via is assigned after enabling - leaves a live window")

    def test_a_refused_chain_leaves_the_tunnel_switched_off(self):
        """Refusing the chain must not fall back to an unchained, live
        tunnel: that is the leak with extra steps."""
        import re
        from pathlib import Path

        api = (Path(__file__).resolve().parent.parent / "vpngw" / "api.py"
               ).read_text(encoding="utf-8")
        m = re.search(r'@app\.post\("/api/tunnels/import"\)(.*?)'
                      r'(?=\n    @app\.)', api, re.S)
        body = m.group(1)
        guard = re.search(r"except ValidationError as exc:(.*?)raise HTTPException",
                          body, re.S)
        self.assertIsNotNone(guard, "no validation guard around via")
        self.assertNotIn("tunnel.enabled = True", guard.group(1),
                         "the failure path enables the tunnel anyway")
