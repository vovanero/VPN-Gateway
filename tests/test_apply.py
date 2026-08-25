"""The uplink apply path.

The dangerous part of this module is not the writing, it is what happens when
the writing is wrong: the connection being used to make the change is the one
that disappears. These tests cover the two mechanisms that make that
survivable - refusing configurations that cannot work, and restoring the
previous one afterwards.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpngw.net import apply as A  # noqa: E402


class TestValidation(unittest.TestCase):
    def test_gateway_outside_the_subnet_is_refused(self):
        """The mistake that strands a remote box: an address it can hold and a
        gateway it can never reach."""
        with self.assertRaises(A.ApplyError) as cm:
            A.validate_wan("static", "10.200.50.100/24", "192.168.9.1")
        self.assertIn("not inside", str(cm.exception))

    def test_gateway_may_not_be_the_machine_itself(self):
        with self.assertRaises(A.ApplyError):
            A.validate_wan("static", "10.200.50.1/24", "10.200.50.1")

    def test_static_needs_a_gateway(self):
        with self.assertRaises(A.ApplyError):
            A.validate_wan("static", "10.200.50.100/24", "")

    def test_prefix_with_no_room_is_refused(self):
        with self.assertRaises(A.ApplyError):
            A.validate_wan("static", "10.200.50.100/31", "10.200.50.1")

    def test_address_must_carry_a_prefix(self):
        with self.assertRaises(A.ApplyError):
            A.validate_wan("static", "10.200.50.100", "10.200.50.1")

    def test_dhcp_needs_nothing(self):
        A.validate_wan("dhcp", "", "")

    def test_a_workable_static_config_is_accepted(self):
        A.validate_wan("static", "10.200.50.100/24", "10.200.50.1")


class TestIfupdownTakeover(unittest.TestCase):
    """Debian's own interfaces file defines eth0 *and* sources interfaces.d.

    Adding a second definition there does not override the first - ifupdown
    keeps the original and ignores ours, so the address never moves while
    every step reports success. The stanza has to be disabled instead.
    """

    DEBIAN_DEFAULT = """\
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

allow-hotplug eth0
iface eth0 inet static
\taddress 100.200.50.100/24
\tgateway 100.200.50.1

auto eth1
iface eth1 inet manual
"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.main = Path(self.tmp.name) / "interfaces"
        self.main.write_text(self.DEBIAN_DEFAULT)
        self._saved = A.MAIN_INTERFACES
        A.MAIN_INTERFACES = self.main
        self.addCleanup(lambda: setattr(A, "MAIN_INTERFACES", self._saved))

    def test_a_conflicting_stanza_is_detected(self):
        self.assertTrue(A.conflicting_stanza("eth0", self.DEBIAN_DEFAULT))
        self.assertTrue(A.conflicting_stanza("eth1", self.DEBIAN_DEFAULT))
        self.assertFalse(A.conflicting_stanza("eth9", self.DEBIAN_DEFAULT))

    def test_the_uplink_stanza_is_disabled(self):
        self.assertTrue(A.take_over_ifupdown("eth0"))
        out = self.main.read_text()
        self.assertNotIn("\nallow-hotplug eth0", out)
        self.assertNotIn("\niface eth0 inet static", out)
        self.assertIn(A.TAKEOVER_MARK + "allow-hotplug eth0", out)
        self.assertIn(A.TAKEOVER_MARK + "\taddress 100.200.50.100/24", out)

    def test_other_interfaces_are_left_alone(self):
        """Disabling too much is how you lose the LAN as well as the WAN."""
        A.take_over_ifupdown("eth0")
        out = self.main.read_text()
        self.assertIn("\nauto lo\n", out)
        self.assertIn("\niface lo inet loopback", out)
        self.assertIn("\nauto eth1\n", out)
        self.assertIn("\niface eth1 inet manual", out)
        self.assertTrue(out.startswith("source /etc/network/interfaces.d/*"))

    def test_nothing_to_take_over_is_not_an_error(self):
        self.assertFalse(A.take_over_ifupdown("eth9"))
        self.assertEqual(self.main.read_text(), self.DEBIAN_DEFAULT)

    def test_running_it_twice_changes_nothing_further(self):
        A.take_over_ifupdown("eth0")
        once = self.main.read_text()
        A.take_over_ifupdown("eth0")
        self.assertEqual(self.main.read_text(), once)


class TestSnapshots(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._saved = A.BACKUP_DIR
        A.BACKUP_DIR = Path(self.tmp.name) / "backup"
        self.addCleanup(lambda: setattr(A, "BACKUP_DIR", self._saved))

    def test_every_file_comes_back(self):
        a = Path(self.tmp.name) / "a"
        b = Path(self.tmp.name) / "b"
        a.write_text("ORIGINAL A\n")
        b.write_text("ORIGINAL B\n")

        snap = A._snapshot([a, b])
        a.write_text("changed\n")
        b.write_text("also changed\n")
        A.restore_snapshot(snap)

        self.assertEqual(a.read_text(), "ORIGINAL A\n")
        self.assertEqual(b.read_text(), "ORIGINAL B\n")

    def test_a_file_that_did_not_exist_is_restored_to_empty(self):
        """Otherwise our own drop-in would survive a rollback and keep
        overriding the configuration it was supposed to give back."""
        missing = Path(self.tmp.name) / "vpngw-wan"
        snap = A._snapshot([missing])
        missing.write_text("iface eth0 inet static\n")
        A.restore_snapshot(snap)
        self.assertEqual(missing.read_text(), "")

    def test_latest_points_at_the_newest_snapshot(self):
        f = Path(self.tmp.name) / "f"
        f.write_text("x")
        snap = A._snapshot([f])
        self.assertEqual((A.BACKUP_DIR / "latest").read_text().strip(), str(snap))

    def test_restoring_without_a_manifest_is_refused(self):
        empty = Path(self.tmp.name) / "empty"
        empty.mkdir()
        with self.assertRaises(A.ApplyError):
            A.restore_snapshot(empty)


class TestRendering(unittest.TestCase):
    def test_ifupdown_static(self):
        out = A.render_ifupdown("eth0", "static", "10.200.50.100/24",
                                "10.200.50.1", ["1.1.1.1"])
        self.assertIn("iface eth0 inet static", out)
        self.assertIn("address 10.200.50.100/24", out)
        self.assertIn("gateway 10.200.50.1", out)
        self.assertIn("dns-nameservers 1.1.1.1", out)

    def test_ifupdown_dhcp_carries_no_address(self):
        out = A.render_ifupdown("eth0", "dhcp", "", "", [])
        self.assertIn("iface eth0 inet dhcp", out)
        self.assertNotIn("address", out)

    def test_networkd_static(self):
        out = A.render_networkd("eth0", "static", "10.200.50.100/24",
                                "10.200.50.1", ["1.1.1.1"])
        self.assertIn("Address=10.200.50.100/24", out)
        self.assertIn("Gateway=10.200.50.1", out)
        self.assertIn("DNS=1.1.1.1", out)

    def test_networkd_dhcp(self):
        out = A.render_networkd("eth0", "dhcp", "", "", [])
        self.assertIn("DHCP=ipv4", out)


if __name__ == "__main__":
    unittest.main()


class TestSettingsRoundTrip(unittest.TestCase):
    """Every section written has to be a section read.

    [wan] and [dhcp] were written by the panel and never parsed back, so those
    settings were write-only: saved, reported as saved, and gone on the next
    read. Nothing failed loudly - the values simply reverted to their defaults,
    which for the uplink means "use DHCP" regardless of what was asked for.
    """

    def setUp(self):
        from vpngw import config
        self.config = config
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "vpngw.toml"

    def test_every_section_survives_a_write_and_read(self):
        import dataclasses

        original = self.config.Settings()
        for name in original.__dataclass_fields__:
            with self.subTest(section=name):
                section = getattr(original, name)
                changed = self._perturb(section)
                candidate = dataclasses.replace(original, **{name: changed})
                candidate.write(self.path)
                self.assertEqual(
                    getattr(self.config.Settings.load(self.path), name), changed,
                    f"[{name}] did not survive; it is probably missing from "
                    f"Settings.load()")

    def test_the_uplink_specifically(self):
        import dataclasses

        s = self.config.Settings()
        s = dataclasses.replace(s, wan=dataclasses.replace(
            s.wan, mode="static", address="10.200.50.100/24",
            gateway="10.200.50.1"))
        s.write(self.path)

        back = self.config.Settings.load(self.path)
        self.assertEqual(back.wan.mode, "static")
        self.assertEqual(back.wan.address, "10.200.50.100/24")
        self.assertEqual(back.wan.gateway, "10.200.50.1")

    #: Sections whose fields are all constrained (addresses, networks) get an
    #: explicit change instead of a guessed one.
    OVERRIDES = {
        "NetSettings": {"lan_bridge": "br-test"},
        "WanSettings": {"mode": "static"},
        "DnsSettings": {"block_dot": True},
        "LogSettings": {"level": "high"},
    }

    @classmethod
    def _perturb(cls, section):
        """A copy of the section with one field changed away from its default.

        Booleans and integers first: they can be changed without inventing a
        value that has to stay valid, which an address or a network does not
        tolerate.
        """
        import dataclasses

        name = type(section).__name__
        if name in cls.OVERRIDES:
            return dataclasses.replace(section, **cls.OVERRIDES[name])

        fields = list(section.__dataclass_fields__)
        for wanted in (bool, int):
            for fname in fields:
                value = getattr(section, fname)
                if type(value) is wanted:
                    replacement = (not value) if wanted is bool else value + 1
                    return dataclasses.replace(section, **{fname: replacement})
        for fname in fields:
            if getattr(section, fname) == "":
                return dataclasses.replace(section, **{fname: "changed"})
        raise AssertionError(f"nothing safely perturbable in {name}")


class TestServiceConstruction(unittest.TestCase):
    """The daemon object is fully built before anything touches it.

    Nothing here previously constructed a Service, so an edit that left half
    of __init__ unreachable passed every test and only failed on the box - as
    a 500 from the status endpoint, several steps away from the cause.
    """

    def setUp(self):
        from vpngw import config, service as service_mod

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.service_mod = service_mod

        self._saved_db = config.DB_FILE
        config.DB_FILE = Path(self.tmp.name) / "vpngw.db"
        self.addCleanup(lambda: setattr(config, "DB_FILE", self._saved_db))

        self._saved_cfg = config.CONFIG_FILE
        config.CONFIG_FILE = Path(self.tmp.name) / "vpngw.toml"
        self.addCleanup(lambda: setattr(config, "CONFIG_FILE", self._saved_cfg))

    def _service(self):
        svc = self.service_mod.Service()
        self.addCleanup(svc.db.close)
        return svc

    def test_every_attribute_the_rest_of_the_daemon_uses_exists(self):
        svc = self._service()
        for name in ("settings", "db", "reconciler", "_wake", "_stop",
                     "_thread", "last_error", "started_at", "history",
                     "_prev_counters"):
            with self.subTest(attribute=name):
                self.assertTrue(hasattr(svc, name),
                                f"Service has no {name!r}; __init__ is "
                                f"probably cut short")

    def test_it_can_be_asked_to_reconcile_and_to_stop(self):
        svc = self._service()
        svc.request_reconcile()
        self.assertTrue(svc._wake.is_set())
        svc.stop()

    def test_reload_settings_picks_up_a_changed_file(self):
        import dataclasses
        from vpngw import config

        svc = self._service()
        self.assertEqual(svc.settings.wan.mode, "dhcp")

        dataclasses.replace(svc.settings, wan=dataclasses.replace(
            svc.settings.wan, mode="static", address="10.200.50.100/24",
            gateway="10.200.50.1")).write(config.CONFIG_FILE)
        svc.reload_settings()

        self.assertEqual(svc.settings.wan.mode, "static")
        self.assertEqual(svc.settings.wan.address, "10.200.50.100/24")
        self.assertIs(svc.reconciler.settings, svc.settings,
                      "the reconciler kept the old settings object")


class TestHostResolver(unittest.TestCase):
    """The gateway's own /etc/resolv.conf.

    Left to the distribution this file ends up empty: a minimal Debian has no
    resolvconf, so `dns-nameservers` in an interfaces stanza does nothing, and
    if DHCP ever runs on the uplink dhcpcd replaces the file with a template
    containing no nameserver at all. The gateway then cannot resolve the
    hostname of the next VPN endpoint it is told to connect to, and the only
    symptom is a tunnel that never comes up.
    """

    def setUp(self):
        from vpngw import dnsmgr

        self.dnsmgr = dnsmgr
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "resolv.conf"
        self._saved = dnsmgr.HOST_RESOLV
        dnsmgr.HOST_RESOLV = self.path
        self.addCleanup(lambda: setattr(dnsmgr, "HOST_RESOLV", self._saved))

    def test_it_writes_the_bootstrap_servers(self):
        self.assertTrue(self.dnsmgr.ensure_host_resolver(["8.8.8.8", "1.1.1.1"]))
        text = self.path.read_text()
        self.assertIn("nameserver 8.8.8.8", text)
        self.assertIn("nameserver 1.1.1.1", text)

    def test_it_replaces_what_dhcpcd_leaves_behind(self):
        self.path.write_text("# Generated by dhcpcd\n"
                             "# /etc/resolv.conf.head can replace this line\n")
        self.dnsmgr.ensure_host_resolver(["8.8.8.8"])
        self.assertIn("nameserver 8.8.8.8", self.path.read_text())

    def test_it_does_not_rewrite_an_already_correct_file(self):
        """The reconciler runs every few seconds; rewriting each pass would
        churn the file and the log for no reason."""
        self.assertTrue(self.dnsmgr.ensure_host_resolver(["8.8.8.8"]))
        self.assertFalse(self.dnsmgr.ensure_host_resolver(["8.8.8.8"]))

    def test_an_empty_bootstrap_list_leaves_the_file_alone(self):
        """Better a stale resolver than none: emptying this file is how a box
        loses the ability to bring any hostname-based tunnel back up."""
        self.path.write_text("nameserver 9.9.9.9\n")
        self.assertFalse(self.dnsmgr.ensure_host_resolver([]))
        self.assertEqual(self.path.read_text(), "nameserver 9.9.9.9\n")

    @unittest.skipIf(os.name == "nt", "Windows has no symlinks without privilege")
    def test_a_symlink_is_replaced_by_a_real_file(self):
        target = Path(self.tmp.name) / "elsewhere.conf"
        target.write_text("nameserver 9.9.9.9\n")
        self.path.symlink_to(target)

        self.dnsmgr.ensure_host_resolver(["8.8.8.8"])
        self.assertFalse(self.path.is_symlink())
        self.assertIn("nameserver 8.8.8.8", self.path.read_text())
        self.assertEqual(target.read_text(), "nameserver 9.9.9.9\n",
                         "wrote through the symlink instead of replacing it")
