"""Panel authentication.

The firewall is the primary control here, but a second lock is only worth
having if it actually locks - so these check the properties that make it one:
a stored password that cannot be reversed, a comparison that does not leak,
sessions that expire and can be revoked, and a change of password that
invalidates what came before it.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpngw import auth, config  # noqa: E402
from vpngw.db import Database  # noqa: E402


class FakeDb:
    def __init__(self):
        self.kv = {}
        self.events = []

    def get(self, key, default=None):
        return self.kv.get(key, default)

    def set(self, key, value):
        self.kv[key] = value

    def log_event(self, level, source, message):
        self.events.append((level, source, message))


class TestPasswordHashing(unittest.TestCase):
    def test_round_trip(self):
        stored = auth.hash_password("a decent passphrase")
        self.assertTrue(auth.verify_password("a decent passphrase", stored))
        self.assertFalse(auth.verify_password("a decent passphras", stored))

    def test_plaintext_never_appears_in_the_stored_form(self):
        secret = "hunter2-hunter2"
        stored = auth.hash_password(secret)
        self.assertNotIn(secret, stored)
        self.assertTrue(stored.startswith("scrypt$"))

    def test_same_password_hashes_differently_each_time(self):
        # A per-password salt: without one, two accounts with the same password
        # are visibly the same, and one cracked hash cracks both.
        a = auth.hash_password("the same password")
        b = auth.hash_password("the same password")
        self.assertNotEqual(a, b)
        self.assertTrue(auth.verify_password("the same password", a))
        self.assertTrue(auth.verify_password("the same password", b))

    def test_short_passwords_are_refused(self):
        with self.assertRaises(auth.AuthError):
            auth.hash_password("short")

    def test_garbage_stored_value_fails_closed(self):
        for broken in ("", "not-a-hash", "scrypt$bad", "md5$1$2$3$4$5"):
            with self.subTest(stored=broken):
                self.assertFalse(auth.verify_password("anything", broken))


class TestSessions(unittest.TestCase):
    def setUp(self):
        self.s = auth.Sessions()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _db(self, name):
        """A throwaway database. Closed on teardown - Windows will not delete
        a sqlite file that is still open."""
        db = Database(Path(self.tmp.name) / name)
        self.addCleanup(db.close)
        return db

    def test_issue_and_validate(self):
        token = self.s.issue()
        self.assertTrue(self.s.valid(token))

    def test_unknown_and_empty_tokens_are_rejected(self):
        self.s.issue()
        for bad in (None, "", "made-up"):
            with self.subTest(token=bad):
                self.assertFalse(self.s.valid(bad))

    def test_tokens_are_not_guessable(self):
        tokens = {self.s.issue() for _ in range(20)}
        self.assertEqual(len(tokens), 20)
        self.assertTrue(all(len(t) >= 32 for t in tokens))

    def test_revoke(self):
        token = self.s.issue()
        self.s.revoke(token)
        self.assertFalse(self.s.valid(token))

    def test_expiry(self):
        token = self.s.issue()
        self.s._tokens[self.s._key(token)] = time.time() - 1
        self.assertFalse(self.s.valid(token))

    def test_a_restart_does_not_sign_the_operator_out(self):
        """The reason this store is on disk at all.

        Restarting the daemon - an upgrade, a settings change, a crash - used
        to evict every session, which reads to the operator as the panel
        logging them out at random.
        """
        db = self._db("sessions.db")
        first = auth.Sessions(db)
        token = first.issue()

        restarted = auth.Sessions(db)
        self.assertTrue(restarted.valid(token))

    def test_only_a_hash_of_the_token_is_stored(self):
        db = self._db("hashes.db")
        token = auth.Sessions(db).issue()
        stored = list(db.sessions_load())
        self.assertTrue(stored)
        self.assertNotIn(token, stored)

    def test_expired_sessions_are_not_adopted_after_a_restart(self):
        db = self._db("stale.db")
        first = auth.Sessions(db)
        token = first.issue()
        db.session_put(first._key(token), time.time() - 1)

        self.assertFalse(auth.Sessions(db).valid(token))

    def test_a_password_change_signs_out_stored_sessions_too(self):
        db = self._db("revoke.db")
        first = auth.Sessions(db)
        token = first.issue()
        first.revoke_all()

        self.assertFalse(auth.Sessions(db).valid(token))

    def test_revoke_all_signs_everyone_out(self):
        tokens = [self.s.issue() for _ in range(3)]
        self.s.revoke_all()
        for t in tokens:
            self.assertFalse(self.s.valid(t))

    def test_throttle_after_repeated_failures(self):
        for _ in range(4):
            self.s.note_failure("10.0.0.5")
        self.assertEqual(self.s.throttled("10.0.0.5"), 0)
        self.s.note_failure("10.0.0.5")
        self.assertGreater(self.s.throttled("10.0.0.5"), 0)

    def test_throttling_is_per_source(self):
        for _ in range(6):
            self.s.note_failure("10.0.0.5")
        self.assertGreater(self.s.throttled("10.0.0.5"), 0)
        self.assertEqual(self.s.throttled("10.0.0.9"), 0)


class TestDbIntegration(unittest.TestCase):
    def setUp(self):
        self.db = FakeDb()

    def test_unconfigured_gateway(self):
        self.assertFalse(auth.is_configured(self.db))
        self.assertFalse(auth.check_password(self.db, "anything"))

    def test_set_then_check(self):
        auth.set_password(self.db, "a decent passphrase")
        self.assertTrue(auth.is_configured(self.db))
        self.assertTrue(auth.check_password(self.db, "a decent passphrase"))
        self.assertFalse(auth.check_password(self.db, "something else"))

    def test_password_change_is_logged(self):
        auth.set_password(self.db, "a decent passphrase")
        self.assertTrue(any("password" in m for _, _, m in self.db.events))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestLocalToken(unittest.TestCase):
    """The credential that keeps vpngwctl working once a password is set.

    Without it, `vpngwctl passwd` - the documented way back in after a
    forgotten panel password - would itself be locked behind that password.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._saved = config.LOCAL_TOKEN
        config.LOCAL_TOKEN = Path(self.tmp.name) / "secrets" / "local.token"
        self.addCleanup(lambda: setattr(config, "LOCAL_TOKEN", self._saved))

    def test_created_on_first_use_and_then_stable(self):
        first = config.local_token()
        self.assertTrue(first)
        self.assertEqual(first, config.local_token())

    @unittest.skipIf(os.name == "nt", "Windows does not carry POSIX mode bits")
    def test_readable_only_by_its_owner(self):
        config.local_token()
        mode = config.LOCAL_TOKEN.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600, f"token file is mode {mode:o}")

    def test_survives_a_trailing_newline(self):
        config.LOCAL_TOKEN.parent.mkdir(parents=True, exist_ok=True)
        config.LOCAL_TOKEN.write_text("abc123\n")
        self.assertEqual(config.local_token(), "abc123")

    def test_an_empty_file_is_replaced_rather_than_trusted(self):
        """An empty token must never authenticate anything."""
        config.LOCAL_TOKEN.parent.mkdir(parents=True, exist_ok=True)
        config.LOCAL_TOKEN.write_text("   \n")
        self.assertTrue(len(config.local_token()) > 20)
