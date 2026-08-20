"""Panel authentication.

The firewall is still the primary control: the API listens only where the input
chain admits it, and no password makes an exposed panel safe. This is the
second lock, for the case the management segment has other machines on it, or
somebody widens admin_cidr and forgets.

Passwords are hashed with scrypt and compared in constant time. Sessions live
in memory only - a restart logs everyone out, which for a gateway is the right
default: the session store should not outlive the process that issued them.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time

log = logging.getLogger("vpngw.auth")

PASSWORD_KEY = "admin_password"
SESSION_TTL = 12 * 3600
# scrypt's cost is 128 * N * r bytes: 32MB here, about 50ms. Strong enough that
# guessing against a firewalled panel is hopeless, small enough not to spike
# memory on a gateway with 2GB. maxmem must be passed explicitly - OpenSSL
# defaults to a 32MB ceiling and refuses anything at or above it, which shows
# up as "memory limit exceeded" rather than as a parameter problem.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
SCRYPT_MAXMEM = 96 * 1024 * 1024
MIN_LENGTH = 8


class AuthError(ValueError):
    """A message safe to show the person who just failed to log in."""


def hash_password(password: str) -> str:
    if len(password) < MIN_LENGTH:
        raise AuthError(
            f"the password must be at least {MIN_LENGTH} characters"
        )
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N,
                            r=SCRYPT_R, p=SCRYPT_P, dklen=32,
                            maxmem=SCRYPT_MAXMEM)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt_hex),
            n=int(n), r=int(r), p=int(p), dklen=len(digest_hex) // 2,
            maxmem=SCRYPT_MAXMEM)
    except (ValueError, TypeError):
        return False
    # Constant time: a comparison that returns early leaks how much of the
    # hash matched, one byte at a time.
    return hmac.compare_digest(digest.hex(), digest_hex)


class Sessions:
    """Panel sessions: a sliding expiry, persisted so restarts do not evict.

    Keyed by a hash of the token rather than the token itself. The store is
    written through to the database on every issue and on renewals that move
    the expiry meaningfully, so an upgrade or a crash does not throw the
    operator back to the login screen - which, on a box whose panel is the
    only comfortable way to manage the kill switch, is more than an
    inconvenience.
    """

    #: Renewals inside this many seconds of the stored expiry are kept in
    #: memory only. Without it every polled request would write to sqlite.
    RENEW_SLACK = 300

    def __init__(self, db=None) -> None:
        self._tokens: dict[str, float] = {}
        self._persisted: dict[str, float] = {}
        self._failures: dict[str, list[float]] = {}
        self._db = None
        if db is not None:
            self.bind(db)

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def bind(self, db) -> None:
        """Adopt the sessions already on disk and write through from now on."""
        self._db = db
        try:
            self._tokens = db.sessions_load()
        except Exception:  # a database too old to have the table
            log.warning("could not load stored sessions; starting empty",
                        exc_info=True)
            self._tokens = {}
        self._persisted = dict(self._tokens)

    def _store(self, key: str, expiry: float) -> None:
        if self._db is None:
            return
        try:
            self._db.session_put(key, expiry)
            self._persisted[key] = expiry
        except Exception:
            log.warning("could not persist session", exc_info=True)

    def issue(self) -> str:
        token = secrets.token_urlsafe(32)
        key = self._key(token)
        expiry = time.time() + SESSION_TTL
        self._tokens[key] = expiry
        self._store(key, expiry)
        self._sweep()
        return token

    def valid(self, token: str | None) -> bool:
        if not token:
            return False
        key = self._key(token)
        expiry = self._tokens.get(key)
        if expiry is None:
            return False
        now = time.time()
        if now > expiry:
            self._forget(key)
            return False
        renewed = now + SESSION_TTL
        self._tokens[key] = renewed
        if renewed - self._persisted.get(key, 0) > self.RENEW_SLACK:
            self._store(key, renewed)
        return True

    def _forget(self, key: str) -> None:
        self._tokens.pop(key, None)
        self._persisted.pop(key, None)
        if self._db is not None:
            try:
                self._db.session_drop(key)
            except Exception:
                log.warning("could not drop session", exc_info=True)

    def revoke(self, token: str | None) -> None:
        if token:
            self._forget(self._key(token))

    def revoke_all(self) -> None:
        """Used when the password changes: an old session must not outlive the
        credential it was issued against."""
        self._tokens.clear()
        self._persisted.clear()
        if self._db is not None:
            try:
                self._db.sessions_clear()
            except Exception:
                log.warning("could not clear sessions", exc_info=True)

    def _sweep(self) -> None:
        now = time.time()
        for key, expiry in list(self._tokens.items()):
            if now > expiry:
                self._forget(key)

    # -- rate limiting ------------------------------------------------------

    def note_failure(self, source: str) -> None:
        now = time.time()
        window = [t for t in self._failures.get(source, []) if now - t < 300]
        window.append(now)
        self._failures[source] = window

    def throttled(self, source: str) -> int:
        """Seconds the caller must wait, or 0.

        Five wrong guesses buys a pause. Not a lockout - locking an admin out
        of the only management path to a fail-closed gateway is a worse outcome
        than a slow brute force against a firewalled port.
        """
        now = time.time()
        window = [t for t in self._failures.get(source, []) if now - t < 300]
        self._failures[source] = window
        if len(window) < 5:
            return 0
        return max(1, int(30 - (now - window[-1])))


def is_configured(db) -> bool:
    return bool(db.get(PASSWORD_KEY))


def set_password(db, password: str) -> None:
    db.set(PASSWORD_KEY, hash_password(password))
    db.log_event("warning", "auth", "admin password changed")
    log.warning("admin password changed")


def check_password(db, password: str) -> bool:
    stored = db.get(PASSWORD_KEY)
    if not stored:
        return False
    return verify_password(password, stored)
