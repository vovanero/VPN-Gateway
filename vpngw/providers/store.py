"""Where provider credentials and sessions live.

Credentials go to /etc/vpngw/secrets/ with mode 0600, created before anything
is written so there is never a moment where the file exists and is readable by
anyone else. Sessions - short-lived access tokens - go to /run, which is tmpfs,
so they do not survive a reboot and never touch the disk.

Nothing here ever logs a credential, puts one in an exception message, or
prints one back. The only way a secret leaves this module is into the request
that needs it.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import time
from pathlib import Path

from .. import config
from .base import Provider, ProviderError, Session

log = logging.getLogger("vpngw.provider.store")

SESSION_DIR = config.RUN / "providers"


def _cred_path(provider_id: str) -> Path:
    return config.SECRETS_DIR / f"provider-{provider_id}.json"


def _write_private(path: Path, text: str) -> None:
    """Delegates to the shared helper so every secret on this box is written
    the same way - created 0600, never chmod-ed after the fact."""
    config.write_secret(path, text)


# ---------------------------------------------------------------------------
# credentials
# ---------------------------------------------------------------------------


def save_credentials(provider_id: str, credentials: dict[str, str]) -> None:
    _write_private(_cred_path(provider_id), json.dumps(credentials, indent=2))
    log.info("stored credentials for %s", provider_id)


def load_credentials(provider_id: str) -> dict[str, str] | None:
    path = _cred_path(provider_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except ValueError:
        raise ProviderError(
            f"the stored credentials for {provider_id} are unreadable; "
            f"log in again"
        ) from None


def forget(provider_id: str) -> None:
    _cred_path(provider_id).unlink(missing_ok=True)
    (SESSION_DIR / f"{provider_id}.json").unlink(missing_ok=True)
    log.info("forgot credentials for %s", provider_id)


def configured() -> list[str]:
    if not config.SECRETS_DIR.exists():
        return []
    return sorted(
        p.stem[len("provider-"):]
        for p in config.SECRETS_DIR.glob("provider-*.json")
    )


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------


def _session_path(provider_id: str) -> Path:
    return SESSION_DIR / f"{provider_id}.json"


def _load_session(provider_id: str) -> Session | None:
    path = _session_path(provider_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except ValueError:
        return None
    session = Session(
        token=data.get("token", ""),
        expires_at=float(data.get("expires_at", 0) or 0),
        account=data.get("account", {}),
    )
    return session if session.valid else None


def _save_session(provider_id: str, session: Session) -> None:
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(SESSION_DIR, stat.S_IRWXU)
    _write_private(_session_path(provider_id), json.dumps({
        "token": session.token,
        "expires_at": session.expires_at,
        "account": session.account,
        "cached_at": time.time(),
    }))


def session_for(provider: Provider, *, refresh: bool = False) -> Session:
    """A valid session, from cache when possible.

    Re-authenticating on every command would be slower and would count against
    whatever rate limit the provider applies, so a token is reused until it is
    within a minute of expiring.
    """
    if not refresh:
        cached = _load_session(provider.id)
        if cached:
            return cached

    credentials = load_credentials(provider.id)
    if credentials is None:
        raise ProviderError(
            f"no credentials stored for {provider.name}. "
            f"Run 'vpngwctl provider login {provider.id}' first."
        )
    session = provider.login(credentials)
    _save_session(provider.id, session)
    return session
