"""The provider plugin interface, and the HTTP helper every plugin uses.

Written against the standard library only. A gateway that cannot start because
a dependency failed to import is a gateway with no firewall, so the control
plane keeps its dependency surface to what Debian ships.
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ..models import TunnelKind

log = logging.getLogger("vpngw.provider")

USER_AGENT = "vpngw/0.1 (+https://github.com/local/vpngw)"
# Short on purpose. The usual reason a provider API does not answer on this box
# is our own output chain dropping the packets, and a long timeout turns that
# into a minute of silence instead of a prompt error naming the firewall.
TIMEOUT = 12


class ProviderError(RuntimeError):
    """Anything the operator needs to read: bad credentials, quota, outage."""


@dataclass
class AuthField:
    """One credential the operator has to supply.

    The UI renders these; nothing here ever invents a value. ``secret=True``
    means the field is masked on input and never echoed back, logged, or
    included in an error message.
    """

    key: str
    label: str
    secret: bool = False
    help: str = ""
    placeholder: str = ""


@dataclass
class Session:
    """An authenticated session. Short-lived, kept in tmpfs, never on disk."""

    token: str = ""
    expires_at: float = 0.0
    account: dict = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return bool(self.token) and (
            self.expires_at == 0 or time.time() < self.expires_at - 60
        )


@dataclass
class Location:
    """A server the operator can pick."""

    id: str                      # provider-unique, e.g. "nl-ams-wg-001"
    country: str
    city: str
    hostname: str
    address: str                 # IPv4 the tunnel dials
    kind: TunnelKind
    pubkey: str = ""             # WireGuard peer key, when known
    port: int = 0
    owned: bool = False          # provider-owned hardware vs rented
    extra: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"{self.city}, {self.country}"


@dataclass
class RemoteTunnel:
    """Everything needed to build a working tunnel, from the provider."""

    kind: TunnelKind
    # WireGuard
    private_key: str = ""
    addresses: list[str] = field(default_factory=list)
    peer_pubkey: str = ""
    endpoint: str = ""           # "host:port"
    dns: list[str] = field(default_factory=list)
    mtu: int = 0
    # OpenVPN
    ovpn_config: str = ""
    auth_username: str = ""
    auth_password: str = ""
    # bookkeeping so the plugin can clean up after itself
    remote_id: str = ""
    notes: str = ""


class Provider:
    """Base class. Subclasses register themselves in providers/__init__.py."""

    id: str = ""
    name: str = ""
    api_hosts: list[str] = []
    auth_fields: list[AuthField] = []
    supports: list[TunnelKind] = []
    #: providers that cap concurrent registrations (Mullvad: 5 devices)
    device_limit: int = 0
    #: False when the server catalogue is public. Browsing servers before
    #: committing to an account is genuinely useful, and sending credentials to
    #: an endpoint that does not need them is a habit worth not having.
    locations_need_auth: bool = True
    #: "api"           - the provider issues tunnel credentials over its API
    #: "wireguard_key" - the operator pastes a key obtained from the provider,
    #:                   and the plugin supplies only the server catalogue
    credential_mode: str = "api"
    help_url: str = ""
    notes: str = ""

    # -- to implement ------------------------------------------------------

    def login(self, credentials: dict[str, str]) -> Session:
        raise NotImplementedError

    def locations(self, session: Session | None = None) -> list[Location]:
        raise NotImplementedError

    def provision(
        self, session: Session, location: Location, kind: TunnelKind
    ) -> RemoteTunnel:
        raise NotImplementedError

    # -- optional ----------------------------------------------------------

    def account_info(self, session: Session) -> dict:
        return {}

    def devices(self, session: Session) -> list[dict]:
        return []

    def remove_device(self, session: Session, device_id: str) -> None:
        raise ProviderError(f"{self.name} does not support removing devices")

    # -- helpers -----------------------------------------------------------

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        token: str = "",
        payload: Any = None,
        timeout: int = TIMEOUT,
    ) -> Any:
        """One JSON request. Fails loudly and without leaking the credential.

        Provider errors carry the HTTP status and the server's message because
        "provisioning failed" with no detail is the kind of message that costs
        an hour. The Authorization header is never included in that detail.
        """
        self._assert_allowed_host(url)

        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"

        req = urllib.request.Request(url, data=data, method=method,
                                     headers=headers)
        context = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=context) as resp:
                body = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            if exc.code in (401, 403):
                raise ProviderError(
                    f"{self.name} rejected the credentials (HTTP {exc.code}). "
                    f"Check the account details and try again."
                ) from None
            raise ProviderError(
                f"{self.name} API returned HTTP {exc.code}: {detail}"
            ) from None
        except (urllib.error.URLError, socket.timeout, ssl.SSLError) as exc:
            raise ProviderError(
                f"cannot reach {self.name}'s API ({exc}).\n"
                f"With strict host egress on, this gateway may only contact "
                f"hosts in the firewall allowlist. Check that "
                f"{', '.join(self.api_hosts)} resolved and was allowed - "
                f"blocked packets land in the host_egress_drop counter."
            ) from None

        if not body.strip():
            return None
        try:
            return json.loads(body)
        except ValueError:
            return body

    def _assert_allowed_host(self, url: str) -> None:
        """A plugin may only talk to the hosts it declared.

        The firewall allowlist is built from ``api_hosts``. If a plugin were
        free to fetch elsewhere, the allowlist and the code would disagree and
        the request would be dropped with no useful error - so disagreeing is
        made a programming error instead.
        """
        from urllib.parse import urlparse

        host = urlparse(url).hostname or ""
        if host not in self.api_hosts:
            raise ProviderError(
                f"{self.name} plugin tried to contact {host!r}, which is not "
                f"in its declared api_hosts {self.api_hosts}. Add it there so "
                f"the firewall allowlist stays in step with the code."
            )
