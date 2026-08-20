"""Providers that publish a server catalogue but not your credentials.

This covers most of the market. NordVPN, IVPN and Surfshark all publish their
full server list - including each server's WireGuard public key - without
authentication, but none of them documents a way to fetch *your* private key.
That comes from their app or account area.

So the split is: the plugin fetches the catalogue, and you paste the key once.
The alternative would be reverse-engineering an undocumented endpoint and
shipping code that breaks silently the first time they change it, which is
worse than an honest manual step - a tunnel that quietly stops being
provisioned looks exactly like one that was never configured.

Adding another provider of this shape means subclassing :class:`CatalogueProvider`
and writing one method: turn their JSON into ``Location`` objects.
"""

from __future__ import annotations

import logging

from ..models import TunnelKind
from .base import AuthField, Location, Provider, ProviderError, RemoteTunnel, Session

log = logging.getLogger("vpngw.provider.catalogue")

KEY_LENGTH = 44   # base64 of 32 bytes, including the '=' padding


def wireguard_key_field(help_text: str, placeholder: str = "wIeB…=") -> AuthField:
    return AuthField(key="private_key", label="WireGuard private key",
                     secret=True, help=help_text, placeholder=placeholder)


def address_field(help_text: str, placeholder: str = "10.0.0.2/32") -> AuthField:
    return AuthField(key="address", label="Tunnel address", secret=False,
                     help=help_text, placeholder=placeholder)


class CatalogueProvider(Provider):
    """Public server list, operator-supplied key."""

    credential_mode = "wireguard_key"
    locations_need_auth = False
    supports = [TunnelKind.WIREGUARD]

    #: Set when the provider assigns every client the same tunnel address, so
    #: the operator only has to supply a key.
    fixed_address: str = ""
    default_dns: list[str] = []
    wg_port: int = 51820
    wg_mtu: int = 1420

    # -- auth ---------------------------------------------------------------

    def login(self, credentials: dict[str, str]) -> Session:
        """No network call: there is nothing to authenticate against.

        The key's shape is checked here so a typo surfaces now rather than as a
        tunnel that builds cleanly and never completes a handshake - which is a
        much harder thing to diagnose.
        """
        key = (credentials.get("private_key") or "").strip()
        if not key:
            raise ProviderError("a WireGuard private key is required")
        if len(key) != KEY_LENGTH or not key.endswith("="):
            raise ProviderError(
                f"that does not look like a WireGuard key: expected "
                f"{KEY_LENGTH} base64 characters ending in '=', got {len(key)}"
            )
        if not self.fixed_address:
            address = (credentials.get("address") or "").strip()
            if not address:
                raise ProviderError(
                    f"{self.name} assigns each key its own tunnel address; "
                    f"copy it from the same page you copied the key from"
                )
            if "/" not in address:
                raise ProviderError(
                    f"the tunnel address needs a prefix length, "
                    f"e.g. {address}/32"
                )
        return Session(token="local", expires_at=0)

    def account_info(self, session: Session) -> dict:
        return {"credentials": "stored locally; the provider is never asked "
                               "for them"}

    # -- catalogue ----------------------------------------------------------

    def fetch_catalogue(self) -> list[Location]:  # pragma: no cover - abstract
        raise NotImplementedError

    def locations(self, session: Session | None = None) -> list[Location]:
        out = self.fetch_catalogue()
        out.sort(key=lambda l: (l.country.lower(), l.city.lower(), l.id))
        log.info("%s: %d wireguard servers", self.id, len(out))
        return out

    # -- provisioning -------------------------------------------------------

    def provision(
        self, session: Session, location: Location, kind: TunnelKind
    ) -> RemoteTunnel:
        if kind is not TunnelKind.WIREGUARD:
            raise ProviderError(
                f"This plugin builds WireGuard tunnels. For {self.name} over "
                f"OpenVPN, download their config bundle and use bulk import."
            )
        if not location.pubkey:
            raise ProviderError(
                f"server {location.id} published no WireGuard public key"
            )

        from .store import load_credentials

        credentials = load_credentials(self.id) or {}
        private_key = (credentials.get("private_key") or "").strip()
        if not private_key:
            raise ProviderError(
                f"no {self.name} key stored; connect the account first"
            )
        address = self.fixed_address or (credentials.get("address") or "").strip()
        if not address:
            raise ProviderError(f"no tunnel address stored for {self.name}")

        return RemoteTunnel(
            kind=TunnelKind.WIREGUARD,
            private_key=private_key,
            addresses=[address],
            peer_pubkey=location.pubkey,
            endpoint=f"{location.address}:{location.port or self.wg_port}",
            dns=list(self.default_dns),
            mtu=self.wg_mtu,
            notes=f"{location.city}, {location.country} ({location.id})",
        )
