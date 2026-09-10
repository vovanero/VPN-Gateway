"""NordVPN (NordLynx).

Publishes its whole catalogue without authentication, with each server's
WireGuard public key buried in a technologies/metadata list. NordLynx hands
every client the same tunnel address, so a private key on its own is enough
to build a tunnel.

Getting that key used to be the hard part. This plugin asks for an access
token instead and fetches the key itself: /v1/users/services/credentials
returns the NordLynx key to anyone holding the account's token, and the
token is a string you copy out of the Nord account page. The alternative -
install NordVPN's own client on some other machine, connect it, and read the
key out of the running interface with `wg show nordlynx private-key` - is
still accepted for operators who already have the key, but nobody should
have to do it.

The token is used once and dropped. It can manage the account; the key it
buys can only build a tunnel, and the tunnel is all this box needs.
"""

from __future__ import annotations

import base64
import string

from ..models import TunnelKind
from . import register
from .base import AuthField, Location, ProviderError
from .catalogue import CatalogueProvider, KEY_LENGTH

API = "https://api.nordvpn.com"


class NordVpn(CatalogueProvider):
    id = "nordvpn"
    name = "NordVPN"
    api_hosts = ["api.nordvpn.com"]
    # NordLynx assigns the same address to everyone; nothing to negotiate.
    fixed_address = "10.5.0.2/32"
    default_dns = ["103.86.96.100", "103.86.99.100"]
    wg_mtu = 1420
    help_url = "https://support.nordvpn.com/"
    notes = (
        "Paste an access token and the NordLynx key is fetched for you. "
        "The token is used once and not stored; the whole server catalogue "
        "is public, so nothing else needs your account."
    )
    auth_fields = [
        AuthField(
            key="token", label="Access token", secret=True,
            help="Nord account page → Services → NordVPN → "
                 "Manual setup → Generate new token. Used once to fetch "
                 "your NordLynx key, then discarded.",
            placeholder="a1b2c3…"),
        AuthField(
            key="private_key", label="WireGuard private key", secret=True,
            required=False,
            help="Optional, and only if you already have it - leave empty "
                 "and the token above is enough.",
            placeholder="wIeB…="),
    ]

    # -- auth ---------------------------------------------------------------

    def login(self, credentials: dict[str, str]):
        """Turn an access token into the NordLynx key, once.

        ``credentials`` is the dict the caller goes on to store, so the key
        is written into it and the token taken back out: what lands in
        /etc/vpngw/secrets is the same private key this plugin has always
        used, and never the more powerful credential that bought it.
        """
        key = (credentials.get("private_key") or "").strip()
        if not key:
            token = (credentials.get("token") or "").strip()
            if not token:
                raise ProviderError(
                    "an access token is required - generate one on the Nord "
                    "account page under Services > NordVPN > Manual setup"
                )
            credentials["private_key"] = self._key_for_token(token)
        credentials.pop("token", None)
        return super().login(credentials)

    def _key_for_token(self, token: str) -> str:
        """Ask NordVPN for this account's NordLynx key.

        Basic auth with the literal username "token" is what their API wants
        here; it is not a bearer header, which is why base.request grew the
        `auth` escape hatch.
        """
        basic = base64.b64encode(f"token:{token}".encode()).decode()
        data = self.request(f"{API}/v1/users/services/credentials",
                            auth=f"Basic {basic}")
        if not isinstance(data, dict):
            raise ProviderError(
                "NordVPN accepted the token but the reply was not the "
                "expected object"
            )

        key = str(data.get("nordlynx_private_key") or "").strip()
        if _is_wireguard_key(key):
            return key
        # Field names are not a contract. If the documented one is gone or
        # renamed, the key is still recognisable by its shape, and finding it
        # that way beats failing on a rename.
        for value in data.values():
            if isinstance(value, str) and _is_wireguard_key(value.strip()):
                return value.strip()

        # Names only. The values here include the OpenVPN password.
        raise ProviderError(
            "NordVPN accepted the token but sent no NordLynx key back "
            "(fields: " + ", ".join(sorted(data)) + "). Your plan may not "
            "include NordLynx, or the token may be scoped to something else. "
            "You can paste the key directly in the field below instead."
        )

    def fetch_catalogue(self) -> list[Location]:
        servers = self.request(
            f"{API}/v1/servers"
            "?limit=8000"
            "&filters[servers_technologies][identifier]=wireguard_udp"
        ) or []

        out: list[Location] = []
        for s in servers:
            if s.get("status") != "online" or not s.get("station"):
                continue
            pubkey = self._pubkey(s)
            if not pubkey:
                continue
            country, city, code = self._where(s)
            out.append(Location(
                id=s.get("hostname", str(s.get("id", ""))),
                country=country, city=city,
                hostname=s.get("hostname", ""),
                address=s["station"],
                kind=TunnelKind.WIREGUARD,
                pubkey=pubkey,
                port=self.wg_port,
                extra={"country_code": code, "load": s.get("load"),
                       "name": s.get("name", "")},
            ))
        return out

    @staticmethod
    def _pubkey(server: dict) -> str:
        for tech in server.get("technologies", []):
            if tech.get("identifier") != "wireguard_udp":
                continue
            for meta in tech.get("metadata", []):
                if meta.get("name") == "public_key":
                    return meta.get("value", "")
        return ""

    @staticmethod
    def _where(server: dict) -> tuple[str, str, str]:
        for loc in server.get("locations", []):
            country = loc.get("country", {})
            city = country.get("city", {})
            return (country.get("name", "?"), city.get("name", "?"),
                    (country.get("code", "") or "").lower())
        return "?", "?", ""


def _is_wireguard_key(value: str) -> bool:
    """A base64-encoded 32-byte key, which is what both ends of this deal in."""
    return (len(value) == KEY_LENGTH and value.endswith("=")
            and set(value) <= set(string.ascii_letters + string.digits + "+/="))


register(NordVpn())
