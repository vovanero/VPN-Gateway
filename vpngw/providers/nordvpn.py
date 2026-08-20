"""NordVPN (NordLynx).

Publishes its whole catalogue without authentication, with each server's
WireGuard public key buried in a technologies/metadata list. NordLynx hands
every client the same tunnel address, so a private key on its own is enough -
which makes this the least fiddly of the catalogue providers to set up.
"""

from __future__ import annotations

from ..models import TunnelKind
from . import register
from .base import Location
from .catalogue import CatalogueProvider, wireguard_key_field

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
        "Public server catalogue. NordVPN does not document a way to fetch "
        "your NordLynx key, so paste it once - everything after that is "
        "automatic."
    )
    auth_fields = [
        wireguard_key_field(
            "On a machine running the NordVPN app: connect once, then run "
            "`sudo wg show nordlynx private-key`.",
            "wIeB…="),
    ]

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


register(NordVpn())
