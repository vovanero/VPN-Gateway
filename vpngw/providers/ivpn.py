"""IVPN.

Publishes the complete WireGuard catalogue at /v5/servers.json, with a public
key on every host. Keys are registered in the account area, which is where the
tunnel address comes from too - IVPN assigns a different one per key, so both
have to be supplied.
"""

from __future__ import annotations

from ..models import TunnelKind
from . import register
from .base import Location
from .catalogue import CatalogueProvider, address_field, wireguard_key_field

API = "https://api.ivpn.net"


class Ivpn(CatalogueProvider):
    id = "ivpn"
    name = "IVPN"
    api_hosts = ["api.ivpn.net"]
    default_dns = ["172.16.0.1"]     # IVPN's in-tunnel resolver
    wg_mtu = 1420
    help_url = "https://www.ivpn.net/account/"
    notes = (
        "Public server catalogue. Add a key in the IVPN account area under "
        "WireGuard; it gives you both the key and the address to paste here."
    )
    auth_fields = [
        wireguard_key_field(
            "Account area -> WireGuard -> Add a new key. Copy the private key "
            "it generates.",
            "aB3d…="),
        address_field(
            "The IPv4 address shown next to that key, with its prefix.",
            "172.16.0.5/32"),
    ]

    def fetch_catalogue(self) -> list[Location]:
        data = self.request(f"{API}/v5/servers.json") or {}
        out: list[Location] = []
        for gateway in data.get("wireguard", []):
            country = gateway.get("country", "?")
            city = gateway.get("city", "?")
            code = (gateway.get("country_code", "") or "").lower()
            for host in gateway.get("hosts", []):
                if not host.get("host") or not host.get("public_key"):
                    continue
                out.append(Location(
                    id=host.get("hostname") or host["host"],
                    country=country, city=city,
                    hostname=host.get("hostname", ""),
                    address=host["host"],
                    kind=TunnelKind.WIREGUARD,
                    pubkey=host["public_key"],
                    port=self.wg_port,
                    extra={"country_code": code,
                           "load": host.get("load"),
                           "isp": gateway.get("isp", "")},
                ))
        return out


register(Ivpn())
