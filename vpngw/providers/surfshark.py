"""Surfshark.

The cluster list is public and carries each server's WireGuard public key. The
key pair and tunnel address come from the Surfshark account area's manual
setup section.
"""

from __future__ import annotations

from ..models import TunnelKind
from . import register
from .base import Location
from .catalogue import CatalogueProvider, address_field, wireguard_key_field

API = "https://api.surfshark.com"


class Surfshark(CatalogueProvider):
    id = "surfshark"
    name = "Surfshark"
    api_hosts = ["api.surfshark.com"]
    default_dns = ["162.252.172.57", "149.154.159.92"]
    wg_mtu = 1420
    help_url = "https://my.surfshark.com/vpn/manual-setup/main"
    notes = (
        "Public server catalogue. Generate a WireGuard key pair under Manual "
        "setup in your Surfshark account and paste the private key here."
    )
    auth_fields = [
        wireguard_key_field(
            "Account -> VPN -> Manual setup -> WireGuard. Generate a key pair "
            "and copy the private key.",
            "cD4f…="),
        address_field(
            "The address Surfshark shows for that key.",
            "10.14.0.2/16"),
    ]

    def fetch_catalogue(self) -> list[Location]:
        clusters = self.request(
            f"{API}/v4/server/clusters/generic?countryCode=") or []
        out: list[Location] = []
        for c in clusters:
            host = c.get("connectionName")
            pubkey = c.get("pubKey")
            if not host or not pubkey:
                continue
            out.append(Location(
                id=host,
                country=c.get("country", "?"),
                city=c.get("location", "?"),
                hostname=host,
                # Surfshark publishes a hostname rather than an address; the
                # importer resolves it, and the resolved address is what goes
                # into the firewall allowlist.
                address=host,
                kind=TunnelKind.WIREGUARD,
                pubkey=pubkey,
                port=self.wg_port,
                extra={"country_code": (c.get("countryCode", "") or "").lower(),
                       "load": c.get("load"),
                       "region": c.get("region", "")},
            ))
        return out


register(Surfshark())
