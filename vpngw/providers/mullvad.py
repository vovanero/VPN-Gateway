"""Mullvad.

The one commercial provider whose API is fully usable from public
documentation: the relay list needs no authentication at all, and account
access is a single number rather than a username/password pair.

The provisioning flow is:

  1. exchange the account number for a short-lived access token
  2. generate a WireGuard keypair *locally* - the private key never leaves
     this machine and is never sent to Mullvad
  3. register the public key as a "device", which returns the tunnel address
     Mullvad assigned to it
  4. combine that with a relay's public key and address from the public list

Step 2 matters: what gets uploaded is the public half. A provider integration
that generated keys server-side would be handing over the ability to decrypt.
"""

from __future__ import annotations

import logging
from datetime import datetime

from ..models import TunnelKind
from . import register
from .base import AuthField, Location, Provider, ProviderError, RemoteTunnel, Session

log = logging.getLogger("vpngw.provider.mullvad")

API = "https://api.mullvad.net"

# Inside a Mullvad tunnel this is the resolver; using anything else leaks the
# lookups to a third party even though the packets stay encrypted.
MULLVAD_DNS = "10.64.0.1"
WG_PORT = 51820
# Mullvad's own recommendation. The default 1420 fragments on several of their
# transit paths, which shows up as "works, but large downloads stall".
WG_MTU = 1380


class Mullvad(Provider):
    id = "mullvad"
    name = "Mullvad"
    api_hosts = ["api.mullvad.net"]
    supports = [TunnelKind.WIREGUARD]
    device_limit = 5
    locations_need_auth = False      # /www/relays/ is public
    credential_mode = "api"
    help_url = "https://mullvad.net/account"
    notes = (
        "Account number only - no username or password. WireGuard is "
        "provisioned through the API; Mullvad's OpenVPN service is being "
        "retired, so import any .ovpn files you still need as a bundle."
    )
    auth_fields = [
        AuthField(
            key="account_number",
            label="Hesap numarası",
            secret=True,
            help="Mullvad hesabınızdaki 16 haneli numara. Kullanıcı adı ve "
                 "parola yoktur.",
            placeholder="1234567890123456",
        ),
    ]

    # -- auth ---------------------------------------------------------------

    def login(self, credentials: dict[str, str]) -> Session:
        account = (credentials.get("account_number") or "").strip().replace(" ", "")
        if not account:
            raise ProviderError("account number is required")
        if not account.isdigit():
            raise ProviderError(
                "a Mullvad account number is all digits - this looks like "
                "something else"
            )

        data = self.request(
            f"{API}/auth/v1/token",
            method="POST",
            payload={"account_number": account},
        )
        token = (data or {}).get("access_token")
        if not token:
            raise ProviderError("Mullvad returned no access token")

        session = Session(token=token)
        expiry = (data or {}).get("expiry")
        if expiry:
            try:
                session.expires_at = datetime.fromisoformat(
                    expiry.replace("Z", "+00:00")
                ).timestamp()
            except ValueError:
                pass
        return session

    def account_info(self, session: Session) -> dict:
        data = self.request(
            f"{API}/accounts/v1/accounts/me", token=session.token
        ) or {}
        return {
            "expires": data.get("expiry", ""),
            "max_devices": data.get("max_devices", self.device_limit),
            "can_add_devices": data.get("can_add_devices"),
        }

    # -- catalogue ----------------------------------------------------------

    def locations(self, session: Session | None = None) -> list[Location]:
        """The relay list is public - no session needed, and none is sent."""
        relays = self.request(f"{API}/www/relays/wireguard/") or []
        out: list[Location] = []
        for r in relays:
            if not r.get("active") or not r.get("ipv4_addr_in"):
                continue
            out.append(Location(
                id=r["hostname"],
                country=r.get("country_name", "?"),
                city=r.get("city_name", "?"),
                hostname=r.get("fqdn", r["hostname"]),
                address=r["ipv4_addr_in"],
                kind=TunnelKind.WIREGUARD,
                pubkey=r.get("pubkey", ""),
                port=WG_PORT,
                owned=bool(r.get("owned")),
                extra={
                    "provider": r.get("provider", ""),
                    "speed_gbps": r.get("network_port_speed"),
                    "daita": bool(r.get("daita")),
                    "country_code": r.get("country_code", ""),
                    "city_code": r.get("city_code", ""),
                },
            ))
        out.sort(key=lambda l: (l.country.lower(), l.city.lower(), l.id))
        log.info("mullvad: %d active wireguard relays", len(out))
        return out

    # -- devices ------------------------------------------------------------

    def devices(self, session: Session) -> list[dict]:
        data = self.request(
            f"{API}/accounts/v1/devices", token=session.token
        ) or []
        return [
            {
                "id": d.get("id", ""),
                "name": d.get("name", ""),
                "pubkey": d.get("pubkey", ""),
                "created": d.get("created", ""),
                "ipv4": d.get("ipv4_address", ""),
            }
            for d in data
        ]

    def remove_device(self, session: Session, device_id: str) -> None:
        self.request(
            f"{API}/accounts/v1/devices/{device_id}",
            method="DELETE",
            token=session.token,
        )
        log.info("mullvad: removed device %s", device_id)

    # -- provisioning -------------------------------------------------------

    def provision(
        self, session: Session, location: Location, kind: TunnelKind
    ) -> RemoteTunnel:
        if kind is not TunnelKind.WIREGUARD:
            raise ProviderError(
                "Mullvad's API provisions WireGuard only. For OpenVPN, "
                "download the config bundle from mullvad.net and import it "
                "with 'vpngwctl tunnel import-bundle'."
            )
        if not location.pubkey:
            raise ProviderError(
                f"relay {location.id} has no public key in the relay list"
            )

        from ..tunnels.wg import genkey

        # Generated here. Only the public half is uploaded.
        private_key, public_key = genkey()

        existing = self.devices(session)
        if self.device_limit and len(existing) >= self.device_limit:
            names = ", ".join(f"{d['name']} ({d['id'][:8]})" for d in existing)
            raise ProviderError(
                f"this Mullvad account already has {len(existing)} of "
                f"{self.device_limit} devices registered: {names}.\n"
                f"Remove one with 'vpngwctl provider device rm mullvad <id>' "
                f"before adding another tunnel."
            )

        device = self.request(
            f"{API}/accounts/v1/devices",
            method="POST",
            token=session.token,
            # hijack_dns is Mullvad's own DNS interception. Left off: this
            # gateway already intercepts every client lookup and routes it
            # through the tunnel's own resolver, and two layers of hijacking
            # make a leak harder to reason about, not easier.
            payload={"pubkey": public_key, "hijack_dns": False},
        ) or {}

        address = device.get("ipv4_address")
        if not address:
            raise ProviderError(
                "Mullvad registered the key but returned no tunnel address"
            )

        log.info("mullvad: registered device %s at %s",
                 device.get("name", "?"), address)

        return RemoteTunnel(
            kind=TunnelKind.WIREGUARD,
            private_key=private_key,
            addresses=[address],
            peer_pubkey=location.pubkey,
            endpoint=f"{location.address}:{location.port or WG_PORT}",
            dns=[MULLVAD_DNS],
            mtu=WG_MTU,
            remote_id=device.get("id", ""),
            notes=f"{location.city}, {location.country} ({location.id})",
        )


register(Mullvad())
