"""Commercial VPN provider integrations.

Importing forty .ovpn files by hand is the single biggest day-to-day friction
in running this gateway, so providers that expose an API get a plugin that can
list their servers and provision tunnels directly.

Two rules shape everything here:

**Credentials are entered by the operator, never guessed or defaulted.** They
are written to /etc/vpngw/secrets/ with mode 0600 and are never logged, never
placed in a URL, and never sent anywhere except the provider's own API host.

**A provider's API host must be in the firewall allowlist or the call silently
fails.** Under strict host egress this gateway may only reach the VPN endpoints
it was configured with - an unlisted api.example.com is dropped by our own
output chain, with the packets landing in host_egress_drop and no obvious
cause. :func:`api_hosts` feeds that allowlist; see reconciler.refresh_endpoints.
"""

from .base import (
    AuthField,
    Location,
    Provider,
    ProviderError,
    RemoteTunnel,
    Session,
)

_REGISTRY: dict[str, Provider] = {}


def register(provider: Provider) -> Provider:
    _REGISTRY[provider.id] = provider
    return provider


def get(provider_id: str) -> Provider:
    try:
        return _REGISTRY[provider_id.strip().lower()]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY)) or "none"
        raise ProviderError(
            f"unknown provider {provider_id!r} (known: {known})"
        ) from None


def all_providers() -> list[Provider]:
    return sorted(_REGISTRY.values(), key=lambda p: p.name.lower())


def api_hosts() -> list[str]:
    """Every host any provider plugin may contact.

    The firewall allowlist is built from this. Static rather than discovered at
    call time on purpose: an allowlist that grows in response to what the code
    decides to fetch is not an allowlist.
    """
    hosts: set[str] = set()
    for p in _REGISTRY.values():
        hosts.update(p.api_hosts)
    return sorted(hosts)


# Registration happens on import; keep these at the bottom so the registry
# helpers above are defined first.
from . import ivpn, mullvad, nordvpn, surfshark  # noqa: E402,F401

__all__ = [
    "AuthField",
    "Location",
    "Provider",
    "ProviderError",
    "RemoteTunnel",
    "Session",
    "all_providers",
    "api_hosts",
    "get",
    "register",
]
