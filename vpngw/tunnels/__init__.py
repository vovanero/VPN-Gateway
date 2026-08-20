"""Tunnel drivers.

Both drivers deliberately refuse to install routes into the *main* table. A
tunnel's default route exists only inside its own policy table, next to the
blackhole. That is why bringing a tunnel up can never accidentally start
routing the gateway's own traffic, and why a tunnel dying can never fall the
clients back onto the uplink.
"""

from .base import LinkInfo, TunnelDriver, driver_for

__all__ = ["LinkInfo", "TunnelDriver", "driver_for"]
