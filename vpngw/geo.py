"""Which country an address belongs to, decided offline.

No request leaves this machine to answer the question. The alternative -
asking a web service - would mean a privacy gateway making a call about its
own exit address every time the panel refreshed, which is the sort of thing
this box exists to avoid.

The cost is honesty about the data. Debian ships the legacy GeoIP country
database, whose contents were frozen on 2019-12-24; MaxMind stopped
publishing the free replacement without a licence key. Country assignments do
move - VPN exit ranges more than most - so a lookup here can be out of date,
and there is no way for it to know that it is. It is offered as a hint beside
the address, never in place of it: the address is the fact, the country is a
label.

Nothing here raises. A gateway must not fail to render its own dashboard
because a cosmetic lookup went wrong.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from .net.shell import try_run

log = logging.getLogger("vpngw.geo")

#: geoip-bin. Present only if the operator installed it; absent is normal.
LOOKUP = "geoiplookup"
#: What geoip-database lays down. Checked directly so a missing database is
#: reported as such rather than as a mysteriously empty answer.
DATABASE = Path("/usr/share/GeoIP/GeoIP.dat")

#: `GeoIP Country Edition: PT, Portugal`
_ANSWER = re.compile(r":\s*([A-Z]{2}),\s*(.+?)\s*$", re.MULTILINE)

_cache: dict[str, tuple[str, str] | None] = {}


def available() -> bool:
    """Whether a lookup can succeed at all, without performing one."""
    return DATABASE.exists()


def country_of(ip: str) -> tuple[str, str] | None:
    """``("PT", "Portugal")`` for an address, or None.

    None covers every kind of "we do not know": no database installed, a
    private or reserved address, or a range the 2019 data never had. The
    caller shows nothing in all of those cases, which is the honest rendering
    of not knowing.
    """
    if not ip:
        return None
    if ip in _cache:
        return _cache[ip]

    answer = None
    if available():
        res = try_run([LOOKUP, "-f", str(DATABASE), ip], timeout=4)
        if res.ok:
            m = _ANSWER.search(res.stdout)
            # "IP Address not found" and "N/A" both come back as a successful
            # run, so the shape of the answer is what decides, not the exit
            # code.
            if m and m.group(1) not in ("--", "N/A"):
                answer = (m.group(1), m.group(2))

    _cache[ip] = answer
    return answer


def forget() -> None:
    """Drop the cache. For tests, and for a database that was just installed."""
    _cache.clear()
