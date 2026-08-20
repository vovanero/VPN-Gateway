"""Pool member selection and failover.

A pool owns a routing table exactly like a tunnel does. The difference is that
its default route is repointed as members come and go, which means failover
costs one ``ip route replace`` no matter how many clients are on the pool. Ten
clients on a pool do not need ten updates, and there is no window in which some
of them have moved and some have not.

What happens when every member is down is the part that matters: the real
default route is removed and the table's blackhole takes over. Clients on that
pool lose the internet. They do not fall back to the uplink - that is the whole
point of a pool on this box, as opposed to a pool on a normal router.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass

from .health import HealthMonitor
from .models import Pool, PoolStrategy

log = logging.getLogger("vpngw.pool")


@dataclass
class PoolState:
    active: str | None = None          # tunnel slug currently carrying the pool
    since: float = 0.0
    last_rotate: float = 0.0
    last_reason: str = ""


class PoolManager:
    def __init__(self) -> None:
        self.state: dict[str, PoolState] = {}

    def get(self, slug: str) -> PoolState:
        return self.state.setdefault(slug, PoolState())

    def forget(self, slug: str) -> None:
        self.state.pop(slug, None)

    def select(self, pool: Pool, health: HealthMonitor) -> tuple[str | None, str]:
        """Pick the member that should carry this pool right now.

        Returns ``(slug_or_None, reason)``. ``None`` means every member is
        down, which the caller turns into a blackholed pool.
        """
        st = self.get(pool.slug)
        now = time.time()

        if not pool.enabled:
            return None, "pool disabled"

        members = pool.ordered_members()
        healthy = [m for m in members if health.healthy(m.tunnel_slug)]
        if not healthy:
            return None, "no healthy members"

        current_ok = st.active and health.healthy(st.active)

        # Stickiness. Once we have moved, do not move back the instant the
        # preferred member returns: a tunnel that is flapping would otherwise
        # drag every client on the pool through a reconnect each time it
        # bounced. Wait until it has held steady.
        if current_ok and st.active is not None:
            preferred = self._preferred(pool, healthy, health, st)
            if preferred == st.active:
                return st.active, "unchanged"
            held = now - st.since
            if held < pool.sticky_seconds:
                return (
                    st.active,
                    f"holding {st.active} for another "
                    f"{int(pool.sticky_seconds - held)}s (sticky)",
                )
            if health.stable_for(preferred) < pool.sticky_seconds:
                return (
                    st.active,
                    f"{preferred} not stable long enough to switch back",
                )
            return preferred, f"switching to preferred member {preferred}"

        chosen = self._preferred(pool, healthy, health, st)
        if st.active and not current_ok:
            return chosen, f"{st.active} went down, failing over to {chosen}"
        return chosen, "initial selection"

    def _preferred(self, pool: Pool, healthy, health: HealthMonitor,
                   st: PoolState) -> str:
        slugs = [m.tunnel_slug for m in healthy]

        if pool.strategy is PoolStrategy.PRIORITY:
            return slugs[0]  # ordered_members() already sorted by priority

        if pool.strategy is PoolStrategy.LATENCY:
            def rtt(slug: str) -> float:
                h = health.state.get(slug)
                return h.rtt_ms if h and h.rtt_ms is not None else 9e9
            return min(slugs, key=rtt)

        if pool.strategy is PoolStrategy.RANDOM:
            # Keep the current member if it is still healthy, otherwise the
            # pool would reshuffle on every single reconcile.
            if st.active in slugs:
                return st.active
            return random.choice(slugs)

        if pool.strategy is PoolStrategy.ROUND_ROBIN:
            now = time.time()
            if st.active in slugs and now - st.last_rotate < pool.rotate_seconds:
                return st.active
            st.last_rotate = now
            if st.active in slugs:
                return slugs[(slugs.index(st.active) + 1) % len(slugs)]
            return slugs[0]

        return slugs[0]

    def commit(self, pool: Pool, chosen: str | None, reason: str) -> bool:
        """Record a selection. Returns True when the active member changed."""
        st = self.get(pool.slug)
        if st.active == chosen:
            return False
        old = st.active
        st.active = chosen
        st.since = time.time()
        st.last_reason = reason
        if chosen is None:
            log.error("pool %s has no healthy member; clients on it are now "
                      "blackholed (this is correct - they are not falling back "
                      "to the uplink)", pool.slug)
        else:
            log.warning("pool %s: %s -> %s (%s)", pool.slug, old or "none",
                        chosen, reason)
        return True
