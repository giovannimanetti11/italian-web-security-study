"""Per-host pacing, independent of the crawler's global concurrency
semaphore. The global semaphore bounds total outstanding connections; this
bounds how often any single host is hit, regardless of how much global
concurrency headroom exists.

Doesn't show up in a 105-domain smoke test where every domain is a
distinct host, but shared .it hosting (Aruba, Register, OVH, Netsons...)
puts many unrelated domains behind the same infrastructure — this is the
abstraction point for that, keyed by requested hostname for now.

Scope note: this keys by hostname, not resolved IP. Two different domains
on the same shared-hosting IP are NOT currently paced against each other —
that would need a DNS-resolution step before rate-limiting. Left as a
documented gap rather than solved prematurely; hostname-level pacing is
what's needed today.
"""

import asyncio
import time


class PerHostRateLimiter:
    def __init__(self, min_interval_seconds: float):
        self._min_interval = min_interval_seconds
        self._next_allowed: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def wait(self, host: str) -> None:
        async with self._lock:
            now = time.monotonic()
            next_allowed = self._next_allowed.get(host, now)
            start = max(now, next_allowed)
            self._next_allowed[host] = start + self._min_interval

        delay = start - now
        if delay > 0:
            await asyncio.sleep(delay)
