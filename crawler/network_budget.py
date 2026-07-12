"""Global network-activity budget: every network operation the crawler
performs (HTTP fetch, TLS handshake + DNS resolution, well-known/CORS probe
burst) acquires this before running, not just the primary HTTP fetch.

Found during M3 hardening: the concurrency semaphore only gated the
primary HTTP fetch, so DNS's internal 23-query burst per domain (and TLS,
and the well-known/CORS burst) ran with no concurrency bound at all —
`concurrency=20` was never true of the crawler's actual network behavior,
only of its HTTP-fetch behavior. Exhausted the process's file-descriptor
limit at 105 domains once well-known/CORS parallelization added more
concurrent load on top of the already-uncapped DNS/TLS phases.

This is a single undifferentiated budget for now (matches baseline_v1's
scope) — splitting it into per-operation-type budgets (global_http /
global_dns / global_tls) is a documented future refinement, not needed
until a profile actually requires differentiated limits.
"""

import asyncio
from contextlib import asynccontextmanager


class NetworkBudget:
    def __init__(self, capacity: int):
        self._sem = asyncio.Semaphore(capacity)
        self._active = 0
        self._peak = 0
        self._lock = asyncio.Lock()

    @property
    def peak_concurrent(self) -> int:
        return self._peak

    @asynccontextmanager
    async def acquire(self):
        await self._sem.acquire()
        async with self._lock:
            self._active += 1
            self._peak = max(self._peak, self._active)
        try:
            yield
        finally:
            async with self._lock:
                self._active -= 1
            self._sem.release()
