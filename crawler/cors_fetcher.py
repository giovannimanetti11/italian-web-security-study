"""Passive CORS-policy probe: a GET with a synthetic test Origin header —
exactly what a browser sends on a cross-origin fetch/XHR. Observing the
response is standard HTTP behavior, not an attack. This measures
observable CORS policy characteristics, not exploitability: without an
authenticated cross-origin request we cannot demonstrate that reflected
origin + allowed credentials is actually exploitable, only that it is
configured that way (see paper/methodology.md).

Runs under a caller-provided per-host semaphore, shared with the
well-known fetches in crawler/run.py, so this probe overlaps with them
instead of waiting for them to finish sequentially.
"""

import asyncio
import time

import httpx

from crawler.models import CORSFetchResult

TEST_ORIGIN = "https://iwss-cors-probe.invalid"
TIMEOUT = 8.0


async def fetch_cors(
    client: httpx.AsyncClient, domain: str, semaphore: asyncio.Semaphore
) -> CORSFetchResult:
    t0 = time.monotonic()
    try:
        async with semaphore:
            resp = await client.get(
                f"https://{domain}/",
                headers={"Origin": TEST_ORIGIN},
                timeout=TIMEOUT,
                follow_redirects=True,
            )
    except Exception:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return CORSFetchResult(
            tested_origin=TEST_ORIGIN, acao_raw=None, acac_raw=None, elapsed_ms=elapsed_ms
        )

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    return CORSFetchResult(
        tested_origin=TEST_ORIGIN,
        acao_raw=resp.headers.get("access-control-allow-origin"),
        acac_raw=resp.headers.get("access-control-allow-credentials"),
        elapsed_ms=elapsed_ms,
    )
