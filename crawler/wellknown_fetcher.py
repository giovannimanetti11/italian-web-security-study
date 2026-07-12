"""Fetch robots.txt / sitemap.xml / security.txt — standard, publicly
intended resources any browser or search-engine crawler requests routinely.
Passive: plain GET on well-known, standard paths only.

robots.txt, sitemap.xml, and the security.txt lookup run concurrently
(bounded by a caller-provided per-host semaphore, shared with the CORS
probe in crawler/run.py) instead of sequentially — this was previously the
dominant cost in per-domain HTTP time. The security.txt lookup itself
stays internally sequential with early exit, preserving the exact existing
path-preference behavior (.well-known/security.txt before /security.txt);
only the WHEN of these three independent operations changed, not what each
one measures.
"""

import asyncio
import time

import httpx

from crawler.models import WellknownFetchResult

TIMEOUT = 8.0


async def _get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    try:
        return await client.get(url, timeout=TIMEOUT, follow_redirects=True)
    except Exception:
        return None


async def _security_txt(
    client: httpx.AsyncClient, base: str, semaphore: asyncio.Semaphore
) -> tuple[str | None, int]:
    attempted = 0
    for path in ("/.well-known/security.txt", "/security.txt"):
        attempted += 1
        async with semaphore:
            resp = await _get(client, f"{base}{path}")
        if resp and resp.status_code == 200 and "contact:" in resp.text.lower():
            return resp.text, attempted
    return None, attempted


async def fetch_wellknown(
    client: httpx.AsyncClient, domain: str, semaphore: asyncio.Semaphore
) -> WellknownFetchResult:
    t0 = time.monotonic()
    base = f"https://{domain}"

    async def _robots() -> httpx.Response | None:
        async with semaphore:
            return await _get(client, f"{base}/robots.txt")

    async def _sitemap() -> httpx.Response | None:
        async with semaphore:
            return await _get(client, f"{base}/sitemap.xml")

    robots_resp, sitemap_resp, (security_txt, sec_attempted) = await asyncio.gather(
        _robots(), _sitemap(), _security_txt(client, base, semaphore)
    )

    robots_text = robots_resp.text if robots_resp and robots_resp.status_code == 200 else None
    sitemap_present = bool(sitemap_resp and sitemap_resp.status_code == 200)

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    return WellknownFetchResult(
        robots_txt=robots_text,
        sitemap_present=sitemap_present,
        security_txt=security_txt,
        requests_attempted=2 + sec_attempted,
        elapsed_ms=elapsed_ms,
    )
