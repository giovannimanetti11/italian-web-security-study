"""Async HTTP fetcher. Owns all network I/O; never raises for expected
network failure modes — every outcome becomes a FetchResult with a
scan_status, not an exception the caller has to handle. This is what keeps
timeouts/DNS failures/TLS failures/dead sites as clean categorical data
instead of silently-swallowed exceptions that would bias the dataset.

Certificate validation is intentionally disabled (verify=False): an
invalid/self-signed/expired certificate should not prevent observing the
site's HTTP security headers, it should be flagged by the TLS analyzer.
This mirrors the deliberate choice already made in insights.f-hack.com's
checks/headers.py.

The response body is streamed with a hard cap (MAX_BODY_BYTES) — needed
transiently for the fingerprint analyzer and to compute body_sha256/size
for raw_http_responses, but never stored in full: a pathological giant
response must not be downloaded blindly at 100k-domain scale.
"""

import hashlib
import socket
import ssl
import time

import httpx

from crawler.models import FetchResult, RedirectHop, ScanStatus

MAX_BODY_BYTES = 5_000_000


def _root_cause(exc: BaseException) -> BaseException:
    """Walk the exception chain to the innermost cause. httpx/httpcore/anyio
    wrap low-level errors (socket.gaierror, ssl.SSLError) via implicit
    chaining (__context__), not explicit `raise ... from ...` (__cause__),
    so both must be followed — checking __cause__ alone misses them."""
    seen: set[int] = set()
    current = exc
    while id(current) not in seen:
        seen.add(id(current))
        next_exc = current.__cause__ or current.__context__
        if next_exc is None:
            return current
        current = next_exc
    return current


def _classify_error(exc: Exception) -> ScanStatus:
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    root = _root_cause(exc)
    if isinstance(root, socket.gaierror):
        return "dns_error"
    if isinstance(root, ssl.SSLError):
        return "tls_error"
    if isinstance(exc, (httpx.ConnectError, httpx.NetworkError)):
        return "connection_error"
    if isinstance(exc, httpx.HTTPError):
        return "invalid_response"
    return "invalid_response"


def _alt_svc_advertises_h3(headers: httpx.Headers) -> bool:
    alt_svc = headers.get("alt-svc", "")
    return "h3=" in alt_svc or "h3-" in alt_svc


def _normalize_http_version(raw: str) -> str:
    return raw.removeprefix("HTTP/")


def _parse_content_type(raw: str | None) -> tuple[str | None, str | None]:
    if not raw:
        return None, None
    parts = [p.strip() for p in raw.split(";")]
    content_type = parts[0] or None
    charset = None
    for p in parts[1:]:
        if p.lower().startswith("charset="):
            charset = p.split("=", 1)[1].strip().strip('"')
    return content_type, charset


async def _read_capped_body(response: httpx.Response) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    truncated = False
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            truncated = True
            break
        chunks.append(chunk)
    return b"".join(chunks), truncated


def _error_result(
    requested_url: str, status: ScanStatus, exc: Exception, elapsed_ms: int
) -> FetchResult:
    return FetchResult(
        requested_url=requested_url,
        final_url=None,
        status_code=None,
        redirect_count=0,
        redirect_chain=(),
        dns_resolved=status != "dns_error",
        scan_status=status,
        connect_error=f"{type(exc).__name__}: {exc}",
        response_time_ms=elapsed_ms,
        http_version=None,
        http3_advertised=False,
        headers={},
    )


async def fetch_site(client: httpx.AsyncClient, domain: str) -> FetchResult:
    requested_url = f"https://{domain}/"
    t0 = time.monotonic()
    try:
        async with client.stream("GET", requested_url, follow_redirects=True) as response:
            body_bytes, truncated = await _read_capped_body(response)
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return _error_result(requested_url, _classify_error(exc), exc, elapsed_ms)

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    redirect_chain = tuple(
        RedirectHop(url=str(r.url), status_code=r.status_code) for r in response.history
    )
    content_type, charset = _parse_content_type(response.headers.get("content-type"))
    body_text = None
    try:
        body_text = body_bytes.decode(charset or response.encoding or "utf-8", errors="replace")
    except (LookupError, UnicodeDecodeError):
        body_text = body_bytes.decode("utf-8", errors="replace")

    return FetchResult(
        requested_url=requested_url,
        final_url=str(response.url),
        status_code=response.status_code,
        redirect_count=len(redirect_chain),
        redirect_chain=redirect_chain,
        dns_resolved=True,
        scan_status="success",
        connect_error=None,
        response_time_ms=elapsed_ms,
        http_version=_normalize_http_version(response.http_version),
        http3_advertised=_alt_svc_advertises_h3(response.headers),
        headers=dict(response.headers),
        set_cookie_headers=tuple(response.headers.get_list("set-cookie")),
        body=body_text,
        body_sha256=hashlib.sha256(body_bytes).hexdigest() if body_bytes else None,
        body_size_bytes=len(body_bytes),
        body_truncated=truncated,
        content_type=content_type,
        charset=charset,
        server_date=response.headers.get("date"),
    )
