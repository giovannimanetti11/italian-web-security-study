"""Shared data model produced by the crawler and consumed by analyzers.

Analyzers must be pure functions of these fetch results -> <TypedResult>,
with no I/O of their own, so they can be unit-tested against hand-built
fixtures instead of live network calls.
"""

from dataclasses import dataclass, field
from typing import Literal

ScanStatus = Literal[
    "success",
    "dns_error",
    "timeout",
    "tls_error",
    "connection_error",
    "blocked",
    "http_error",
    "invalid_response",
]


@dataclass(frozen=True)
class RedirectHop:
    url: str
    status_code: int


@dataclass(frozen=True)
class FetchResult:
    requested_url: str
    final_url: str | None
    status_code: int | None
    redirect_count: int
    redirect_chain: tuple[RedirectHop, ...]
    dns_resolved: bool
    scan_status: ScanStatus
    connect_error: str | None
    response_time_ms: int | None
    http_version: str | None
    http3_advertised: bool
    headers: dict[str, str] = field(default_factory=dict)
    set_cookie_headers: tuple[str, ...] = ()
    body: str | None = None
    body_sha256: str | None = None
    body_size_bytes: int | None = None
    body_truncated: bool = False
    content_type: str | None = None
    charset: str | None = None
    server_date: str | None = None


@dataclass(frozen=True)
class TLSFetchResult:
    """Raw TLS handshake data — a separate network operation from the main
    HTTP fetch (crawler/tls_fetcher.py owns it), always against the bare
    requested domain on port 443, independent of the HTTP fetch's own
    redirect chain."""

    domain: str
    tls_ok: bool
    tls_version_negotiated: str | None
    cipher_suite: str | None
    tls10_supported: bool
    tls11_supported: bool
    peer_cert_der: bytes | None
    error: str | None
    elapsed_ms: int = 0


@dataclass(frozen=True)
class DNSFetchResult:
    """Raw DNS query results — a separate lookup from the main HTTP fetch
    (crawler/dns_fetcher.py owns it)."""

    domain: str
    spf_raw: str | None
    dmarc_raw: str | None
    dkim_selector: str | None
    mx_present: bool
    queries_made: int = 0
    elapsed_ms: int = 0


@dataclass(frozen=True)
class WellknownFetchResult:
    """Raw robots.txt/sitemap.xml/security.txt fetch results (crawler/wellknown_fetcher.py)."""

    robots_txt: str | None
    sitemap_present: bool
    security_txt: str | None
    requests_attempted: int = 0
    elapsed_ms: int = 0


@dataclass(frozen=True)
class CORSFetchResult:
    """Raw CORS-probe result — a GET with a synthetic test Origin header,
    exactly what a browser sends on a cross-origin fetch/XHR. Observing the
    response is standard HTTP behavior, not an attack (crawler/cors_fetcher.py)."""

    tested_origin: str
    acao_raw: str | None
    acac_raw: str | None
    elapsed_ms: int = 0
