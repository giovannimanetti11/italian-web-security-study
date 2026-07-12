"""Security-header analysis. Pure function of FetchResult -> SecurityHeadersResult,
no I/O — testable against hand-built fixtures without a network connection.

CSP is only checked for presence/raw value here. Directive-level parsing
(unsafe-inline, unsafe-eval, wildcard sources, frame-ancestors) lives in
analyzers/csp.py, which only runs when csp_present is True, writing to its
own csp_analysis table.
"""

from dataclasses import dataclass

from crawler.models import FetchResult

ANALYZER_VERSION = "0.1.0"


@dataclass(frozen=True)
class SecurityHeadersResult:
    csp_present: bool
    csp_raw: str | None
    hsts_present: bool
    hsts_max_age: int | None
    hsts_include_subdomains: bool | None
    hsts_preload: bool | None
    xfo_present: bool
    xfo_value: str | None
    xcto_present: bool
    referrer_policy_present: bool
    referrer_policy_value: str | None
    permissions_policy_present: bool


def _parse_hsts(raw: str) -> tuple[int | None, bool, bool]:
    max_age = None
    include_subdomains = False
    preload = False
    for part in raw.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                pass
        elif part == "includesubdomains":
            include_subdomains = True
        elif part == "preload":
            preload = True
    return max_age, include_subdomains, preload


def analyze_headers(fetch: FetchResult) -> SecurityHeadersResult:
    h = {k.lower(): v for k, v in fetch.headers.items()}

    csp_raw = h.get("content-security-policy")

    hsts_raw = h.get("strict-transport-security")
    hsts_max_age = hsts_include_subdomains = hsts_preload = None
    if hsts_raw is not None:
        hsts_max_age, hsts_include_subdomains, hsts_preload = _parse_hsts(hsts_raw)

    xfo_raw = h.get("x-frame-options")
    xcto_raw = h.get("x-content-type-options")
    referrer_raw = h.get("referrer-policy")
    permissions_raw = h.get("permissions-policy")

    return SecurityHeadersResult(
        csp_present=csp_raw is not None,
        csp_raw=csp_raw,
        hsts_present=hsts_raw is not None,
        hsts_max_age=hsts_max_age,
        hsts_include_subdomains=hsts_include_subdomains,
        hsts_preload=hsts_preload,
        xfo_present=xfo_raw is not None,
        xfo_value=xfo_raw,
        xcto_present=(xcto_raw or "").strip().lower() == "nosniff",
        referrer_policy_present=referrer_raw is not None,
        referrer_policy_value=referrer_raw,
        permissions_policy_present=permissions_raw is not None,
    )
