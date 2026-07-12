"""Pure DNS/email-auth analysis. Operates on an already-fetched
DNSFetchResult (crawler/dns_fetcher.py owns the actual queries) — no I/O
here, testable against hand-built fixtures.

Deliberately framed as domain-level email-spoofing-resistance posture, a
distinct construct from HTTP/TLS website security — never call this
"website security" in the paper (see paper/methodology.md).
"""

from dataclasses import dataclass

from crawler.models import DNSFetchResult

ANALYZER_VERSION = "0.1.0"


@dataclass(frozen=True)
class DNSEmailResult:
    spf_present: bool
    spf_raw: str | None
    dmarc_present: bool
    dmarc_raw: str | None
    dmarc_policy: str | None
    dkim_present: bool
    dkim_selector: str | None
    mx_present: bool


def _extract_dmarc_policy(raw: str) -> str | None:
    for part in raw.split(";"):
        part = part.strip()
        if part.startswith("p="):
            return part.split("=", 1)[1].strip()
    return None


def analyze_dns_email(fetch: DNSFetchResult) -> DNSEmailResult:
    dmarc_policy = _extract_dmarc_policy(fetch.dmarc_raw) if fetch.dmarc_raw else None
    return DNSEmailResult(
        spf_present=fetch.spf_raw is not None,
        spf_raw=fetch.spf_raw,
        dmarc_present=fetch.dmarc_raw is not None,
        dmarc_raw=fetch.dmarc_raw,
        dmarc_policy=dmarc_policy,
        dkim_present=fetch.dkim_selector is not None,
        dkim_selector=fetch.dkim_selector,
        mx_present=fetch.mx_present,
    )
