"""Raw DNS queries for SPF/DMARC/DKIM/MX — standard DNS resolution, exactly
what any mail server does when checking a domain's email-authentication
posture. Passive: standard queries only, no zone transfers, no brute force
beyond a small fixed list of common DKIM selectors (ported from
insights.f-hack.com's checks/dns_check.py).
"""

import asyncio
import time

import dns.asyncresolver
import dns.exception

from crawler.models import DNSFetchResult

DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "selector1", "selector2", "smtp",
    "zmail", "zoho", "s1", "s2", "mta", "mx", "em", "k2", "k3",
    "mandrill", "sendgrid", "mailchimp", "mailgun", "sg", "pm",
]

# SPF + DMARC + MX + one query per DKIM selector — fixed and known by
# construction, not measured post-hoc, since fetch_dns always issues
# exactly this many regardless of outcome.
QUERIES_PER_DOMAIN = 3 + len(DKIM_SELECTORS)

TIMEOUT = 5.0


def _make_resolver() -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = TIMEOUT
    resolver.lifetime = TIMEOUT
    return resolver


async def _first_txt_matching(
    resolver: dns.asyncresolver.Resolver, name: str, prefix: str
) -> str | None:
    try:
        answers = await resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return None
    for rdata in answers:
        txt = rdata.to_text().strip('"')
        if txt.startswith(prefix):
            return txt
    return None


async def _try_dkim_selector(
    resolver: dns.asyncresolver.Resolver, domain: str, selector: str
) -> str | None:
    try:
        answers = await resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return None
    for rdata in answers:
        txt = rdata.to_text()
        if "v=DKIM1" in txt or "p=" in txt:
            return selector
    return None


async def _mx_present(resolver: dns.asyncresolver.Resolver, domain: str) -> bool:
    try:
        await resolver.resolve(domain, "MX")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return False


async def fetch_dns(domain: str) -> DNSFetchResult:
    t0 = time.monotonic()
    resolver = _make_resolver()

    spf_raw, dmarc_raw, mx_present, dkim_results = await asyncio.gather(
        _first_txt_matching(resolver, domain, "v=spf1"),
        _first_txt_matching(resolver, f"_dmarc.{domain}", "v=DMARC1"),
        _mx_present(resolver, domain),
        asyncio.gather(*[_try_dkim_selector(resolver, domain, s) for s in DKIM_SELECTORS]),
    )
    dkim_selector = next((s for s in dkim_results if s), None)
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    return DNSFetchResult(
        domain=domain,
        spf_raw=spf_raw,
        dmarc_raw=dmarc_raw,
        dkim_selector=dkim_selector,
        mx_present=mx_present,
        queries_made=QUERIES_PER_DOMAIN,
        elapsed_ms=elapsed_ms,
    )
