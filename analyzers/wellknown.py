"""Pure well-known-resource analysis. Operates on an already-fetched
WellknownFetchResult — no I/O here.

security_txt_rfc9116_compliant is a deliberately narrow definition
(Contact + Expires fields both present) — RFC 9116 has additional optional
fields this doesn't check; documented here so the paper cites the actual
criterion, not "RFC 9116 compliant" as an unqualified claim.
"""

import re
from dataclasses import dataclass

from crawler.models import WellknownFetchResult

ANALYZER_VERSION = "0.1.0"

SENSITIVE_PATTERNS = [
    r"/admin", r"/wp-admin", r"/phpmyadmin", r"/cpanel", r"/backup",
    r"/\.env", r"/config", r"/database", r"/private", r"/secret",
    r"/api/", r"/internal", r"/staging", r"/test", r"/_",
]


@dataclass(frozen=True)
class WellknownResult:
    robots_txt_present: bool
    robots_disallow_count: int
    robots_sensitive_path_count: int
    sitemap_xml_present: bool
    security_txt_present: bool
    security_txt_rfc9116_compliant: bool | None


def analyze_wellknown(fetch: WellknownFetchResult) -> WellknownResult:
    robots_present = fetch.robots_txt is not None
    disallow_count = 0
    sensitive_count = 0
    if fetch.robots_txt:
        disallows = re.findall(r"(?im)^Disallow:\s*(.+)$", fetch.robots_txt)
        disallow_count = len(disallows)
        for path in disallows:
            path = path.strip()
            if any(re.search(pattern, path, re.IGNORECASE) for pattern in SENSITIVE_PATTERNS):
                sensitive_count += 1

    security_txt_present = fetch.security_txt is not None
    rfc9116_compliant = None
    if security_txt_present:
        text_lower = fetch.security_txt.lower()
        rfc9116_compliant = "contact:" in text_lower and "expires:" in text_lower

    return WellknownResult(
        robots_txt_present=robots_present,
        robots_disallow_count=disallow_count,
        robots_sensitive_path_count=sensitive_count,
        sitemap_xml_present=fetch.sitemap_present,
        security_txt_present=security_txt_present,
        security_txt_rfc9116_compliant=rfc9116_compliant,
    )
