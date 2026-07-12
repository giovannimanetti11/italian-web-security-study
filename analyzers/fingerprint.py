"""Technology fingerprinting: CMS, framework, JS libraries, server
software, CDN. Deliberately treated as a context/explanatory variable, not
a security metric in itself — used to explain variation in posture (e.g.
"CMS=WordPress" as a covariate for a CSP-missing outcome), never scored.

Pure function of (headers, body) -> list[TechnologyResult]. No I/O — ported
from insights.f-hack.com's checks/fingerprint.py detection logic, scoped
down for M2 (CDN/WAF distinction, deeper version extraction: future work).
"""

import re
from dataclasses import dataclass

from bs4 import BeautifulSoup

ANALYZER_VERSION = "0.1.0"

_JS_LIB_PATTERNS = [
    ("jQuery", r"jquery[.-]([\d.]+)(\.min)?\.js"),
    ("Bootstrap", r"bootstrap[.-]([\d.]+)(\.min)?\.js"),
    ("React", r"react[.-]([\d.]+)(\.min)?\.js"),
    ("Angular", r"angular[.-]([\d.]+)(\.min)?\.js"),
    ("Vue.js", r"vue[.-]([\d.]+)(\.min)?\.js"),
]


@dataclass(frozen=True)
class TechnologyResult:
    category: str  # cms | framework | js_library | server | cdn
    name: str
    version: str | None
    detection_method: str


def _extract_version(header_value: str, software: str) -> str | None:
    m = re.search(rf"{software}/([\d.]+)", header_value, re.IGNORECASE)
    return m.group(1) if m else None


def _detect_cms(body: str, soup: BeautifulSoup | None) -> tuple[str | None, str | None, str]:
    if not body:
        return None, None, ""

    if soup is not None:
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen:
            content = gen.get("content", "") or ""
            if "wordpress" in content.lower():
                m = re.search(r"WordPress ([\d.]+)", content, re.IGNORECASE)
                return "WordPress", (m.group(1) if m else None), "generator meta tag"

    if "wp-content" in body or "wp-includes" in body or "/wp-json/" in body:
        return "WordPress", None, "html markers"
    if "/media/jui/" in body or "Joomla!" in body or "/components/com_" in body:
        return "Joomla", None, "html markers"
    if "Drupal" in body or "/sites/default/files" in body:
        return "Drupal", None, "html markers"
    if "shopify" in body.lower():
        return "Shopify", None, "html markers"
    if "wixsite.com" in body or "wix.com" in body:
        return "Wix", None, "html markers"

    return None, None, ""


def analyze_fingerprint(headers: dict[str, str], body: str) -> list[TechnologyResult]:
    h = {k.lower(): v for k, v in headers.items()}
    results: list[TechnologyResult] = []
    soup = BeautifulSoup(body, "lxml") if body else None

    xpb = h.get("x-powered-by", "")
    php_version = _extract_version(xpb, "PHP")
    if php_version:
        results.append(TechnologyResult("framework", "PHP", php_version, "x-powered-by header"))

    cms_name, cms_version, cms_method = _detect_cms(body, soup)
    if cms_name:
        results.append(TechnologyResult("cms", cms_name, cms_version, cms_method))

    server_raw = h.get("server", "")
    if "nginx" in server_raw.lower():
        version = _extract_version(server_raw, "nginx")
        results.append(TechnologyResult("server", "Nginx", version, "server header"))
    elif "apache" in server_raw.lower():
        version = _extract_version(server_raw, "Apache")
        results.append(TechnologyResult("server", "Apache", version, "server header"))

    if "cf-ray" in h or "cloudflare" in server_raw.lower():
        results.append(TechnologyResult("cdn", "Cloudflare", None, "header signature"))

    if soup is not None:
        for lib_name, pattern in _JS_LIB_PATTERNS:
            for script in soup.find_all("script", src=True):
                m = re.search(pattern, script["src"], re.IGNORECASE)
                if m:
                    version = m.group(1)
                    results.append(
                        TechnologyResult("js_library", lib_name, version, "script src")
                    )
                    break

    return results
