"""Cookie security analysis. Pure function of the raw Set-Cookie header
values captured by the crawler — parsing only, completely passive.
"""

from dataclasses import dataclass

ANALYZER_VERSION = "0.1.0"


@dataclass(frozen=True)
class CookieResult:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None  # 'strict' | 'lax' | 'none' | None (attribute absent)


def analyze_cookies(set_cookie_headers: tuple[str, ...]) -> list[CookieResult]:
    results: list[CookieResult] = []
    for raw in set_cookie_headers:
        parts = [p.strip() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()

        attrs = [p.lower() for p in parts[1:]]
        secure = "secure" in attrs
        httponly = "httponly" in attrs

        samesite = None
        for p in parts[1:]:
            if p.lower().startswith("samesite="):
                samesite = p.split("=", 1)[1].strip().lower()
                break

        results.append(CookieResult(name=name, secure=secure, httponly=httponly, samesite=samesite))
    return results
