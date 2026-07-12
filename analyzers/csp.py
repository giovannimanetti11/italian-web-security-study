"""CSP directive-level analysis. Pure function of the raw CSP header value —
only invoked when analyzers.headers has already found csp_present=True, so
this table only ever holds rows for sites that actually have a policy.
"""

from dataclasses import dataclass

ANALYZER_VERSION = "0.1.0"

_UNSAFE_INLINE = "'unsafe-inline'"
_UNSAFE_EVAL = "'unsafe-eval'"
_WILDCARD = "*"

# Directives whose restrictiveness matters most for XSS mitigation — used
# only to decide is_restrictive below; every directive is still captured in
# `directives` regardless of whether it's "primary".
_PRIMARY_DIRECTIVES = ("default-src", "script-src")


@dataclass(frozen=True)
class CSPResult:
    directives: dict[str, list[str]]
    directive_count: int
    has_unsafe_inline: bool
    has_unsafe_eval: bool
    has_wildcard_source: bool
    frame_ancestors_present: bool
    is_restrictive: bool


def parse_csp(raw: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for chunk in raw.split(";"):
        tokens = chunk.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        directives[name] = tokens[1:]
    return directives


def analyze_csp(raw_csp: str) -> CSPResult:
    directives = parse_csp(raw_csp)
    all_sources = [src for sources in directives.values() for src in sources]

    has_unsafe_inline = _UNSAFE_INLINE in all_sources
    has_unsafe_eval = _UNSAFE_EVAL in all_sources
    has_wildcard_source = _WILDCARD in all_sources
    frame_ancestors_present = "frame-ancestors" in directives

    # is_restrictive: documented so the paper's methodology section can cite
    # exactly what this means, rather than an unexplained magic threshold.
    # A CSP counts as restrictive if it constrains script execution
    # (default-src or script-src present) without falling back to
    # unsafe-inline, unsafe-eval, or a bare wildcard source anywhere.
    has_primary_directive = any(d in directives for d in _PRIMARY_DIRECTIVES)
    is_restrictive = (
        has_primary_directive
        and not has_unsafe_inline
        and not has_unsafe_eval
        and not has_wildcard_source
    )

    return CSPResult(
        directives=directives,
        directive_count=len(directives),
        has_unsafe_inline=has_unsafe_inline,
        has_unsafe_eval=has_unsafe_eval,
        has_wildcard_source=has_wildcard_source,
        frame_ancestors_present=frame_ancestors_present,
        is_restrictive=is_restrictive,
    )
