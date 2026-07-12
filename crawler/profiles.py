"""Measurement profiles: which analyzers run in a given crawl_run.

Introduced because adding DNS/email + well-known (M3) roughly quadrupled
the per-domain request budget compared to M1-M2 — silently changing what a
"scan" measures breaks comparability between runs (pilot_500's headers/CSP
adoption numbers aren't the same measurement scope as a run under a
richer profile). A run's profile name and enabled-analyzer set are
recorded in crawl_runs.config_snapshot, not just implied by "whatever the
code did that day".

Future profiles (extended_v1, longitudinal_v2, ...) should be added here,
never by silently changing what BASELINE_V1 includes — that would corrupt
comparisons against runs already tagged baseline_v1.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class MeasurementProfile:
    name: str
    enabled_analyzers: frozenset[str]


BASELINE_V1 = MeasurementProfile(
    name="baseline_v1",
    enabled_analyzers=frozenset(
        {
            "headers",
            "csp",
            "cookies",
            "tls",
            "fingerprint",
            "dns_email",
            "wellknown",
            "cors",
        }
    ),
)
