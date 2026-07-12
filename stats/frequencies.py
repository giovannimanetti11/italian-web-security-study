"""Frequency / adoption-rate statistics: Wilson score confidence intervals
for proportions. Wilson is used instead of the normal approximation
because adoption rates in this dataset are frequently near 0% or 100%
(e.g. CSP-restrictive at 0.7%, security.txt at 2.4%), where the normal
approximation produces intervals that can extend below 0% or above 100%.

Pure functions — no I/O, no database access. Callers pass in counts
already queried from the database (see statistics/report.py for the
query-and-format layer).
"""

import math
from dataclasses import dataclass

Z_95 = 1.959963984540054  # two-sided 95% CI


@dataclass(frozen=True)
class ProportionEstimate:
    successes: int
    n: int
    proportion: float
    ci_low: float
    ci_high: float
    z: float = Z_95


def wilson_ci(successes: int, n: int, z: float = Z_95) -> ProportionEstimate:
    """Wilson score interval for a single proportion. Not the normal
    (Wald) approximation — see module docstring for why."""
    if n == 0:
        return ProportionEstimate(0, 0, 0.0, 0.0, 0.0, z)

    p_hat = successes / n
    denom = 1 + z**2 / n
    center = (p_hat + z**2 / (2 * n)) / denom
    half_width = (z / denom) * math.sqrt(p_hat * (1 - p_hat) / n + z**2 / (4 * n**2))

    ci_low = max(0.0, center - half_width)
    ci_high = min(1.0, center + half_width)

    return ProportionEstimate(
        successes=successes, n=n, proportion=p_hat, ci_low=ci_low, ci_high=ci_high, z=z
    )
