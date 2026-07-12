"""Association statistics for categorical×categorical comparisons (e.g.
CMS × header presence, sector × header presence): chi-square test of
independence plus Cramér's V for effect size.

Effect size matters alongside the p-value: at n in the thousands, a chi-
square test finds "significant" associations that are too small to be
practically meaningful. Cramér's V (0 = no association, 1 = perfect
association) is reported alongside every test so a real effect can be
told apart from a trivial one inflated by sample size.

Pure functions — no I/O. Callers build the contingency table from
database query results (see statistics/report.py).
"""

from dataclasses import dataclass

from scipy import stats


@dataclass(frozen=True)
class AssociationResult:
    chi2: float
    p_value: float
    dof: int
    n: int
    cramers_v: float
    significant_at_05: bool


def chi_square_association(contingency_table: list[list[int]]) -> AssociationResult:
    """contingency_table: rows x columns of observed counts, e.g.
    [[cms_a_header_present, cms_a_header_absent],
     [cms_b_header_present, cms_b_header_absent]]
    """
    chi2, p_value, dof, _expected = stats.chi2_contingency(contingency_table)
    n = sum(sum(row) for row in contingency_table)
    n_rows = len(contingency_table)
    n_cols = len(contingency_table[0]) if contingency_table else 0
    min_dim = min(n_rows - 1, n_cols - 1)

    cramers_v = 0.0
    if n > 0 and min_dim > 0:
        cramers_v = (chi2 / (n * min_dim)) ** 0.5

    return AssociationResult(
        chi2=float(chi2),
        p_value=float(p_value),
        dof=int(dof),
        n=n,
        cramers_v=float(cramers_v),
        significant_at_05=p_value < 0.05,
    )


def effect_size_label(cramers_v: float) -> str:
    """Documented thresholds (Cohen 1988, adapted for df=1 contingency
    tables) — not a magic number, cited so the paper can reference the
    same convention."""
    if cramers_v < 0.1:
        return "negligible"
    if cramers_v < 0.3:
        return "small"
    if cramers_v < 0.5:
        return "medium"
    return "large"
