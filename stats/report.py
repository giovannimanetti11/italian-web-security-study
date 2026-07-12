"""Computes Wilson confidence intervals for the key adoption rates in
dataset_primary_it_v1, against the correct analysis subset (A/B/C) for
each feature — see dataset/primary_it/manifest.json. Dual output (JSON +
human-readable text), same pattern as seo-study's correlate_v3.py.

Usage: uv run python -m stats.report
"""

import asyncio
import json
from pathlib import Path

from database.pool import create_pool
from stats.frequencies import wilson_ci

OUT_JSON = Path(__file__).parent.parent / "paper" / "adoption_rates_ci.json"
OUT_TEXT = Path(__file__).parent.parent / "paper" / "adoption_rates_ci.txt"

# (label, sql_count_expr, table/join, subset_note)
QUERIES = {
    "hsts": (
        "SELECT count(*) FROM security_headers sh JOIN scans s ON s.scan_id=sh.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it')) AND sh.hsts_present",
        "SELECT count(*) FROM security_headers sh JOIN scans s ON s.scan_id=sh.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it'))",
        "Dataset A (n=8829)",
    ),
    "csp_present": (
        "SELECT count(*) FROM security_headers sh JOIN scans s ON s.scan_id=sh.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it')) AND sh.csp_present",
        "SELECT count(*) FROM security_headers sh JOIN scans s ON s.scan_id=sh.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it'))",
        "Dataset A (n=8829)",
    ),
    "csp_restrictive": (
        "SELECT count(*) FROM csp_analysis ca JOIN scans s ON s.scan_id=ca.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it')) AND ca.is_restrictive",
        "SELECT count(*) FROM csp_analysis ca JOIN scans s ON s.scan_id=ca.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it'))",
        "CSP-present subset (n=1646)",
    ),
    "xfo": (
        "SELECT count(*) FROM security_headers sh JOIN scans s ON s.scan_id=sh.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it')) AND sh.xfo_present",
        "SELECT count(*) FROM security_headers sh JOIN scans s ON s.scan_id=sh.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it'))",
        "Dataset A (n=8829)",
    ),
    "spf": (
        "SELECT count(*) FROM dns_email_security de JOIN scans s ON s.scan_id=de.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it')) AND de.spf_present",
        "SELECT count(*) FROM dns_email_security de JOIN scans s ON s.scan_id=de.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it'))",
        "Dataset B (n=9520)",
    ),
    "dmarc": (
        "SELECT count(*) FROM dns_email_security de JOIN scans s ON s.scan_id=de.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it')) AND de.dmarc_present",
        "SELECT count(*) FROM dns_email_security de JOIN scans s ON s.scan_id=de.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it'))",
        "Dataset B (n=9520)",
    ),
    "security_txt": (
        "SELECT count(*) FROM wellknown_resources wk JOIN scans s ON s.scan_id=wk.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it')) AND wk.security_txt_present",
        "SELECT count(*) FROM wellknown_resources wk JOIN scans s ON s.scan_id=wk.scan_id "
        "WHERE s.run_id IN (SELECT run_id FROM crawl_runs WHERE dataset_id="
        "(SELECT dataset_id FROM datasets WHERE code='primary_it'))",
        "Dataset B (n=8438)",
    ),
    "reachable": (
        "SELECT count(*) FROM scans s WHERE s.run_id IN (SELECT run_id FROM crawl_runs "
        "WHERE dataset_id=(SELECT dataset_id FROM datasets WHERE code='primary_it')) "
        "AND s.scan_status='success'",
        "SELECT count(*) FROM scans s WHERE s.run_id IN (SELECT run_id FROM crawl_runs "
        "WHERE dataset_id=(SELECT dataset_id FROM datasets WHERE code='primary_it'))",
        "Dataset C (n=10020)",
    ),
}


async def main() -> None:
    pool = await create_pool()
    results = {}
    lines = ["Adoption rates with 95% Wilson confidence intervals", "=" * 55, ""]

    async with pool.acquire() as conn:
        for label, (success_q, total_q, subset) in QUERIES.items():
            successes = await conn.fetchval(success_q)
            total = await conn.fetchval(total_q)
            est = wilson_ci(successes, total)
            results[label] = {
                "successes": est.successes,
                "n": est.n,
                "proportion": round(est.proportion, 4),
                "ci_low": round(est.ci_low, 4),
                "ci_high": round(est.ci_high, 4),
                "subset": subset,
            }
            lines.append(
                f"{label:<18} {est.proportion*100:5.1f}%  "
                f"[{est.ci_low*100:5.1f}%, {est.ci_high*100:5.1f}%]  "
                f"n={est.n:<6} ({subset})"
            )

    await pool.close()

    OUT_JSON.write_text(json.dumps(results, indent=2))
    OUT_TEXT.write_text("\n".join(lines))
    print("\n".join(lines))
    print(f"\nSaved: {OUT_JSON}\n        {OUT_TEXT}")


if __name__ == "__main__":
    asyncio.run(main())
