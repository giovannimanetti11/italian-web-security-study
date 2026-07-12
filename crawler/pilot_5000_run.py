"""pilot_5000: operational validation at 10x pilot_500's scale — NOT for
the paper (see paper/pilot_5000_checklist.md). 5,000 domains drawn disjoint
from pilot_500, from the same real Tranco .it sampling frame.

Usage: uv run python -m crawler.pilot_5000_run
"""

import asyncio
import csv
from pathlib import Path

import analyzers.cookies as cookies_analyzer
import analyzers.cors as cors_analyzer
import analyzers.csp as csp_analyzer
import analyzers.dns_email as dns_email_analyzer
import analyzers.fingerprint as fingerprint_analyzer
import analyzers.headers as headers_analyzer
import analyzers.tls as tls_analyzer
import analyzers.wellknown as wellknown_analyzer
from crawler.guard import GuardFailure, RunGuard, check_guard
from crawler.profiles import BASELINE_V1
from crawler.run import run_crawl

DOMAINS_FILE = Path(__file__).parent.parent / "dataset" / "primary_it" / "pilot_5000.csv"
CONCURRENCY = 20
SAMPLE_SEED = 20260710

GUARD = RunGuard(
    expected_dataset_code="primary_it",
    expected_profile_name="baseline_v1",
    expected_sample_size=5000,
    expected_analyzer_versions={
        "headers": "0.1.0",
        "csp": "0.1.0",
        "cookies": "0.1.0",
        "tls": "0.1.0",
        "fingerprint": "0.1.0",
        "dns_email": "0.1.0",
        "wellknown": "0.1.0",
        "cors": "0.1.0",
    },
)


def load_domains() -> list[str]:
    with DOMAINS_FILE.open(newline="", encoding="utf-8") as f:
        return [row["domain"].strip() for row in csv.DictReader(f) if row["domain"].strip()]


async def main() -> None:
    domains = load_domains()
    print(f"Loaded {len(domains)} domains from {DOMAINS_FILE}")

    actual_versions = {
        "headers": headers_analyzer.ANALYZER_VERSION,
        "csp": csp_analyzer.ANALYZER_VERSION,
        "cookies": cookies_analyzer.ANALYZER_VERSION,
        "tls": tls_analyzer.ANALYZER_VERSION,
        "fingerprint": fingerprint_analyzer.ANALYZER_VERSION,
        "dns_email": dns_email_analyzer.ANALYZER_VERSION,
        "wellknown": wellknown_analyzer.ANALYZER_VERSION,
        "cors": cors_analyzer.ANALYZER_VERSION,
    }

    try:
        check_guard(GUARD, "primary_it", BASELINE_V1, domains, actual_versions)
    except GuardFailure as exc:
        print(exc)
        raise SystemExit(1) from exc

    await run_crawl(
        dataset_code="primary_it",
        dataset_name="Primary .it sample",
        dataset_description=(
            "Tranco top .it domains — representative sample of the Italian web, "
            "RQ1-RQ7 primary dataset"
        ),
        domains=domains,
        run_label="pilot_5000",
        measurement_version="pilot-5000-operational-validation",
        concurrency=CONCURRENCY,
        summary_title="PILOT_5000 — OPERATIONAL VALIDATION (not for the paper)",
        profile=BASELINE_V1,
        extra_config={
            "sample_seed": SAMPLE_SEED,
            "sample_size": len(domains),
            "sample_source": "dataset/primary_it/tranco_it_full.csv",
            "sample_method": "random_without_replacement_disjoint_from_pilot_500",
        },
    )


if __name__ == "__main__":
    asyncio.run(main())
