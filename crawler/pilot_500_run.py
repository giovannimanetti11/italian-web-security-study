"""pilot_500: the first real research run — a random 500-domain subsample
of the real Tranco .it sampling frame (dataset/primary_it/pilot_500.csv,
seed 20260709, see dataset/primary_it/README.md and
paper/pilot_500_checklist.md). Not disposable — this is real research data
under the primary_it dataset.

Usage: uv run python -m crawler.pilot_500_run
"""

import asyncio
import csv
from pathlib import Path

from crawler.run import run_crawl

DOMAINS_FILE = Path(__file__).parent.parent / "dataset" / "primary_it" / "pilot_500.csv"
CONCURRENCY = 30
SAMPLE_SEED = 20260709


def load_domains() -> list[str]:
    with DOMAINS_FILE.open(newline="", encoding="utf-8") as f:
        return [row["domain"].strip() for row in csv.DictReader(f) if row["domain"].strip()]


async def main() -> None:
    domains = load_domains()
    print(f"Loaded {len(domains)} domains from {DOMAINS_FILE}")
    await run_crawl(
        dataset_code="primary_it",
        dataset_name="Primary .it sample",
        dataset_description=(
            "Tranco top .it domains — representative sample of the Italian web, "
            "RQ1-RQ7 primary dataset"
        ),
        domains=domains,
        run_label="pilot_500",
        measurement_version="pilot-500-real-sample",
        concurrency=CONCURRENCY,
        summary_title="PILOT_500 — REAL RESEARCH RUN",
        extra_config={
            "sample_seed": SAMPLE_SEED,
            "sample_size": len(domains),
            "sample_source": "dataset/primary_it/tranco_it_full.csv",
            "sample_method": "random_without_replacement",
        },
    )


if __name__ == "__main__":
    asyncio.run(main())
