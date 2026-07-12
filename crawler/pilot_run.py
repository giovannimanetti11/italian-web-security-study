"""M2 smoke test: crawl the pilot_smoke_test domain list. Disposable infra
validation — see dataset/pilot_smoke_test/README.md. Not a research run.

Usage: uv run python -m crawler.pilot_run
"""

import asyncio
import csv
import time
from pathlib import Path

from crawler.run import run_crawl

DOMAINS_FILE = Path(__file__).parent.parent / "dataset" / "pilot_smoke_test" / "domains.csv"
CONCURRENCY = 20


def load_domains() -> list[str]:
    with DOMAINS_FILE.open(newline="", encoding="utf-8") as f:
        return [row["domain"].strip() for row in csv.DictReader(f) if row["domain"].strip()]


async def main() -> None:
    domains = load_domains()
    print(f"Loaded {len(domains)} domains from {DOMAINS_FILE}")
    await run_crawl(
        dataset_code="pilot_smoke_test",
        dataset_name="M2 pilot smoke test",
        dataset_description=(
            "Hand-picked .it domains, infra validation only, not a research dataset"
        ),
        domains=domains,
        run_label=f"m2_smoke_{int(time.time())}",
        measurement_version="m2-five-analyzers-smoke-test",
        concurrency=CONCURRENCY,
        summary_title="M2 PILOT SMOKE TEST",
    )


if __name__ == "__main__":
    asyncio.run(main())
