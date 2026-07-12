# Italian Web Security Study (IWSS)

[![License: MIT](https://img.shields.io/badge/code-MIT-blue.svg)](LICENSE)
[![Data: CC-BY 4.0](https://img.shields.io/badge/data-CC--BY%204.0-lightgrey.svg)](LICENSE-DATA)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](pyproject.toml)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.21322437-blue.svg)](https://doi.org/10.5281/zenodo.21322437)

Italian Web Security Study (IWSS) is a reproducible, large-scale passive measurement study of the security configuration of the Italian web, covering 10,022 `.it` domains and dozens of HTTP, TLS, DNS and browser security signals.

**Paper title:** *Measuring the Security Configuration of the Italian Web: A Large-Scale Passive Measurement Study* (v1.0). DOI: [10.5281/zenodo.21322437](https://doi.org/10.5281/zenodo.21322437).

**Interactive summary:** https://f-hack.com/analisi-sicurezza-web-italiano-2026

---

## What this is

This repository contains the code, methodology and dataset used for a passive measurement study of the Italian web.

The study analyzes 10,022 `.it` domains, measuring HTTP security headers, TLS configuration, cookie security, DNS email authentication, CORS configuration and other observable security signals.

Measurements are collected exclusively through standard, browser-equivalent HTTP, HTTPS and DNS requests. No exploitation, active vulnerability scanning or brute-force techniques are used.

The domain pool is the entire `.it` slice of the [Tranco](https://tranco-list.eu/) top-1M list (list date 2026-07-08).

## Highlights

- Passive-only measurements, no exploitation or active scanning
- 10,022 Italian domains, 10,020 completed scans
- HTTP headers, CSP, cookies, TLS, DNS/email auth, well-known resources, CORS
- Fully reproducible pipeline (crawler, analyzers, database schema included)
- Pseudonymized public dataset, explicitly not overclaimed as anonymized
- Statistical analysis included (Wilson score intervals, chi-square, Cramer's V)
- Paper, methodology and data dictionary included

## Analyzers

| Analyzer | What it checks |
|---|---|
| `headers` | HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) |
| `csp` | Content-Security-Policy directive parsing, `unsafe-inline`/`unsafe-eval`/wildcard detection |
| `cookies` | `Secure` / `HttpOnly` / `SameSite` attribute coverage |
| `tls` | Negotiated TLS version, weak ciphers, certificate metadata |
| `dns_email` | SPF / DMARC / DKIM presence, MX records |
| `wellknown` | `robots.txt`, `sitemap.xml`, `security.txt` (RFC 9116) |
| `fingerprint` | CMS/CDN/server detection (context variable, not a security signal) |
| `cors` | `Access-Control-Allow-Origin` / `-Credentials` behavior |

All analyzers are independent, pure modules whose outputs are merged into a single structured dataset.

## Pipeline

```
Tranco top-1M (.it slice)
        |
        v
   Crawler (httpx, HTTP/2, per-host rate limiting)
        |
        v
   Analyzers (headers, csp, cookies, tls, dns_email, wellknown, fingerprint, cors)
        |
        v
   Postgres (immutable per-scan snapshots)
        |
        v
   Statistics (Wilson CI, chi-square, Cramer's V)
        |
        v
   Paper (methodology, data dictionary, sector classification, adoption-rate CIs)
```

## Repository structure

```
paper/        methodology, data dictionary, sector classification, adoption-rate figures with 95% CIs
dataset/
  primary_it/
    manifest.json                           dataset provenance, sampling frame, pseudonymization method
    exports/primary_it_pseudonymized.csv    full pseudonymized export (see "Data" below)
crawler/      async httpx (HTTP/2) fetcher, work queue, checkpoint/resume, per-host rate limiting
analyzers/    one module per concern, pure functions: response -> typed result
stats/        Wilson score intervals, chi-square / Cramer's V association tests
database/     Postgres schema migrations + asyncpg repository layer
```

The full crawl/orchestration pipeline (network scheduling, run scripts) is included for reproducibility, but this repository does not include raw HTTP response bodies, only the derived, structured measurements described in `paper/data_dictionary.md`.

## Data

**Dataset summary**
- 10,022 sampled `.it` domains
- 10,020 completed scans
- 54 measured columns per scan row in the public export (identity/outcome metadata + HTTP/CSP/cookie/TLS/DNS/CORS signals)
- One CSV row per scan, documented column-by-column in `paper/data_dictionary.md`

**Domain identifiers are pseudonymized, not anonymized.** Each domain is replaced by `SHA-256(domain)` with no salt. Because `.it` domain names are public information, this isn't a severe exposure, but the hash is invertible by dictionary attack against known `.it` domains, so it does **not** meet the bar for "anonymized" in the strict sense. See `dataset/primary_it/manifest.json` -> `anonymization` for the exact wording used in the paper.

**The `sector` and `sector_confidence` columns are suppressed in the public export.** Public Administration, University and Media are all derived from small, enumerable candidate lists; publishing sector alongside the unsalted domain hash would let a dictionary attack be narrowed from the full `.it` domain space to these short closed lists. Aggregate sector counts are still reported in `paper/sector_classification.md` and in the paper. See `dataset/primary_it/manifest.json` -> `public_export` for the full rationale.

**License:** the dataset is released under **CC-BY 4.0** (see `LICENSE-DATA`). Code is **MIT** (see `LICENSE`).

## Preliminary findings

The accompanying paper reports the prevalence of:

- HTTP security header adoption (no single header clears 42% adoption)
- CSP effectiveness (fewer than 1% of policies qualify as restrictive)
- TLS version distribution (TLS 1.3 already the de facto standard)
- Email authentication adoption (SPF, DKIM, DMARC)
- Cookie security attribute coverage
- CORS configuration patterns

Full figures and discussion: the paper, published on Zenodo (DOI [10.5281/zenodo.21322437](https://doi.org/10.5281/zenodo.21322437)) and linked from the interactive summary above; this repository does not host the PDF. Raw adoption-rate figures with 95% Wilson confidence intervals: `paper/adoption_rates_ci.txt`.

## Reproducing the measurement

```bash
uv sync
cp .env.example .env   # fill in a Postgres DSN
uv run psql -f database/migrations/001_initial_schema.sql
uv run python -m crawler.run --dataset primary_it
uv run pytest
```

Requires Python >= 3.13 and a Postgres instance. The published CSV in `dataset/primary_it/exports/` lets you reproduce all figures and statistics in `paper/` without re-running the crawl.

## Methodology, ethics

Passive analysis only, see `paper/methodology.md` for the full definition of "Italian site" (ccTLD `.it`), sampling procedure, and why no opt-out registry was implemented (only publicly-observable data, no active probing). Domain names are pseudonymized before release; they are stored unhashed only in the private working database, never in this repository or the paper.

## Citation

See `CITATION.cff`. If you use this dataset, please cite both the repository and the accompanying paper. Paper DOI: [10.5281/zenodo.21322437](https://doi.org/10.5281/zenodo.21322437). The dataset's own DOI will be added here once its Zenodo record is published.

## License

- Code: [MIT](LICENSE)
- Dataset (`dataset/primary_it/exports/`, `paper/*.csv`, `paper/*.json`): [CC-BY 4.0](LICENSE-DATA)

## Contact

Giovanni Manetti - giovanni@perseodesign.com
