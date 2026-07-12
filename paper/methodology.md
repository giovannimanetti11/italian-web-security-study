# Methodology

Working title: *Measuring the Security Posture of the Italian Web: A Large-Scale
Passive Measurement Study*.

This document records methodological decisions before real sampling data enters
the system. Every decision here is written the way it needs to appear in the
paper's Methods section — if a decision changes later, this file changes and the
reason is recorded, not silently overwritten.

## 1. Definition of scope

> A website is considered Italian if its primary domain uses the `.it`
> country-code top-level domain.

Rejected alternatives, and why:

- **Hosting location** (server IP geolocated to Italy) — unstable over time
  (CDNs, migrations), not verifiable at 50k-100k scale without a second
  measurement layer, and conflates "Italian" with "using Italian infrastructure."
- **Content language** (Italian-language pages) — requires reliable language
  detection on every page, adds a dependency and a failure mode to the
  sampling frame itself, and many legitimately Italian institutional sites
  serve bilingual or English-first content.
- **Company registration** (Italian legal entity) — not derivable from a
  domain or its content at all without an external registry lookup per site,
  which reintroduces the WHOIS-at-scale problems already ruled out for the
  main pipeline (see roadmap §A.3).

`.it` is unambiguous, machine-checkable from the domain string alone, free,
reproducible by anyone re-running this study, and matches prior ccTLD-scale
web measurement literature's convention of using the ccTLD as the sampling
boundary. The corresponding limitation (excludes `.com`/`.eu` Italian sites,
includes any `.it` domain regardless of who actually operates it) belongs in
the paper's Threats to Validity section, not hidden here.

## 2. Sampling frame

- **Base list**: Tranco (https://tranco-list.eu), filtered to `.it` domains.
  Tranco is used in prior web-measurement literature specifically because it
  is a stable, citable, manipulation-resistant ranking (unlike raw Alexa/Cisco
  Umbrella lists) — this is why it replaces `insights.f-hack.com`'s original
  Google-scraping domain collector (roadmap §A.3).
- **List identity**: every acquired list is saved under `dataset/primary_it/`
  with the exact Tranco list ID/date it was generated from, so "the sampling
  frame" is a citable, re-derivable artifact, not a moving target.
- **Sub-sampling for pilots**: `pilot_500` and `pilot_5000` are **random
  subsamples without replacement** from the full `.it` frame, drawn with a
  fixed, recorded random seed — not the top-N domains by Tranco rank. Top-N
  would skew toward large, well-resourced sites (exactly the bias already
  observed in the hand-picked 105-domain smoke test) and defeat the pilot's
  purpose of estimating realistic error/coverage rates for the eventual
  50k-100k run, which will include the long tail.
- **Dataset identity**: all `.it` sites live under one `datasets.code =
  'primary_it'` row. `pilot_500`, `pilot_5000`, and `final_50000` are
  different `crawl_runs.run_label` values against (growing) subsets of the
  same dataset, not separate datasets — this keeps the longitudinal design
  (roadmap §7) intact from the first real run onward.
- **Known constraint on frame size**: the Tranco top-1M global list yields
  10,022 `.it` domains (see `dataset/primary_it/README.md`) — this is the
  entire directly-downloadable frame. `pilot_5000` draws from it disjoint
  from `pilot_500` to avoid wasting the limited pool on redundant re-scans.
  Reaching `final_50000` as originally scoped requires either a deeper
  Tranco list (their configurator tool supports larger lists but isn't a
  simple direct download) or a complementary `.it` domain source — an open
  decision, not yet resolved, revisited after `pilot_5000`'s results are in.

## 3. Data collection window

Each `crawl_runs` row is the authoritative record of when a given batch was
collected (`started_at`/`finished_at`, both `TIMESTAMPTZ`, already enforced
NOT NULL/auto-set by the schema) — this file does not duplicate that data, it
only fixes the *reporting convention* for the paper:

> Collection period: `[started_at date]`–`[finished_at date]`, campaign
> `[run_label]`. Crawler version: `[crawler_version]`. Measurement version:
> `[measurement_version]`.

**No collection has happened against the real sampling frame yet.** The only
data in the database as of this writing is the disposable
`pilot_smoke_test` validation run (105 hand-picked domains, see
`dataset/pilot_smoke_test/README.md`) — explicitly excluded from any
reported result.

## 4. Analyzer versions (current, as implemented)

Every analyzer module exports an `ANALYZER_VERSION` constant, persisted per
result row via the composite `(scan_id, analyzer_version)` keys added in
migration 003. As of M2:

| Analyzer | Version | Covers |
|---|---|---|
| `headers` | `0.1.0` | HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CSP presence |
| `csp` | `0.1.0` | Directive-level parse, unsafe-inline/unsafe-eval/wildcard/frame-ancestors, documented `is_restrictive` |
| `cookies` | `0.1.0` | Secure/HttpOnly/SameSite per cookie |
| `tls` | `0.1.0` | Protocol version, cipher suite, certificate chain, weak-cipher marker list |
| `fingerprint` | `0.1.0` | CMS/framework/server/CDN/JS libraries |
| `dns_email` | `0.1.0` | SPF/DMARC/DKIM/MX — domain-level email-spoofing-resistance posture, distinct from website security |
| `wellknown` | `0.1.0` | robots.txt, sitemap.xml, security.txt (narrow RFC 9116 check: Contact+Expires only) |
| `cors` | `0.1.0` | CORS policy characteristics (ACAO/wildcard/reflection/credentials) — not exploitability |
| `crawler` | `0.2.0` | (`config.py` `IWSS_CRAWLER_VERSION`) — bumped at `v0.2.0-baseline-v1` |

Deliberately not implemented yet, by decision (M3 is intentionally scoped
to the eight analyzers above — see roadmap §9): COOP/COEP/CORP, WAF/CDN
signature split. Expanding scope further before `pilot_5000`/`final_50000`
run was assessed as a bigger risk than measuring with what already exists.

**Module coverage differs by run, and this is stated, not backfilled.**
The initial `pilot_500` dataset was collected before the introduction of
additional measurement modules (DNS/email security, well-known resources,
and CORS analysis). Therefore, these measurements are unavailable for
this subset, and analyses involving these features exclude `pilot_500`.
`dataset/primary_it/manifest.json` defines this precisely as three
analysis subsets — Dataset A (security headers corpus, n=8,829, all three
runs), Dataset B (extended security posture, n=8,438, `pilot_5000` +
`final_remaining_pool` only), Dataset C (full `primary_it`, n=10,022,
sample description and coverage reporting only) — so no statistic is
computed against a base rate it doesn't actually have.

Because every result row is versioned rather than overwritten, a future
`csp v0.2.0` with a richer parser adds new rows alongside `v0.1.0`'s — old
analysis stays reproducible even after the code improves. This is what makes
a longitudinal follow-up paper (*Evolution of Web Security Practices in
Italian Websites*) possible without re-crawling history.

## 5. Ethics statement

- **HTTP GET only** — every request is a standard, unauthenticated GET any
  browser would send. No POST, no form submission, no session establishment.
- **No exploitation, no brute force** — no payloads, no fuzzing, no
  vulnerability probing. `checks/active/`-equivalent code was never ported
  into this codebase (roadmap §A.3) — this is a structural guarantee, not a
  configuration flag that could be flipped.
- **Fixed, small endpoint list per site** — `GET /`, a TLS handshake on
  port 443, `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt` (with
  `/security.txt` fallback), and one CORS probe GET with a synthetic
  `Origin` header — 8.3 requests/domain on average as measured (see §6).
  All standard, publicly-intended resources or standard cross-origin
  browser behavior; no path fuzzing, no non-standard endpoints.
- **Rate limiting** — a global network-concurrency budget
  (`crawler/network_budget.py`, covering HTTP/TLS/DNS/well-known/CORS, not
  just the primary fetch — see §6) plus a per-host minimum interval
  (`crawler/rate_limiter.py`), so no single site is hit faster than a
  normal visitor would load it, regardless of overall crawl throughput.
- **Identifiable User-Agent** — `IWSS_USER_AGENT` in `.env` names the crawler
  and gives a contact point.
- **No opt-out registry, by design** — this is a passive-only measurement
  study: every request is a standard, unauthenticated GET that any browser
  sends when loading a public homepage. No personal data, no
  authentication-gated content, no sensitive data of any kind is collected —
  only publicly-served HTTP response metadata (headers, TLS parameters,
  technology fingerprints). Because nothing sensitive is collected and no
  non-standard access is attempted, this study does not implement a
  per-domain opt-out/exclusion mechanism, consistent with standard practice
  in internet-scale passive measurement research (Mozilla Observatory,
  Shodan, Censys, and prior Tranco-scale header-adoption studies all operate
  the same way).
- **Transparency page, not an opt-out mechanism** — a page will be published
  at `https://f-hack.com/iwss` explaining the project's purpose,
  methodology, and a contact address, so any site operator who notices the
  crawler and has questions has somewhere to go. It does not gate or exclude
  anything; the crawler's behavior doesn't depend on it.
- **Data handling policy**:
  - Domain names are stored in cleartext in the research database — this is
    operational research data (needed for re-scanning under the
    longitudinal design and for internal validity checks), not a public
    artifact by default.
  - The paper itself does not name or cite specific domains as examples of
    good or bad security posture — results are reported in aggregate
    (adoption percentages, statistical tests), never as a
    naming-and-shaming exercise against individual sites or organizations.
  - **Public release format (revised)**: a row-level anonymized export,
    not aggregates-only — each row keyed by an internal site identifier
    plus `SHA-256(domain)` in place of the cleartext domain, carrying
    every measured feature (headers, CSP, cookies, TLS, fingerprint,
    DNS/email, well-known, CORS). This lets other researchers reproduce
    the statistical analysis itself (chi-square, correlations, regression
    — all of which need row-level data, not just our published aggregates)
    without being able to casually look up which specific site had which
    finding. It's not perfect anonymity (anyone who already suspects a
    specific domain can hash it and check), but it's a defensible balance
    between reproducibility and not publishing a directly browsable
    per-site security report card. Aggregated charts/tables in the paper
    itself are unaffected by this — this only concerns a supplementary
    dataset release, not required for the paper to stand on its own.
- **No response body persisted** — only a SHA-256 hash and size/content-type
  metadata are stored (`raw_http_responses`), enforced by a hard read cap in
  the fetcher (5MB), not just a policy choice.

## 6. Measurement platform performance

Recorded once the concurrency model was actually correct (see below) —
numbers from before that fix are discarded, not reported, since they
reflected a bug, not the platform's real behavior.

- **Hardware**: homeServer, Ubuntu 24.04.4 LTS, 4 vCPU, 31GB RAM, PostgreSQL
  16.14 running natively on the same host as the crawler.
- **Concurrency budget**: the crawler enforces a single global network
  concurrency budget of 20 simultaneous network operations
  (`crawler/network_budget.py`), covering HTTP fetch, TLS handshake + DNS
  resolution, and the well-known/CORS probe burst — not just the primary
  HTTP fetch. Validation on the disposable smoke-test set showed the
  configured budget (20) matched the observed peak concurrent operations
  (20) exactly, on two consecutive runs. Per-operation-type budgets
  (separate `global_http`/`global_dns`/`global_tls` limits) are a documented
  future refinement, not needed for `baseline_v1`.
- **Requests per domain**: 8.3 attempted on average (1 HTTP + 3 TLS-related
  connections + up to 4 well-known/CORS requests), measured via
  `scan_metrics`, not assumed.
- **Timeout policy**: 12s HTTP request timeout; 8s TLS handshake timeout
  (unchanged); 3s timeout for the TLS 1.0/1.1 legacy-support probes
  specifically (reduced from 8s — most rejections are near-instant, and the
  original 8s per probe was found to dominate per-domain TLS cost); 8s for
  well-known/CORS requests.
- **Throughput observed**: 6,127-8,153 domains/hour on the 105-domain
  smoke-test set (two consecutive runs, `concurrency=20`) — not
  extrapolated, measured. This is markedly lower than an earlier,
  pre-concurrency-fix measurement (~31,500/hour), which is the expected and
  correct outcome: that earlier number reflected a network-budget bug (see
  roadmap) under which `concurrency=20` did not actually bound the crawler's
  real network activity. The lower, bounded number is the one that can be
  cited, because it is true.
- **Queueing delay is measured separately from active measurement time.**
  A scan acquires the shared network concurrency budget three times (HTTP
  fetch, TLS+DNS, well-known/CORS) — each acquisition's wait-to-acquire and
  subsequent pure work duration are timed independently (`scan_metrics`:
  `queue_wait_ms`, `http_duration_ms`, `tls_dns_queue_wait_ms`,
  `tls_dns_duration_ms`, `aux_queue_wait_ms`, `aux_duration_ms`). Verified
  on a 105-domain micro-test (`concurrency=20`) that these components sum
  to `total_duration_ms` within 0.4%. Median breakdown: queue wait 920ms +
  HTTP 391ms + TLS/DNS wait 5,509ms + TLS/DNS 1,173ms + well-known/CORS
  wait 10,245ms + well-known/CORS 1,490ms — pure network work totals
  ~3.05s/domain, while budget-coordination wait totals ~16.7s/domain under
  this concurrency setting and task-creation pattern (all domains
  scheduled at once). This means per-domain wall-clock cost is dominated
  by the crawler's own concurrency policy, not by network or analyzer
  work — a deliberate methodological choice (bounded concurrency), not a
  performance defect, and the paper can state precisely that queueing
  delay was measured and separated from active measurement time, not
  conflated with it.
