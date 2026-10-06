"""Reusable crawl-run orchestration: scan_one / run_crawl / print_summary.
Shared by the disposable smoke test (crawler/pilot_run.py) and real
research runs (crawler/pilot_500_run.py, future pilot_5000/final_50000) —
avoids duplicating the scan logic between throwaway and real runs.

Every scan runs under a MeasurementProfile (crawler/profiles.py) — which
analyzers execute, and therefore what a "scan" actually measures, is
explicit and recorded in crawl_runs.config_snapshot, not implied by
whatever the code happened to do that day. Adding an analyzer changes the
measurement scope; profiles make that a declared fact, not a silent one.
"""

import asyncio
import dataclasses
import time

import httpx

import analyzers.cookies as cookies_analyzer
import analyzers.cors as cors_analyzer
import analyzers.csp as csp_analyzer
import analyzers.dns_email as dns_email_analyzer
import analyzers.fingerprint as fingerprint_analyzer
import analyzers.headers as headers_analyzer
import analyzers.tls as tls_analyzer
import analyzers.wellknown as wellknown_analyzer
from config import CRAWLER
from crawler.cors_fetcher import fetch_cors
from crawler.dns_fetcher import fetch_dns
from crawler.fetcher import fetch_site
from crawler.models import FetchResult
from crawler.network_budget import NetworkBudget
from crawler.network_safety import enforce_public_http_request
from crawler.profiles import BASELINE_V1, MeasurementProfile
from crawler.rate_limiter import PerHostRateLimiter
from crawler.tls_fetcher import fetch_tls
from crawler.wellknown_fetcher import fetch_wellknown
from database.pool import create_pool
from database.repository import (
    create_run,
    ensure_sites,
    finish_run,
    get_or_create_dataset,
    insert_certificate,
    insert_cookies,
    insert_cors,
    insert_csp_analysis,
    insert_dns_email,
    insert_raw_http_response,
    insert_scan,
    insert_scan_metrics,
    insert_security_headers,
    insert_technologies,
    insert_tls_info,
    insert_wellknown,
    log_event,
)

# Bound on concurrent connections to a single host for the well-known +
# CORS probe burst — was previously fully sequential (measured ~15s avg
# HTTP time per domain, dominating total scan time). Parallelizing these
# independent, lightweight requests cuts that to roughly the slowest
# individual request instead of their sum, while still capping how many
# simultaneous connections one host sees at once (politeness, not just a
# performance knob).
PER_HOST_BURST_CONCURRENCY = 3


async def scan_one(
    client: httpx.AsyncClient,
    pool,
    rate_limiter: PerHostRateLimiter,
    profile: MeasurementProfile,
    network_budget: NetworkBudget,
    site_id: int,
    run_id: int,
    domain: str,
) -> FetchResult | None:
    """One domain must never be able to sink the whole batch. Found via a
    real crash at pilot_5000 scale: a single site returning
    TLSV13_ALERT_CERTIFICATE_REQUIRED raised an exception outside any of
    the per-fetcher try/excepts (an async callback deep in httpx/anyio's
    HTTP/2 handling, not a normal await-point failure), which propagated
    through asyncio.gather and cancelled all 4,999 other in-flight scans.
    Every per-fetcher error path already turns failures into scan_status
    data (that was the whole point of the M0 review's #1 finding) — this
    is the same principle applied one level up, catching whatever a
    fetcher's own try/except didn't anticipate. Returns None (domain
    skipped, logged) rather than ever letting an exception escape.
    """
    try:
        return await _scan_one_unsafe(
            client, pool, rate_limiter, profile, network_budget, site_id, run_id, domain
        )
    except Exception as exc:
        try:
            async with pool.acquire() as conn:
                await log_event(
                    conn,
                    None,
                    "error",
                    f"{domain}: unhandled exception in scan_one — {type(exc).__name__}: {exc}",
                )
        except Exception:
            pass  # logging itself must never propagate and take down the batch either
        return None


async def _scan_one_unsafe(
    client: httpx.AsyncClient,
    pool,
    rate_limiter: PerHostRateLimiter,
    profile: MeasurementProfile,
    network_budget: NetworkBudget,
    site_id: int,
    run_id: int,
    domain: str,
) -> FetchResult:
    t_scan_start = time.monotonic()
    requests_attempted = 0
    requests_completed = 0
    analyzer_seconds = 0.0
    aux_queue_wait_ms: int | None = None
    aux_duration_ms: int | None = None

    def _timed_analyze(fn, *args):
        nonlocal analyzer_seconds
        t0 = time.monotonic()
        result = fn(*args)
        analyzer_seconds += time.monotonic() - t0
        return result

    # Every phase acquires the same global network_budget three times
    # (HTTP, TLS+DNS, well-known/CORS) — pilot_5000 revealed that only
    # isolating the first acquisition's wait still left later phases'
    # queueing hidden inside what looked like "measurement time". Each
    # phase below is timed as wait-to-acquire, then pure work duration,
    # so total_duration_ms is fully attributable, not partially opaque.
    await rate_limiter.wait(domain)
    async with network_budget.acquire():
        t_http_acquired = time.monotonic()
        queue_wait_ms = int((t_http_acquired - t_scan_start) * 1000)
        fetch = await fetch_site(client, domain)
    t_http_done = time.monotonic()
    http_duration_ms = int((t_http_done - t_http_acquired) * 1000)
    requests_attempted += 1
    requests_completed += 1 if fetch.scan_status == "success" else 0

    await rate_limiter.wait(domain)
    # DNS queries go to DNS servers, not the target host — no rate-limiter
    # wait needed, they don't add load to the site being measured. They DO
    # still need the global network budget: fetch_dns's internal 23-query
    # gather previously ran with no concurrency bound at all (the bug this
    # NetworkBudget fixes) — one budget slot covers the whole TLS+DNS
    # gather, not one slot per underlying query.
    async with network_budget.acquire():
        t_tls_dns_acquired = time.monotonic()
        tls_dns_queue_wait_ms = int((t_tls_dns_acquired - t_http_done) * 1000)
        tls_fetch, dns_fetch = await asyncio.gather(fetch_tls(domain), fetch_dns(domain))
    t_tls_dns_done = time.monotonic()
    tls_dns_duration_ms = int((t_tls_dns_done - t_tls_dns_acquired) * 1000)
    requests_attempted += 3  # 1 real handshake + 2 constrained-version probes
    requests_completed += 1 if tls_fetch.tls_ok else 0
    dns_queries = dns_fetch.queries_made

    wellknown_fetch = None
    cors_fetch = None
    wellknown_enabled = "wellknown" in profile.enabled_analyzers
    cors_enabled = "cors" in profile.enabled_analyzers
    # Legacy aggregate (kept for continuity with pilot_500/pilot_5000 rows,
    # which predate the per-phase breakdown) — HTTP + well-known + CORS
    # combined, as it always meant before this migration.
    http_requests_duration_ms = http_duration_ms

    if fetch.scan_status == "success" and (wellknown_enabled or cors_enabled):
        await rate_limiter.wait(domain)
        # One pacing wait for the whole burst, not per sub-request — the
        # burst's own concurrency is bounded by host_burst_sem (max
        # simultaneous connections to THIS host), while network_budget
        # bounds this domain's share of the GLOBAL concurrent-operations
        # budget alongside every other domain's HTTP/TLS/DNS/burst phases.
        host_burst_sem = asyncio.Semaphore(PER_HOST_BURST_CONCURRENCY)

        wellknown_task = (
            fetch_wellknown(client, domain, host_burst_sem) if wellknown_enabled else None
        )
        cors_task = fetch_cors(client, domain, host_burst_sem) if cors_enabled else None

        async with network_budget.acquire():
            t_aux_acquired = time.monotonic()
            aux_queue_wait_ms = int((t_aux_acquired - t_tls_dns_done) * 1000)
            if wellknown_task is not None and cors_task is not None:
                wellknown_fetch, cors_fetch = await asyncio.gather(wellknown_task, cors_task)
            elif wellknown_task is not None:
                wellknown_fetch = await wellknown_task
            elif cors_task is not None:
                cors_fetch = await cors_task
        t_aux_done = time.monotonic()
        aux_duration_ms = int((t_aux_done - t_aux_acquired) * 1000)

        if wellknown_fetch is not None:
            requests_attempted += wellknown_fetch.requests_attempted
            requests_completed += 1 if wellknown_fetch.robots_txt is not None else 0
            http_requests_duration_ms += wellknown_fetch.elapsed_ms

        if cors_fetch is not None:
            requests_attempted += 1
            requests_completed += 1 if cors_fetch.acao_raw is not None else 0
            http_requests_duration_ms += cors_fetch.elapsed_ms

    async with pool.acquire() as conn, conn.transaction():
        scan_id = await insert_scan(conn, site_id, run_id, fetch)

        if fetch.scan_status == "success":
            if "headers" in profile.enabled_analyzers:
                headers_result = _timed_analyze(headers_analyzer.analyze_headers, fetch)
                await insert_security_headers(
                    conn, scan_id, headers_result, headers_analyzer.ANALYZER_VERSION
                )

                csp_enabled = "csp" in profile.enabled_analyzers
                if csp_enabled and headers_result.csp_present and headers_result.csp_raw:
                    csp_result = _timed_analyze(csp_analyzer.analyze_csp, headers_result.csp_raw)
                    await insert_csp_analysis(
                        conn, scan_id, csp_result, csp_analyzer.ANALYZER_VERSION
                    )

            if "cookies" in profile.enabled_analyzers:
                cookie_results = _timed_analyze(
                    cookies_analyzer.analyze_cookies, fetch.set_cookie_headers
                )
                if cookie_results:
                    await insert_cookies(
                        conn, scan_id, cookie_results, cookies_analyzer.ANALYZER_VERSION
                    )

            if "fingerprint" in profile.enabled_analyzers:
                tech_results = _timed_analyze(
                    fingerprint_analyzer.analyze_fingerprint, fetch.headers, fetch.body or ""
                )
                if tech_results:
                    await insert_technologies(
                        conn, scan_id, tech_results, fingerprint_analyzer.ANALYZER_VERSION
                    )

            await insert_raw_http_response(conn, scan_id, fetch)

            if wellknown_fetch is not None:
                wellknown_result = _timed_analyze(
                    wellknown_analyzer.analyze_wellknown, wellknown_fetch
                )
                await insert_wellknown(
                    conn, scan_id, wellknown_result, wellknown_analyzer.ANALYZER_VERSION
                )

            if cors_fetch is not None:
                cors_result = _timed_analyze(cors_analyzer.analyze_cors, cors_fetch)
                await insert_cors(conn, scan_id, cors_result, cors_analyzer.ANALYZER_VERSION)
        else:
            await log_event(
                conn, scan_id, "warning", f"{domain}: {fetch.scan_status} — {fetch.connect_error}"
            )

        # DNS/email posture is independent of HTTP reachability — a site
        # can be down over HTTP and still have a working mail setup.
        if "dns_email" in profile.enabled_analyzers:
            dns_email_result = _timed_analyze(dns_email_analyzer.analyze_dns_email, dns_fetch)
            await insert_dns_email(
                conn, scan_id, dns_email_result, dns_email_analyzer.ANALYZER_VERSION
            )

        if "tls" in profile.enabled_analyzers:
            tls_result = _timed_analyze(tls_analyzer.analyze_tls, tls_fetch)
            await insert_tls_info(conn, scan_id, tls_result, tls_analyzer.ANALYZER_VERSION)

            cert_result = _timed_analyze(tls_analyzer.analyze_certificate, tls_fetch)
            if cert_result:
                await insert_certificate(conn, scan_id, cert_result, tls_analyzer.ANALYZER_VERSION)

        if tls_fetch.error:
            await log_event(conn, scan_id, "warning", f"{domain}: tls — {tls_fetch.error}")

        total_duration_ms = int((time.monotonic() - t_scan_start) * 1000)
        measurement_duration_ms = total_duration_ms - queue_wait_ms
        await insert_scan_metrics(
            conn,
            scan_id,
            requests_attempted=requests_attempted,
            requests_completed=requests_completed,
            dns_queries=dns_queries,
            tls_handshake_duration_ms=tls_fetch.elapsed_ms,
            http_requests_duration_ms=http_requests_duration_ms,
            analyzer_duration_ms=int(analyzer_seconds * 1000),
            total_duration_ms=total_duration_ms,
            queue_wait_ms=queue_wait_ms,
            measurement_duration_ms=measurement_duration_ms,
            http_duration_ms=http_duration_ms,
            tls_dns_queue_wait_ms=tls_dns_queue_wait_ms,
            tls_dns_duration_ms=tls_dns_duration_ms,
            aux_queue_wait_ms=aux_queue_wait_ms,
            aux_duration_ms=aux_duration_ms,
        )

    return fetch


async def run_crawl(
    dataset_code: str,
    dataset_name: str,
    dataset_description: str,
    domains: list[str],
    run_label: str,
    measurement_version: str,
    concurrency: int,
    summary_title: str,
    profile: MeasurementProfile = BASELINE_V1,
    extra_config: dict | None = None,
) -> None:
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            dataset_id = await get_or_create_dataset(
                conn, dataset_code, dataset_name, dataset_description
            )
            site_ids = await ensure_sites(conn, dataset_id, domains)

            config_snapshot = dataclasses.asdict(CRAWLER)
            config_snapshot["concurrency"] = concurrency
            config_snapshot["measurement_profile"] = {
                "name": profile.name,
                "enabled_analyzers": sorted(profile.enabled_analyzers),
            }
            if extra_config:
                config_snapshot.update(extra_config)

            run_id = await create_run(
                conn,
                dataset_id,
                run_label=run_label,
                crawler_version=CRAWLER.crawler_version,
                measurement_version=measurement_version,
                config_snapshot=config_snapshot,
            )

        network_budget = NetworkBudget(concurrency)
        rate_limiter = PerHostRateLimiter(CRAWLER.per_host_min_interval)
        status = "completed"
        try:
            async with httpx.AsyncClient(
                http2=True,
                verify=False,
                timeout=CRAWLER.request_timeout,
                headers={"User-Agent": CRAWLER.user_agent},
                event_hooks={"request": [enforce_public_http_request]},
            ) as client:
                tasks = [
                    scan_one(
                        client,
                        pool,
                        rate_limiter,
                        profile,
                        network_budget,
                        site_ids[domain],
                        run_id,
                        domain,
                    )
                    for domain in domains
                ]
                # scan_one no longer lets exceptions escape (see its
                # docstring) — return_exceptions=True is defense in depth,
                # not the primary safeguard, in case a future bug reopens
                # that gap.
                results = await asyncio.gather(*tasks, return_exceptions=True)
        except Exception:
            status = "aborted"
            raise
        finally:
            async with pool.acquire() as conn:
                await finish_run(conn, run_id, status)

        skipped = sum(1 for r in results if r is None or isinstance(r, Exception))
        if skipped:
            print(f"\nDomains skipped due to an unhandled per-scan error: {skipped}/{len(domains)}")

        # Diagnostic only, not a research metric — confirms the declared
        # concurrency budget was actually respected in practice.
        peak = network_budget.peak_concurrent
        print(f"\nPeak concurrent network operations: {peak} (budget: {concurrency})")

        await print_summary(pool, run_id, summary_title)
    finally:
        await pool.close()


async def print_summary(pool, run_id: int, title: str) -> None:
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT count(*) FROM scans WHERE run_id=$1", run_id)
        status_rows = await conn.fetch(
            "SELECT scan_status, count(*) c FROM scans WHERE run_id=$1 GROUP BY 1 ORDER BY c DESC",
            run_id,
        )
        timing = await conn.fetchrow(
            """
            SELECT
                percentile_cont(0.5) WITHIN GROUP (ORDER BY response_time_ms) AS p50,
                percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time_ms) AS p95
            FROM scans WHERE run_id=$1 AND scan_status='success'
            """,
            run_id,
        )
        run_row = await conn.fetchrow(
            "SELECT started_at, finished_at FROM crawl_runs WHERE run_id=$1", run_id
        )
        n_success = await conn.fetchval(
            "SELECT count(*) FROM scans WHERE run_id=$1 AND scan_status='success'", run_id
        )
        headers_stats = await conn.fetchrow(
            """
            SELECT
                count(*) FILTER (WHERE hsts_present) AS hsts,
                count(*) FILTER (WHERE csp_present) AS csp,
                count(*) FILTER (WHERE xfo_present) AS xfo,
                count(*) FILTER (WHERE xcto_present) AS xcto,
                count(*) FILTER (WHERE referrer_policy_present) AS referrer,
                count(*) FILTER (WHERE permissions_policy_present) AS permissions
            FROM security_headers sh JOIN scans s ON s.scan_id = sh.scan_id
            WHERE s.run_id = $1
            """,
            run_id,
        )
        csp_stats = await conn.fetchrow(
            """
            SELECT count(*) AS n, count(*) FILTER (WHERE is_restrictive) AS restrictive,
                   count(*) FILTER (WHERE has_unsafe_inline) AS unsafe_inline,
                   count(*) FILTER (WHERE has_wildcard_source) AS wildcard,
                   count(*) FILTER (WHERE NOT frame_ancestors_present) AS no_frame_ancestors
            FROM csp_analysis ca JOIN scans s ON s.scan_id = ca.scan_id
            WHERE s.run_id = $1
            """,
            run_id,
        )
        cookie_stats = await conn.fetchrow(
            """
            SELECT count(*) AS n,
                   count(*) FILTER (WHERE NOT secure) AS insecure,
                   count(*) FILTER (WHERE NOT httponly) AS no_httponly,
                   count(*) FILTER (WHERE samesite IS NULL) AS no_samesite
            FROM cookies c JOIN scans s ON s.scan_id = c.scan_id
            WHERE s.run_id = $1
            """,
            run_id,
        )
        tls_stats = await conn.fetch(
            """
            SELECT tls_version_negotiated, count(*) c
            FROM tls_info t JOIN scans s ON s.scan_id = t.scan_id
            WHERE s.run_id = $1 AND tls_supported
            GROUP BY 1 ORDER BY c DESC
            """,
            run_id,
        )
        weak_cipher_n = await conn.fetchval(
            """
            SELECT count(*) FROM tls_info t JOIN scans s ON s.scan_id = t.scan_id
            WHERE s.run_id = $1 AND weak_cipher
            """,
            run_id,
        )
        tech_stats = await conn.fetch(
            """
            SELECT category, name, count(*) c
            FROM technologies t JOIN scans s ON s.scan_id = t.scan_id
            WHERE s.run_id = $1
            GROUP BY 1, 2 ORDER BY c DESC LIMIT 10
            """,
            run_id,
        )
        dns_stats = await conn.fetchrow(
            """
            SELECT count(*) FILTER (WHERE spf_present) AS spf,
                   count(*) FILTER (WHERE dmarc_present) AS dmarc,
                   count(*) FILTER (WHERE dkim_present) AS dkim
            FROM dns_email_security d JOIN scans s ON s.scan_id = d.scan_id
            WHERE s.run_id = $1
            """,
            run_id,
        )
        wellknown_stats = await conn.fetchrow(
            """
            SELECT count(*) AS n,
                   count(*) FILTER (WHERE robots_txt_present) AS robots,
                   count(*) FILTER (WHERE sitemap_xml_present) AS sitemap,
                   count(*) FILTER (WHERE security_txt_present) AS security_txt
            FROM wellknown_resources w JOIN scans s ON s.scan_id = w.scan_id
            WHERE s.run_id = $1
            """,
            run_id,
        )
        cors_stats = await conn.fetchrow(
            """
            SELECT count(*) AS n,
                   count(*) FILTER (WHERE acao_present) AS acao,
                   count(*) FILTER (WHERE acao_is_wildcard) AS wildcard,
                   count(*) FILTER (WHERE acao_reflects_origin) AS reflects,
                   count(*) FILTER (WHERE acac_present) AS acac
            FROM cors_analysis c JOIN scans s ON s.scan_id = c.scan_id
            WHERE s.run_id = $1
            """,
            run_id,
        )
        metrics = await conn.fetchrow(
            """
            SELECT avg(requests_attempted) AS req_avg, avg(dns_queries) AS dns_avg,
                   avg(tls_handshake_duration_ms) AS tls_avg,
                   avg(http_requests_duration_ms) AS http_avg,
                   avg(analyzer_duration_ms) AS analyzer_avg,
                   avg(total_duration_ms) AS total_avg,
                   percentile_cont(0.5) WITHIN GROUP (ORDER BY queue_wait_ms) AS queue_p50,
                   percentile_cont(0.95) WITHIN GROUP (ORDER BY queue_wait_ms) AS queue_p95,
                   percentile_cont(0.5) WITHIN GROUP (ORDER BY http_duration_ms) AS http_dur_p50,
                   percentile_cont(0.5) WITHIN GROUP
                       (ORDER BY tls_dns_queue_wait_ms) AS tls_dns_wait_p50,
                   percentile_cont(0.5) WITHIN GROUP
                       (ORDER BY tls_dns_duration_ms) AS tls_dns_dur_p50,
                   percentile_cont(0.5) WITHIN GROUP (ORDER BY aux_queue_wait_ms) AS aux_wait_p50,
                   percentile_cont(0.5) WITHIN GROUP (ORDER BY aux_duration_ms) AS aux_dur_p50,
                   avg(queue_wait_ms + http_duration_ms + tls_dns_queue_wait_ms
                       + tls_dns_duration_ms + coalesce(aux_queue_wait_ms, 0)
                       + coalesce(aux_duration_ms, 0)) AS reconstructed_avg
            FROM scan_metrics m JOIN scans s ON s.scan_id = m.scan_id
            WHERE s.run_id = $1
            """,
            run_id,
        )
        failed_examples = await conn.fetch(
            """
            SELECT si.domain, s.scan_status, s.connect_error
            FROM scans s JOIN sites si ON si.site_id = s.site_id
            WHERE s.run_id = $1 AND s.scan_status != 'success'
            ORDER BY s.scan_status LIMIT 15
            """,
            run_id,
        )

    print(f"\n{'=' * 60}\n{title} — {total} domains\n{'=' * 60}")

    if run_row and run_row["started_at"] and run_row["finished_at"]:
        elapsed_s = (run_row["finished_at"] - run_row["started_at"]).total_seconds()
        rate = total / elapsed_s * 3600 if elapsed_s > 0 else 0
        print(f"Elapsed: {elapsed_s:.0f}s  ({rate:.0f} domains/hour)")

    if metrics and metrics["req_avg"] is not None:
        print("\nMeasurement cost per domain (avg):")
        print(f"  requests attempted     {metrics['req_avg']:.1f}")
        print(f"  DNS queries            {metrics['dns_avg']:.1f}")
        print(f"  analyzer time          {metrics['analyzer_avg']:.2f}ms")
        print(f"  total scan time        {metrics['total_avg']:.0f}ms  (avg, all phases + waits)")

        print("\nPer-phase breakdown (median), wait-to-acquire then pure work:")
        print(f"  queue wait  (before HTTP)      {metrics['queue_p50']:.0f}ms")
        print(f"  HTTP fetch  (pure)             {metrics['http_dur_p50']:.0f}ms")
        print(f"  TLS+DNS     wait               {metrics['tls_dns_wait_p50']:.0f}ms")
        print(f"  TLS+DNS     (pure)             {metrics['tls_dns_dur_p50']:.0f}ms")
        if metrics["aux_wait_p50"] is not None:
            print(f"  well-known/CORS wait           {metrics['aux_wait_p50']:.0f}ms")
            print(f"  well-known/CORS (pure)         {metrics['aux_dur_p50']:.0f}ms")

        # Sanity check requested before tagging: total_duration_ms should
        # equal the sum of every wait+work component, within noise from
        # the DB-transaction time (analyzer + inserts) not itself timed
        # per-phase.
        #
        # NOTE: this block previously reused the name `total` for
        # total_avg (avg total_duration_ms in ms), shadowing the domain
        # COUNT `total` used below in the Coverage section — every
        # coverage percentage printed after this block was silently wrong
        # (dividing by a millisecond figure instead of the domain count).
        # Found on final_remaining_pool's real output, not caught by the
        # smaller smoke-test runs where nobody read the percentages
        # closely enough to notice. Renamed to avoid ever repeating this.
        recon = metrics["reconstructed_avg"]
        total_avg_ms = metrics["total_avg"]
        if recon is not None and total_avg_ms:
            diff_pct = abs(total_avg_ms - recon) / total_avg_ms * 100
            print(
                f"\nReconciliation: total_duration_ms avg={total_avg_ms:.0f}ms vs "
                f"sum-of-phases avg={recon:.0f}ms (diff {diff_pct:.1f}%)"
            )

    print("\nCoverage:")
    for row in status_rows:
        print(f"  {row['scan_status']:<20} {row['c']:>4}  ({row['c'] / total * 100:.1f}%)")
    print(f"  reachable/sampled: {n_success}/{total} ({n_success / total * 100:.1f}%)")

    if timing and timing["p50"] is not None:
        p50, p95 = timing["p50"], timing["p95"]
        print(f"\nResponse time (success only): median={p50:.0f}ms p95={p95:.0f}ms")

    if n_success:
        print("\nSecurity mechanism adoption (successful scans only):")
        for label, key in [
            ("HSTS", "hsts"),
            ("CSP", "csp"),
            ("X-Frame-Options", "xfo"),
            ("X-Content-Type-Options", "xcto"),
            ("Referrer-Policy", "referrer"),
            ("Permissions-Policy", "permissions"),
        ]:
            c = headers_stats[key]
            print(f"  {label:<26} {c:>4}/{n_success}  ({c / n_success * 100:.1f}%)")
        if dns_stats:
            for dns_label, dns_key in [("SPF", "spf"), ("DMARC", "dmarc"), ("DKIM", "dkim")]:
                c = dns_stats[dns_key]
                print(f"  {dns_label:<26} {c:>4}/{n_success}  ({c / n_success * 100:.1f}%)")
        if wellknown_stats and wellknown_stats["n"]:
            wn = wellknown_stats["n"]
            sec_txt = wellknown_stats["security_txt"]
            print(f"  {'security.txt':<26} {sec_txt:>4}/{wn}  ({sec_txt / wn * 100:.1f}%)")

    if csp_stats and csp_stats["n"]:
        n = csp_stats["n"]
        print(f"\nCSP analysis ({n} sites with CSP present):")
        print(f"  restrictive              {csp_stats['restrictive']:>4}/{n}")
        print(f"  unsafe-inline            {csp_stats['unsafe_inline']:>4}/{n}")
        print(f"  wildcard source          {csp_stats['wildcard']:>4}/{n}")
        print(f"  missing frame-ancestors  {csp_stats['no_frame_ancestors']:>4}/{n}")

    if cookie_stats and cookie_stats["n"]:
        n = cookie_stats["n"]
        print(f"\nCookie analysis ({n} cookies observed):")
        print(f"  missing Secure           {cookie_stats['insecure']:>4}/{n}")
        print(f"  missing HttpOnly         {cookie_stats['no_httponly']:>4}/{n}")
        print(f"  missing SameSite         {cookie_stats['no_samesite']:>4}/{n}")

    if cors_stats and cors_stats["n"]:
        n = cors_stats["n"]
        print(f"\nCORS policy characteristics ({n} scans probed):")
        print(f"  Access-Control-Allow-Origin present  {cors_stats['acao']:>4}/{n}")
        print(f"  wildcard (*)                         {cors_stats['wildcard']:>4}/{n}")
        print(f"  reflects probe origin                {cors_stats['reflects']:>4}/{n}")
        print(f"  Allow-Credentials: true               {cors_stats['acac']:>4}/{n}")

    if wellknown_stats and wellknown_stats["n"]:
        wn = wellknown_stats["n"]
        print(f"\nWell-known resources ({wn} successful scans):")
        print(f"  robots.txt   {wellknown_stats['robots']:>4}/{wn}")
        print(f"  sitemap.xml  {wellknown_stats['sitemap']:>4}/{wn}")

    if tls_stats:
        print(f"\nTLS version distribution (weak cipher: {weak_cipher_n}):")
        for row in tls_stats:
            print(f"  {row['tls_version_negotiated'] or 'unknown':<12} {row['c']:>4}")

    if tech_stats:
        print("\nTop technologies detected:")
        for row in tech_stats:
            print(f"  {row['category']:<12} {row['name']:<16} {row['c']:>4}")

    if failed_examples:
        print("\nFailure examples (up to 15, for bias inspection):")
        for row in failed_examples:
            print(f"  {row['domain']:<28} {row['scan_status']:<18} {row['connect_error'] or ''}")
