"""Write layer. One function per table-group insert. All SQL is
parameterized (asyncpg $N placeholders), never string-built.
"""

import json

import asyncpg

from analyzers.cookies import CookieResult
from analyzers.cors import CORSResult
from analyzers.csp import CSPResult
from analyzers.dns_email import DNSEmailResult
from analyzers.fingerprint import TechnologyResult
from analyzers.headers import SecurityHeadersResult
from analyzers.tls import CertificateResult, TLSResult
from analyzers.wellknown import WellknownResult
from crawler.models import FetchResult


async def get_or_create_dataset(
    conn: asyncpg.Connection, code: str, name: str, description: str
) -> int:
    dataset_id = await conn.fetchval("SELECT dataset_id FROM datasets WHERE code=$1", code)
    if dataset_id is None:
        dataset_id = await conn.fetchval(
            "INSERT INTO datasets (code, name, description) VALUES ($1,$2,$3) RETURNING dataset_id",
            code,
            name,
            description,
        )
    return dataset_id


async def ensure_sites(
    conn: asyncpg.Connection, dataset_id: int, domains: list[str]
) -> dict[str, int]:
    result: dict[str, int] = {}
    for domain in domains:
        tld = domain.rsplit(".", 1)[-1]
        site_id = await conn.fetchval(
            """
            INSERT INTO sites (dataset_id, domain, tld) VALUES ($1,$2,$3)
            ON CONFLICT (dataset_id, domain) DO UPDATE SET domain = EXCLUDED.domain
            RETURNING site_id
            """,
            dataset_id,
            domain,
            tld,
        )
        result[domain] = site_id
    return result


async def create_run(
    conn: asyncpg.Connection,
    dataset_id: int,
    run_label: str,
    crawler_version: str,
    measurement_version: str,
    config_snapshot: dict,
) -> int:
    return await conn.fetchval(
        """
        INSERT INTO crawl_runs (
            dataset_id, run_label, crawler_version, measurement_version, config_snapshot
        )
        VALUES ($1,$2,$3,$4,$5) RETURNING run_id
        """,
        dataset_id,
        run_label,
        crawler_version,
        measurement_version,
        json.dumps(config_snapshot),
    )


async def finish_run(conn: asyncpg.Connection, run_id: int, status: str) -> None:
    await conn.execute(
        "UPDATE crawl_runs SET finished_at = now(), status = $2 WHERE run_id = $1",
        run_id,
        status,
    )


async def insert_scan(
    conn: asyncpg.Connection, site_id: int, run_id: int, fetch: FetchResult
) -> int:
    redirect_chain_json = json.dumps(
        [{"url": hop.url, "status_code": hop.status_code} for hop in fetch.redirect_chain]
    )
    return await conn.fetchval(
        """
        INSERT INTO scans (
            site_id, run_id, requested_url, final_url, status_code,
            redirect_count, redirect_chain, dns_resolved, connect_error,
            response_time_ms, http_version, http3_advertised, scan_status
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        RETURNING scan_id
        """,
        site_id,
        run_id,
        fetch.requested_url,
        fetch.final_url,
        fetch.status_code,
        fetch.redirect_count,
        redirect_chain_json,
        fetch.dns_resolved,
        fetch.connect_error,
        fetch.response_time_ms,
        fetch.http_version,
        fetch.http3_advertised,
        fetch.scan_status,
    )


async def insert_security_headers(
    conn: asyncpg.Connection, scan_id: int, result: SecurityHeadersResult, analyzer_version: str
) -> None:
    await conn.execute(
        """
        INSERT INTO security_headers (
            scan_id, analyzer_version, csp_present, csp_raw, hsts_present, hsts_max_age,
            hsts_include_subdomains, hsts_preload, xfo_present, xfo_value,
            xcto_present, referrer_policy_present, referrer_policy_value,
            permissions_policy_present
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        """,
        scan_id,
        analyzer_version,
        result.csp_present,
        result.csp_raw,
        result.hsts_present,
        result.hsts_max_age,
        result.hsts_include_subdomains,
        result.hsts_preload,
        result.xfo_present,
        result.xfo_value,
        result.xcto_present,
        result.referrer_policy_present,
        result.referrer_policy_value,
        result.permissions_policy_present,
    )


async def insert_csp_analysis(
    conn: asyncpg.Connection, scan_id: int, result: CSPResult, analyzer_version: str
) -> None:
    await conn.execute(
        """
        INSERT INTO csp_analysis (
            scan_id, analyzer_version, directives, directive_count,
            has_unsafe_inline, has_unsafe_eval, has_wildcard_source,
            frame_ancestors_present, is_restrictive
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        """,
        scan_id,
        analyzer_version,
        json.dumps(result.directives),
        result.directive_count,
        result.has_unsafe_inline,
        result.has_unsafe_eval,
        result.has_wildcard_source,
        result.frame_ancestors_present,
        result.is_restrictive,
    )


async def insert_cookies(
    conn: asyncpg.Connection, scan_id: int, results: list[CookieResult], analyzer_version: str
) -> None:
    await conn.executemany(
        """
        INSERT INTO cookies (scan_id, name, secure, httponly, samesite, analyzer_version)
        VALUES ($1,$2,$3,$4,$5,$6)
        """,
        [
            (scan_id, r.name, r.secure, r.httponly, r.samesite, analyzer_version)
            for r in results
        ],
    )


async def insert_tls_info(
    conn: asyncpg.Connection, scan_id: int, result: TLSResult, analyzer_version: str
) -> None:
    await conn.execute(
        """
        INSERT INTO tls_info (
            scan_id, analyzer_version, tls_supported, tls_version_negotiated,
            tls10_supported, tls11_supported, cipher_suite, weak_cipher
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        """,
        scan_id,
        analyzer_version,
        result.tls_supported,
        result.tls_version_negotiated,
        result.tls10_supported,
        result.tls11_supported,
        result.cipher_suite,
        result.weak_cipher,
    )


async def insert_certificate(
    conn: asyncpg.Connection, scan_id: int, result: CertificateResult, analyzer_version: str
) -> None:
    await conn.execute(
        """
        INSERT INTO certificates (
            scan_id, analyzer_version, subject_cn, issuer_cn, issuer_org,
            not_before, not_after, days_until_expiry, self_signed,
            key_type, key_size, san_count
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        """,
        scan_id,
        analyzer_version,
        result.subject_cn,
        result.issuer_cn,
        result.issuer_org,
        result.not_before,
        result.not_after,
        result.days_until_expiry,
        result.self_signed,
        result.key_type,
        result.key_size,
        result.san_count,
    )


async def insert_technologies(
    conn: asyncpg.Connection, scan_id: int, results: list[TechnologyResult], analyzer_version: str
) -> None:
    await conn.executemany(
        """
        INSERT INTO technologies (
            scan_id, category, name, version, detection_method, analyzer_version
        )
        VALUES ($1,$2,$3,$4,$5,$6)
        """,
        [
            (scan_id, r.category, r.name, r.version, r.detection_method, analyzer_version)
            for r in results
        ],
    )


async def insert_raw_http_response(
    conn: asyncpg.Connection, scan_id: int, fetch: FetchResult
) -> None:
    await conn.execute(
        """
        INSERT INTO raw_http_responses (
            scan_id, headers_raw, body_sha256, body_size_bytes, content_type, charset, server_date
        ) VALUES ($1,$2,$3,$4,$5,$6,$7)
        """,
        scan_id,
        json.dumps(fetch.headers),
        fetch.body_sha256,
        fetch.body_size_bytes,
        fetch.content_type,
        fetch.charset,
        fetch.server_date,
    )


async def insert_dns_email(
    conn: asyncpg.Connection, scan_id: int, result: DNSEmailResult, analyzer_version: str
) -> None:
    await conn.execute(
        """
        INSERT INTO dns_email_security (
            scan_id, analyzer_version, spf_present, spf_raw, dmarc_present,
            dmarc_raw, dmarc_policy, dkim_present, dkim_selector, mx_present
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        """,
        scan_id,
        analyzer_version,
        result.spf_present,
        result.spf_raw,
        result.dmarc_present,
        result.dmarc_raw,
        result.dmarc_policy,
        result.dkim_present,
        result.dkim_selector,
        result.mx_present,
    )


async def insert_wellknown(
    conn: asyncpg.Connection, scan_id: int, result: WellknownResult, analyzer_version: str
) -> None:
    await conn.execute(
        """
        INSERT INTO wellknown_resources (
            scan_id, analyzer_version, robots_txt_present, robots_disallow_count,
            robots_sensitive_path_count, sitemap_xml_present, security_txt_present,
            security_txt_rfc9116_compliant
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        """,
        scan_id,
        analyzer_version,
        result.robots_txt_present,
        result.robots_disallow_count,
        result.robots_sensitive_path_count,
        result.sitemap_xml_present,
        result.security_txt_present,
        result.security_txt_rfc9116_compliant,
    )


async def insert_cors(
    conn: asyncpg.Connection, scan_id: int, result: CORSResult, analyzer_version: str
) -> None:
    await conn.execute(
        """
        INSERT INTO cors_analysis (
            scan_id, analyzer_version, acao_present, acao_value,
            acao_is_wildcard, acao_reflects_origin, acac_present
        ) VALUES ($1,$2,$3,$4,$5,$6,$7)
        """,
        scan_id,
        analyzer_version,
        result.acao_present,
        result.acao_value,
        result.acao_is_wildcard,
        result.acao_reflects_origin,
        result.acac_present,
    )


async def insert_scan_metrics(
    conn: asyncpg.Connection,
    scan_id: int,
    requests_attempted: int,
    requests_completed: int,
    dns_queries: int,
    tls_handshake_duration_ms: int | None,
    http_requests_duration_ms: int | None,
    analyzer_duration_ms: int | None,
    total_duration_ms: int,
    queue_wait_ms: int,
    measurement_duration_ms: int,
    http_duration_ms: int | None,
    tls_dns_queue_wait_ms: int | None,
    tls_dns_duration_ms: int | None,
    aux_queue_wait_ms: int | None,
    aux_duration_ms: int | None,
) -> None:
    await conn.execute(
        """
        INSERT INTO scan_metrics (
            scan_id, requests_attempted, requests_completed, dns_queries,
            tls_handshake_duration_ms, http_requests_duration_ms,
            analyzer_duration_ms, total_duration_ms,
            queue_wait_ms, measurement_duration_ms,
            http_duration_ms, tls_dns_queue_wait_ms, tls_dns_duration_ms,
            aux_queue_wait_ms, aux_duration_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
        """,
        scan_id,
        requests_attempted,
        requests_completed,
        dns_queries,
        tls_handshake_duration_ms,
        http_requests_duration_ms,
        analyzer_duration_ms,
        total_duration_ms,
        queue_wait_ms,
        measurement_duration_ms,
        http_duration_ms,
        tls_dns_queue_wait_ms,
        tls_dns_duration_ms,
        aux_queue_wait_ms,
        aux_duration_ms,
    )


async def log_event(
    conn: asyncpg.Connection, scan_id: int | None, level: str, message: str
) -> None:
    await conn.execute(
        "INSERT INTO crawl_events (scan_id, level, message) VALUES ($1,$2,$3)",
        scan_id,
        level,
        message,
    )
