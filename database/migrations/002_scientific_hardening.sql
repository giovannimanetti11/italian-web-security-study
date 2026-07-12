-- iwss migration 002: scientific hardening after M0 code review
-- Fixes blocking/high-priority findings before M1 (concurrent crawler) starts.

-- 1. crawl_runs: distinguish "still running" from "crashed mid-run", and
--    version the *methodology* (measurement_version) separately from the
--    *code* (crawler_version) — the paper cites the former.
ALTER TABLE crawl_runs
    ADD COLUMN status TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'completed', 'aborted')),
    ADD COLUMN measurement_version TEXT;

-- 2. scans: explicit, closed categorical outcome instead of inferring
--    success/failure from a mix of nullable columns. Every 100k-domain run
--    will produce large volumes of every one of these; they are data, not
--    exceptions.
ALTER TABLE scans
    ADD COLUMN scan_status TEXT NOT NULL DEFAULT 'success'
        CHECK (scan_status IN (
            'success', 'dns_error', 'timeout', 'tls_error',
            'connection_error', 'blocked', 'http_error', 'invalid_response'
        ));
ALTER TABLE scans ALTER COLUMN scan_status DROP DEFAULT;  -- must be set explicitly per scan

-- 3. scans: hard uniqueness guarantee so concurrent workers or a retried
--    job can never silently double-insert a scan for the same site in the
--    same run. This is what makes "site with no scans row for this run_id
--    = pending" safe under an asyncio worker pool.
ALTER TABLE scans ADD CONSTRAINT uq_scans_site_run UNIQUE (site_id, run_id);

-- 4. crawl_events: per-scan diagnostic trail for post-hoc debugging once
--    the dataset is tens of thousands of rows and something looks wrong
--    six months from now.
CREATE TABLE crawl_events (
    id           BIGSERIAL PRIMARY KEY,
    scan_id      BIGINT REFERENCES scans(scan_id),
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    level        TEXT NOT NULL CHECK (level IN ('debug', 'info', 'warning', 'error')),
    message      TEXT NOT NULL
);
CREATE INDEX idx_crawl_events_scan ON crawl_events(scan_id);

-- 5. raw_http_responses: full-fidelity capture for the pilot phase only.
--    Research reality: you discover you want a new feature after the fact,
--    and re-crawling live third-party domains months later measures a
--    different (moving) target, not the original dataset. Body stored as
--    a hash by default; full body storage is a crawler-level decision, not
--    a schema one. Intended to be pilot-scoped, not a permanent fixture.
CREATE TABLE raw_http_responses (
    scan_id      BIGINT PRIMARY KEY REFERENCES scans(scan_id),
    headers_raw  JSONB NOT NULL,
    body_hash    TEXT,
    body_size_bytes INTEGER,
    content_type TEXT,
    server_time  TEXT
);

-- 6. scores: allow multiple scoring-formula versions to coexist against the
--    same immutable scan, instead of a formula revision overwriting
--    history. This is what "score is a computed view over raw facts,
--    recomputable without re-crawling" actually requires structurally.
ALTER TABLE scores DROP CONSTRAINT scores_pkey;
ALTER TABLE scores ADD PRIMARY KEY (scan_id, formula_version);
