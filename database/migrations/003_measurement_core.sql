-- iwss migration 003: measurement core hardening (pre-M2)
-- scans and everything hanging off it currently hold only disposable
-- pilot_smoke_test data (see dataset/pilot_smoke_test/README.md) — truncating
-- rather than backfilling provenance columns onto throwaway rows. sites,
-- datasets and crawl_runs are left untouched.

TRUNCATE scans RESTART IDENTITY CASCADE;

-- 1. raw_http_responses: hash + metadata only, never the full body (would
--    be enormous at 50k-100k scale). This is what lets a forgotten feature
--    ("do sites with a generator meta tag have different posture?") be
--    answered later without re-crawling a moving target.
DROP TABLE raw_http_responses;
CREATE TABLE raw_http_responses (
    scan_id          BIGINT PRIMARY KEY REFERENCES scans(scan_id),
    headers_raw      JSONB NOT NULL,
    body_sha256      TEXT,
    body_size_bytes  INTEGER,
    content_type     TEXT,
    charset          TEXT,
    server_date      TEXT
);

-- 2. Analyzer provenance: composite PK so re-running with an improved
--    parser adds a new snapshot instead of overwriting history (mirrors
--    scores.formula_version from migration 002).
ALTER TABLE security_headers ADD COLUMN analyzer_version TEXT NOT NULL;
ALTER TABLE security_headers DROP CONSTRAINT security_headers_pkey;
ALTER TABLE security_headers ADD PRIMARY KEY (scan_id, analyzer_version);

-- CSP graduates to its own table: directive-level detail doesn't belong as
-- extra nullable columns bolted onto security_headers. security_headers
-- keeps only presence/raw value (set by the headers analyzer); this table
-- only gets a row when CSP is actually present.
ALTER TABLE security_headers DROP COLUMN csp_unsafe_inline;
ALTER TABLE security_headers DROP COLUMN csp_unsafe_eval;
ALTER TABLE security_headers DROP COLUMN csp_wildcard_source;
ALTER TABLE security_headers DROP COLUMN csp_frame_ancestors_present;

CREATE TABLE csp_analysis (
    scan_id             BIGINT REFERENCES scans(scan_id),
    analyzer_version    TEXT NOT NULL,
    directives          JSONB NOT NULL,
    directive_count     INTEGER NOT NULL,
    has_unsafe_inline   BOOLEAN NOT NULL,
    has_unsafe_eval     BOOLEAN NOT NULL,
    has_wildcard_source BOOLEAN NOT NULL,
    frame_ancestors_present BOOLEAN NOT NULL,
    is_restrictive      BOOLEAN NOT NULL,
    PRIMARY KEY (scan_id, analyzer_version)
);

ALTER TABLE cookies ADD COLUMN analyzer_version TEXT NOT NULL;

ALTER TABLE tls_info ADD COLUMN analyzer_version TEXT NOT NULL;
ALTER TABLE tls_info DROP CONSTRAINT tls_info_pkey;
ALTER TABLE tls_info ADD PRIMARY KEY (scan_id, analyzer_version);

ALTER TABLE certificates ADD COLUMN analyzer_version TEXT NOT NULL;
ALTER TABLE certificates DROP CONSTRAINT certificates_pkey;
ALTER TABLE certificates ADD PRIMARY KEY (scan_id, analyzer_version);

ALTER TABLE technologies ADD COLUMN analyzer_version TEXT NOT NULL;
