-- iwss: initial schema (Phase 1 — headers, csp, cookies, tls, fingerprint)
-- Dataset separation is structural: every `sites` row belongs to exactly one
-- dataset_id, so cross-dataset analysis requires an explicit join, never an
-- accident. Longitudinal support is built in via crawl_runs.run_label; no
-- later migration is needed to re-run the crawler against the same sites
-- under a new run_label.
--
-- CORS, COOP/COEP/CORP, DNS/email auth, and well-known-resource tables ship
-- in later migrations alongside their analyzers (Phase 1 extension), not
-- speculatively here.

CREATE TABLE datasets (
    dataset_id   SERIAL PRIMARY KEY,
    code         TEXT UNIQUE NOT NULL,   -- 'primary_it', 'sector_pa', 'intl_com', ...
    name         TEXT NOT NULL,
    description  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sites (
    site_id      SERIAL PRIMARY KEY,
    dataset_id   INTEGER NOT NULL REFERENCES datasets(dataset_id),
    domain       TEXT NOT NULL,
    tld          TEXT NOT NULL,
    sector       TEXT,
    sector_source TEXT,
    added_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (dataset_id, domain)
);

CREATE TABLE crawl_runs (
    run_id       SERIAL PRIMARY KEY,
    dataset_id   INTEGER NOT NULL REFERENCES datasets(dataset_id),
    run_label    TEXT NOT NULL,          -- e.g. '2026_07'
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ,
    crawler_version TEXT NOT NULL,
    config_snapshot JSONB NOT NULL,
    UNIQUE (dataset_id, run_label)
);

CREATE TABLE scans (
    scan_id      BIGSERIAL PRIMARY KEY,
    site_id      INTEGER NOT NULL REFERENCES sites(site_id),
    run_id       INTEGER NOT NULL REFERENCES crawl_runs(run_id),
    requested_url TEXT NOT NULL,
    final_url    TEXT,
    status_code  INTEGER,
    redirect_count INTEGER NOT NULL DEFAULT 0,
    redirect_chain JSONB,
    dns_resolved BOOLEAN NOT NULL,
    connect_error TEXT,
    response_time_ms INTEGER,
    http_version TEXT,                  -- '1.1' | '2'
    http3_advertised BOOLEAN NOT NULL DEFAULT false,  -- from Alt-Svc header only, no QUIC handshake
    scanned_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_scans_site ON scans(site_id);
CREATE INDEX idx_scans_run  ON scans(run_id);

CREATE TABLE raw_response_headers (
    id           BIGSERIAL PRIMARY KEY,
    scan_id      BIGINT NOT NULL REFERENCES scans(scan_id),
    header_name  TEXT NOT NULL,
    header_value TEXT
);
CREATE INDEX idx_raw_headers_scan ON raw_response_headers(scan_id);

CREATE TABLE security_headers (
    scan_id      BIGINT PRIMARY KEY REFERENCES scans(scan_id),
    csp_present  BOOLEAN NOT NULL,
    csp_raw      TEXT,
    csp_unsafe_inline BOOLEAN,
    csp_unsafe_eval   BOOLEAN,
    csp_wildcard_source BOOLEAN,
    csp_frame_ancestors_present BOOLEAN,
    hsts_present BOOLEAN NOT NULL,
    hsts_max_age INTEGER,
    hsts_include_subdomains BOOLEAN,
    hsts_preload BOOLEAN,
    xfo_present  BOOLEAN NOT NULL,
    xfo_value    TEXT,
    xcto_present BOOLEAN NOT NULL,
    referrer_policy_present BOOLEAN NOT NULL,
    referrer_policy_value TEXT,
    permissions_policy_present BOOLEAN NOT NULL
);

CREATE TABLE cookies (
    cookie_id    BIGSERIAL PRIMARY KEY,
    scan_id      BIGINT NOT NULL REFERENCES scans(scan_id),
    name         TEXT NOT NULL,
    secure       BOOLEAN NOT NULL,
    httponly     BOOLEAN NOT NULL,
    samesite     TEXT                 -- 'strict' | 'lax' | 'none' | NULL (absent)
);
CREATE INDEX idx_cookies_scan ON cookies(scan_id);

CREATE TABLE tls_info (
    scan_id      BIGINT PRIMARY KEY REFERENCES scans(scan_id),
    tls_supported BOOLEAN NOT NULL,
    tls_version_negotiated TEXT,
    tls10_supported BOOLEAN,
    tls11_supported BOOLEAN,
    cipher_suite TEXT,
    weak_cipher  BOOLEAN
);

CREATE TABLE certificates (
    scan_id      BIGINT PRIMARY KEY REFERENCES scans(scan_id),
    subject_cn   TEXT,
    issuer_cn    TEXT,
    issuer_org   TEXT,
    not_before   TIMESTAMPTZ,
    not_after    TIMESTAMPTZ,
    days_until_expiry INTEGER,
    self_signed  BOOLEAN,
    key_type     TEXT,
    key_size     INTEGER,
    san_count    INTEGER
);

CREATE TABLE technologies (
    tech_id      BIGSERIAL PRIMARY KEY,
    scan_id      BIGINT NOT NULL REFERENCES scans(scan_id),
    category     TEXT NOT NULL,        -- cms | framework | js_library | server | waf | cdn
    name         TEXT NOT NULL,
    version      TEXT,
    detection_method TEXT
);
CREATE INDEX idx_technologies_scan ON technologies(scan_id);

CREATE TABLE scores (
    scan_id      BIGINT PRIMARY KEY REFERENCES scans(scan_id),
    formula_version TEXT NOT NULL,
    score        INTEGER NOT NULL,
    grade        TEXT NOT NULL,
    component_breakdown JSONB NOT NULL
);
