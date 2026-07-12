-- iwss migration 005: CORS analyzer + scan_metrics (measurement cost tracking)

CREATE TABLE cors_analysis (
    scan_id              BIGINT REFERENCES scans(scan_id),
    analyzer_version     TEXT NOT NULL,
    acao_present         BOOLEAN NOT NULL,
    acao_value           TEXT,
    acao_is_wildcard     BOOLEAN NOT NULL,
    acao_reflects_origin BOOLEAN NOT NULL,
    acac_present         BOOLEAN NOT NULL,
    PRIMARY KEY (scan_id, analyzer_version)
);

-- Cost-of-measurement tracking, per scan. Lets the paper say "each
-- measurement required X HTTP requests and Y DNS queries on average"
-- with a real number instead of an estimate, and lets pilot_5000/
-- final_50000 be sized from measured cost, not assumption.
CREATE TABLE scan_metrics (
    scan_id                    BIGINT PRIMARY KEY REFERENCES scans(scan_id),
    requests_attempted         INTEGER NOT NULL,
    requests_completed         INTEGER NOT NULL,
    dns_queries                INTEGER NOT NULL,
    tls_handshake_duration_ms  INTEGER,
    http_requests_duration_ms  INTEGER,
    analyzer_duration_ms       INTEGER,
    total_duration_ms          INTEGER NOT NULL
);
