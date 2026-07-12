-- iwss migration 004: DNS/email auth + well-known resources (M3, high priority)

CREATE TABLE dns_email_security (
    scan_id          BIGINT REFERENCES scans(scan_id),
    analyzer_version TEXT NOT NULL,
    spf_present      BOOLEAN NOT NULL,
    spf_raw          TEXT,
    dmarc_present    BOOLEAN NOT NULL,
    dmarc_raw        TEXT,
    dmarc_policy     TEXT,        -- 'none' | 'quarantine' | 'reject' | NULL
    dkim_present     BOOLEAN NOT NULL,
    dkim_selector    TEXT,        -- which selector matched, if any
    mx_present       BOOLEAN NOT NULL,
    PRIMARY KEY (scan_id, analyzer_version)
);

-- Deliberately not framed as "website security" in the paper — this is
-- domain-level email-spoofing-resistance posture, a different construct
-- from HTTP/TLS website security (see paper/methodology.md).

CREATE TABLE wellknown_resources (
    scan_id                      BIGINT REFERENCES scans(scan_id),
    analyzer_version             TEXT NOT NULL,
    robots_txt_present           BOOLEAN NOT NULL,
    robots_disallow_count        INTEGER,
    robots_sensitive_path_count  INTEGER,
    sitemap_xml_present          BOOLEAN NOT NULL,
    security_txt_present         BOOLEAN NOT NULL,
    security_txt_rfc9116_compliant BOOLEAN,
    PRIMARY KEY (scan_id, analyzer_version)
);
