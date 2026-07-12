# Data Dictionary — `primary_it` / `export_anonymized_v1.csv`

Every column in the anonymized export, one row per scan. See
`dataset/primary_it/manifest.json` for which analysis subset (A/B/C) each
row's non-null columns actually belong to — not every column is populated
for every row (see "Coverage" per variable below).

## Identity

| Variable | Type | Definition | Coverage |
|---|---|---|---|
| `site_id` | integer | Internal site identifier, not the domain | 10,022 |
| `tld` | string | Always `"it"` (sampling frame filter) | 10,022 |
| `sector` | categorical | `PA`/`Università`/`Media`/`E-commerce`/`NULL` — see `paper/sector_classification.md` | 560/10,022 (5.6%) |
| `sector_confidence` | categorical | `high`/`medium`/`low`/`NULL` — all current classifications are `high` (deterministic rules only) | 560/10,022 |
| `domain_sha256` | string | SHA-256 of the domain, no salt — **pseudonymized, not anonymized**, see `manifest.json`'s `anonymization` block | 10,022 |
| `run_label` | categorical | `pilot_500`/`pilot_5000`/`final_remaining_pool` — determines which measurement_modules apply, see manifest | 10,022 |

## Scan outcome (Dataset C, n=10,022 sites / 10,020 scans)

| Variable | Type | Definition |
|---|---|---|
| `scan_id` | integer | Internal scan identifier (immutable snapshot key) |
| `scan_status` | categorical | `success`/`dns_error`/`timeout`/`connection_error`/`tls_error`/`invalid_response`/`blocked`/`http_error` |
| `status_code` | integer, nullable | HTTP status code, null if `scan_status != success` |
| `redirect_count` | integer | Number of redirects followed |
| `http_version` | categorical | `1.1`/`2`, null on failure |
| `http3_advertised` | boolean | From `Alt-Svc` response header only — no QUIC handshake attempted |
| `response_time_ms` | integer, nullable | HTTP fetch wall-clock time |

## Security headers (Dataset A, n=8,829 successful scans, all 3 runs)

| Variable | Type | Definition |
|---|---|---|
| `csp_present` | boolean | `Content-Security-Policy` header present |
| `hsts_present` | boolean | `Strict-Transport-Security` header present |
| `hsts_max_age` | integer, nullable | Parsed `max-age` directive value (seconds) |
| `hsts_include_subdomains` | boolean, nullable | `includeSubDomains` directive present |
| `hsts_preload` | boolean, nullable | `preload` directive present |
| `xfo_present` | boolean | `X-Frame-Options` header present |
| `xcto_present` | boolean | `X-Content-Type-Options: nosniff` present (exact value match required) |
| `referrer_policy_present` | boolean | `Referrer-Policy` header present |
| `permissions_policy_present` | boolean | `Permissions-Policy` header present |

## CSP directive analysis (only when `csp_present = true`, n=1,646)

| Variable | Type | Definition |
|---|---|---|
| `csp_directive_count` | integer | Number of distinct directives parsed |
| `csp_unsafe_inline` | boolean | `'unsafe-inline'` present in any directive's source list |
| `csp_unsafe_eval` | boolean | `'unsafe-eval'` present in any directive's source list |
| `csp_wildcard` | boolean | Bare `*` present as a source in any directive |
| `csp_frame_ancestors` | boolean | `frame-ancestors` directive present |
| `csp_restrictive` | boolean | Documented criterion (see `analyzers/csp.py`): `default-src` or `script-src` present, AND no unsafe-inline, AND no unsafe-eval, AND no wildcard source. Not a general "CSP is good" judgment — cite this exact definition when using the variable. |

## Cookies (aggregated per scan, not per individual cookie)

| Variable | Type | Definition |
|---|---|---|
| `cookie_count` | integer | Number of `Set-Cookie` headers observed |
| `cookies_missing_secure` | integer | Count of cookies without the `Secure` flag |
| `cookies_missing_httponly` | integer | Count of cookies without the `HttpOnly` flag |
| `cookies_missing_samesite` | integer | Count of cookies without a `SameSite` attribute |

## TLS / certificate

| Variable | Type | Definition |
|---|---|---|
| `tls_supported` | boolean | TLS handshake succeeded |
| `tls_version_negotiated` | categorical, nullable | e.g. `TLSv1.3`, `TLSv1.2` |
| `tls10_supported` | boolean | Server accepts a TLS 1.0-constrained handshake (separate probe) |
| `tls11_supported` | boolean | Server accepts a TLS 1.1-constrained handshake (separate probe) |
| `weak_cipher` | boolean, nullable | Negotiated cipher matches a documented weak-cipher marker list (RC4/DES/MD5/NULL/EXPORT) — see `analyzers/tls.py` |
| `key_type` | categorical, nullable | `RSA`/`EC`/other |
| `key_size` | integer, nullable | Public key size in bits |
| `self_signed` | boolean, nullable | Issuer CN equals subject CN |
| `days_until_expiry` | integer, nullable | Days from scan time to certificate `not_after` |

## DNS / email authentication (Dataset B only, n=8,438 — see manifest)

| Variable | Type | Definition |
|---|---|---|
| `spf_present` | boolean | Valid `v=spf1` TXT record found |
| `dmarc_present` | boolean | Valid `v=DMARC1` TXT record found at `_dmarc.<domain>` |
| `dmarc_policy` | categorical, nullable | `none`/`quarantine`/`reject`, parsed from the `p=` field |
| `dkim_present` | boolean | A DKIM TXT record found at any of 26 common selectors |
| `mx_present` | boolean | Domain has an MX record |

**Framing note**: these describe domain-level email-spoofing-resistance
posture, a distinct construct from HTTP/TLS website security — do not
aggregate into the same "security score" as headers/CSP/cookies/TLS
without stating that explicitly.

## Well-known resources (Dataset B only, n=8,438)

| Variable | Type | Definition |
|---|---|---|
| `robots_txt_present` | boolean | `/robots.txt` returns 200 with a `Disallow` line |
| `sitemap_xml_present` | boolean | `/sitemap.xml` returns 200 |
| `security_txt_present` | boolean | `/.well-known/security.txt` or `/security.txt` returns 200 with a `Contact:` field |
| `security_txt_rfc9116_compliant` | boolean, nullable | Narrow definition: both `Contact:` and `Expires:` fields present — not a full RFC 9116 conformance check |

## CORS (Dataset B only, n=8,438)

| Variable | Type | Definition |
|---|---|---|
| `acao_present` | boolean | `Access-Control-Allow-Origin` present in response to a GET carrying a synthetic test `Origin` header |
| `acao_is_wildcard` | boolean | `Access-Control-Allow-Origin: *` |
| `acao_reflects_origin` | boolean | Response echoes back the exact synthetic test origin sent |
| `acac_present` | boolean | `Access-Control-Allow-Credentials: true` present |

**Framing note**: these are observable CORS policy characteristics, not
proof of exploitability — no authenticated cross-origin request was
attempted. Never phrase as "CORS vulnerability" in the paper; phrase as
"CORS policy characteristics."

## Technology fingerprinting (context variable, not a security metric)

| Variable | Type | Definition |
|---|---|---|
| `cms_detected` | string, nullable | Pipe-separated list of detected CMS names (e.g. `WordPress`) |
| `cdn_detected` | string, nullable | Pipe-separated list of detected CDN names (currently only `Cloudflare` signature-matched) |

Explicitly a context/explanatory variable (e.g. "CMS=WordPress" as a
covariate explaining variation in CSP adoption), never itself a security
outcome to be scored.
