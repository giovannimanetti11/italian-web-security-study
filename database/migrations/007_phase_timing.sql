-- iwss migration 007: per-phase queue wait + pure duration.
--
-- measurement_duration_ms (from migration 006) still conflated multiple
-- internal wait points: a scan acquires the shared network_budget three
-- times (HTTP, TLS+DNS, well-known/CORS), and only the first acquisition's
-- wait was isolated. This adds the other two wait points and the
-- corresponding pure phase durations, so every millisecond of a scan's
-- life is attributable to either "waiting for the concurrency budget" or
-- "doing real network work" — additive, not destructive: existing columns
-- (queue_wait_ms, measurement_duration_ms, http_requests_duration_ms) are
-- kept for historical pilot_500/pilot_5000 rows, which don't have this
-- finer breakdown.

ALTER TABLE scan_metrics ADD COLUMN http_duration_ms INTEGER;
ALTER TABLE scan_metrics ADD COLUMN tls_dns_queue_wait_ms INTEGER;
ALTER TABLE scan_metrics ADD COLUMN tls_dns_duration_ms INTEGER;
ALTER TABLE scan_metrics ADD COLUMN aux_queue_wait_ms INTEGER;
ALTER TABLE scan_metrics ADD COLUMN aux_duration_ms INTEGER;
