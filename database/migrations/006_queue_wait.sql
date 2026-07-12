-- iwss migration 006: separate queue wait from real measurement cost.
--
-- total_duration_ms (task creation -> completion) was found at pilot_5000
-- scale to be dominated by time spent waiting for a network_budget slot,
-- not by actual measurement work — with 5,000 tasks created at once
-- against a concurrency budget of 20, the average masqueraded queue delay
-- as measurement cost. Splitting it:
--   queue_wait_ms            = task creation -> first network_budget acquisition
--   measurement_duration_ms  = first acquisition -> scan completion
-- total_duration_ms is kept as their sum, now a documented aggregate
-- rather than an accidentally-conflated number.

ALTER TABLE scan_metrics ADD COLUMN queue_wait_ms INTEGER;
ALTER TABLE scan_metrics ADD COLUMN measurement_duration_ms INTEGER;
