-- iwss migration 008: sector classification confidence tier.
-- sites.sector / sector_source already existed (migration 001, unused
-- until now). Adding confidence so the hybrid deterministic+LLM pipeline
-- (see paper/sector_classification.md) can distinguish "certain" from
-- "needs review" from "unclassified" — never silently treat a low- or
-- medium-confidence guess as equivalent to a deterministic rule match.

ALTER TABLE sites ADD COLUMN sector_confidence TEXT
    CHECK (sector_confidence IN ('high', 'medium', 'low'));
