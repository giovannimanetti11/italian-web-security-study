# Sector classification

## Current state (this paper, `primary_it` dataset)

Deterministic rules only (`dataset/classify_sectors.py`), no LLM, no
extra data capture beyond what's already in the dataset:

- **PA**: `.gov.it` suffix, or `comune./provincia./regione.` domain prefix
- **Università**: hand-built list of ~55 major Italian public
  universities — **not** sourced from an official registry (e.g. MUR),
  documented here as best-effort and incomplete, not exhaustive
- **Media**: hand-built list of ~34 major Italian news outlets — same
  caveat, not exhaustive
- **E-commerce**: sites where the `fingerprint` analyzer already detected
  CMS=Shopify (narrow — WooCommerce/Magento aren't distinguished from
  generic WordPress/other CMS yet)

Result: **560/10,022 sites classified (5.6%)** — PA 156, E-commerce 325,
Università 51, Media 28. The remaining 9,462 (94.4%) are `sector=NULL`
("Unknown"), not guessed at.

**Banche, Sanità, PMI, Enterprise are not classified at all** in this
pass:
- Banche: many major Italian banks use `.com`, not `.it` — systematically
  under-represented in a `.it`-only frame even with a curated list
- Sanità: no reliable domain-string pattern (hospitals/ASL naming isn't
  standardized)
- PMI/Enterprise: not derivable from passive HTTP/TLS observation at
  all — needs company size/revenue data from a different source entirely

**Use in this paper**: sector-comparison RQs (e.g. "do universities adopt
CSP more than companies?") should be scoped to the 4 high-confidence,
high-coverage-enough categories, with sample sizes stated plainly
(Università n=51 and Media n=28 are small — confidence intervals will be
wide, say so rather than overstate the finding). Treat this as Dataset B
groundwork (roadmap §"Decisions locked in" — sectors were always meant to
be a later, separate analysis, never mixed into Dataset A's primary
random-sample role), not a retrofit of Dataset A itself.

## Future work — deferred to a future, larger dataset and a separate paper

Idea (Giovanni, 2026-07-09): extract `title`, `meta description`, and
**JSON-LD structured data** (schema.org) per site, and use JSON-LD's
`@type` as the primary sector signal — `GovernmentOrganization`,
`EducationalOrganization`, `NewsMediaOrganization`, `Hospital`,
`BankOrCreditUnion`, `Store`/`OnlineStore`, etc. map fairly directly onto
the categories above. This is a much cleaner signal than domain-string
heuristics where it's present: it's the site's own structured
self-description, deterministic to parse, and needs no LLM/API call at
all — the earlier plan to use Claude's API for residual classification
was reconsidered specifically because JSON-LD extraction is "just
parsing," not a judgment call requiring a model.

Explicitly scoped as **future work on a future, larger dataset for a
separate paper**, not a retrofit of `primary_it` for this one:
- Would require a new lightweight fetch (title/meta/JSON-LD only, still
  no body persistence) — not yet implemented
- No API key or LLM dependency needed for the JSON-LD signal itself; an
  LLM pass might still help for the residual sites with no/unusable
  JSON-LD, but that's a secondary refinement, not the primary mechanism
- Revisit when scoping that future dataset, not before
