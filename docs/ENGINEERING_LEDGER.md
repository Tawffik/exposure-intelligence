# Engineering Ledger — Exposure Intelligence

## Snapshot (2026-10-15 continuation)

| Field | Value |
|-------|-------|
| main HEAD (verified) | `e936e034` — HUMAN_QUEUE + product README (#14) |
| Feature branch | `feat/hypothesis-wire-human-queue-quality` |
| Open PR | [#15](https://github.com/Tawffik/exposure-intelligence/pull/15) — open, not merged |
| CI on PR #15 base commit | success (run 38678357985) — re-run expected after this push |
| Notion | BLOCKED_EXTERNAL (no verified write) |

## This cycle — implemented and tested

### PR #15 review findings
1. **Defect fixed:** `_safe_next_step` applied path templates (e.g. `.env` → “open the blob”) *before* UNATTRIBUTED/INDEX_ONLY gates, over-promising on third-party hosts. **Order now:** LOW_PRIORITY → localhost → weak attribution → path/token templates.
2. Hypothesis still separates claim / counter_evidence / missing_evidence; `confirmed_vulnerability` remains False.
3. Ranking still penalizes INDEX_ONLY/UNATTRIBUTED (×0.55) without dropping candidates; labels aligned to DIRECT_HOST / RELATED_SUBDOMAIN.
4. `demo -o <dir>` writes full Actions bundle including HUMAN_QUEUE.md.

### Benchmark v2
- Corpus expanded **16 → 26** labeled cases across families: env_config, source_maps, git_metadata, backups_listing, openapi, token_shapes, noise_localhost, auth_waf, noise_empty/spa/public.
- Metrics: review **precision / recall / FPR / FNR** with explicit positive class = `{NEEDS_REVIEW, POTENTIAL_EXPOSURE_UNCONFIRMED}`; **AMBIGUOUS** excluded from denominators.
- Measured on current fixtures: P=1.0 R=1.0 FPR=0.0 FNR=0.0 (synthetic only — **not** real-world effectiveness).
- Limitations recorded in report schema_version `2.0`.

### Regression tests
- `test_hypothesis_unattributed_overrides_path_template`
- `test_hypothesis_index_only_before_env_path`
- `test_benchmark_precision_recall_definitions`
- Full suite green locally after changes.

## Verified architecture
Target → fail-closed profile → query families → passive providers → normalize → DNS-boundary attribution → classify → evidence review → rank → lifecycle/SQLite → HUMAN_QUEUE + export-v1.

## Residual risks / blockers
| Item | Status |
|------|--------|
| Real-world P/R | Unknown — fixture corpus only |
| Live provider rate limits | Operational residual |
| Notion write | External blocker |
| PR #15 merge | Awaits explicit human authorization |
| Active probing | Disabled by default; ACTIVE gate only |

## Merge recommendation for PR #15
**Recommend merge after CI green on latest commit** — focused operator-quality + benchmark honesty; no provider expansion; no active probing. Do not claim production readiness beyond passive triage.

## Resume point
- Branch: `feat/hypothesis-wire-human-queue-quality`
- Next highest-value independent work after merge: independent labeled historical sample for benchmark; optional one authorized passive live run with per-provider status audit.
