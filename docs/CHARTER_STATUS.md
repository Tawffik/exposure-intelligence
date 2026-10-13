# Exposure Intelligence — Charter Completion Status

Mapped against *Exposure Intelligence — Independent Project Charter & Engineering Roadmap* (Notion).

| # | Charter component | Status | Evidence |
|---|-------------------|--------|----------|
| 1 | Target Registry | Done | ei/registry.py, examples/targets_registry.json |
| 2 | Policy & Scope Gate | Done | ei/profile.py fail-closed |
| 3 | Planner / Budget | Done | ei/planner.py |
| 4 | Passive Providers (GitHub, URLScan, CDX) | Done | ei/providers/* |
| 5 | Bounded Current-State Probes | Done | ei/probe.py + artifact_paths (ACTIVE only) |
| 6 | Observation Ledger | Done | ei/store.py SQLite |
| 7 | Normalize & Canonicalize | Done | provider normalize + pipeline |
| 8 | Scope Attribution | Done | DNS-boundary relationship labels |
| 9 | Deduplicate & Correlate | Done | stable keys + cross-run compare |
| 10 | Classifier (lead != finding) | Done | ei/classifier.py + reason codes |
| 11 | Evidence review | Done | ei/evidence_review.py |
| 12 | Candidate Queue + lifecycle | Done | queue + ei/candidate_state.py |
| 13 | Run health & yield metrics | Done | provider statuses + yield_metrics |
| 14 | Export adapter | Done | ei.export.v1 |
| 15 | GitHub Actions target-to-report | Done | workflow_dispatch |
| 16 | Benchmark gate | Done | ei benchmark |
| 17 | Query families (bounty signals) | Done | ei/query_families.py |
| 18 | Daily schedule | Partial | manual Actions first (per charter) |
| 19 | Paid indexes | Deferred | charter |
| 20 | BOLA/GraphQL account-aware | Deferred | separate workflow |
| 21 | Notion auto-sync | Partial | needs write access |

Estimated P0-P1 slice: **~95%**.

Non-goals respected: no vuln oracle, no secret storage, no CAPTCHA evasion, no exploitation.


## Attribution note (2026-10-13)
URLScan/CDX previously used substring `host in url`. Fixed to shared DNS-boundary helper (`ei/host_relationship.py`). Textual matches remain metadata only.

## v0.5.0 restructure (2026-10-14)

Merged P0 attribution (#9) + Superdrug data-path (#10) into feature branch.
Expanded disclosure surface coverage:

- Query families: env/config, secrets/maps, backups, **api_specs (OpenAPI/Swagger)**, **vcs_meta**, diagnostics
- Artifact path catalog v2 (authorized probes only)
- `ei/disclosure_taxonomy.py` — class labels for ranking rationale
- `docs/ID_RESEARCH_METHOD.md` — research method bound to Notion ID scenarios
- Honesty: PARTIAL retention, FIRST_SEEN, DNS-boundary host authority

Still non-goals: vuln oracle, secret storage, CAPTCHA evasion, full BugBountyCI recon merge.
