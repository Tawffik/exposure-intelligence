# Final Report — 20-Cycle Program (batch)

## Executive summary
Exposure Intelligence on `feat/id-restructure-v050` is an evidence-driven passive ID research system with multi-provider collection, DNS-boundary attribution, example/template demotion, explainable ranking, hypothesis templates, and a growing labeled benchmark.

**Release decision: READY_WITH_LIMITATIONS**

### What improved this batch
- Fixed false NEEDS_REVIEW on `.env.local.example` / `.env.integration.example` (D01)
- Expanded benchmark 9→13 cases (SPA, auth, source map, openapi, env.local.example)
- Added deterministic hypothesis export
- Documented content-availability semantics constants
- Capability matrix and cycle log under `reports/autonomous/`

### Limitations
- No confirmed vulnerability claims from passive indexes alone
- GitHub Code Search rate limits under parallel Actions runs
- CDX often times out
- BOLA/GraphQL/authz families deferred (need ACTIVE + lab)
- main still at `1f97be2`; feature work on PR #11

### Security/privacy
- Passive probing blocked when authorization is UNKNOWN
- Secrets not persisted; redaction paths exist
- `confirmed_vulnerability` always false in export

Generated: 2026-10-13T23:10:56Z
