# Engineering Ledger — Exposure Intelligence

## Snapshot (2026-10-15)

| Field | Value |
|-------|-------|
| main HEAD (verified) | `e936e034` — HUMAN_QUEUE + product README (#14) |
| Local branch | `feat/hypothesis-wire-human-queue-quality` @ `e7d5a73` |
| Open PRs on origin | 0 before this cycle (all #1–#14 merged) |
| PR #9 host-attribution | **Merged** (closed 2026-10-13) — DNS-boundary in `ei/host_relationship.py` |
| Tests | Full suite green locally |
| Notion | BLOCKED_EXTERNAL (no write confirmation in this environment) |

## This cycle — implemented (local + partial remote)

1. **Hypothesis on operator queue** (`ei/research.py`): every research-queue item gets `build_hypothesis()`; `suggested_next_step` comes from impact-oriented templates.
2. **HUMAN_QUEUE quality** (`ei/report.py`): attribution legend; hypothesis line; clearer next steps.
3. **Next-step templates** (`ei/hypothesis.py`): .env, source maps, git metadata, UNATTRIBUTED vs INDEX_ONLY.
4. **Queue sort**: attribution strength tie-break (DIRECT > subdomain > index > unattributed).
5. **demo CLI** (`ei/cli.py`): `-o <directory>` writes full Actions report bundle including `HUMAN_QUEUE.md`.
6. **Ranker labels** (`ei/ranker.py`): `DIRECT_HOST` / `RELATED_SUBDOMAIN` instead of opaque `DIRECT_OR_IN_SCOPE`.
7. **Regression**: `test_research_queue_attaches_hypothesis`.

Remote branch has: hypothesis.py, ranker.py, test_human_queue.py (via GitHub connector). research.py / report.py / cli.py may still need a follow-up push if connector payload limits blocked full upload.

## Verified architecture (actual, not historical)

Target → Profile fail-closed → Planner/query families → Passive providers (GitHub/URLScan/CDX) → Normalize → DNS-boundary attribution → Dedup → Classify → Evidence review → Rank → Lifecycle/SQLite → HUMAN_QUEUE + export-v1 → Actions artifacts.

Probes exist only behind ACTIVE + explicit enable; default Actions path does not probe hosts.

## Residual risks / blockers

| Item | Status |
|------|--------|
| Git `origin` PAT in remote URL | Expired (push via git CLI fails) — use GitHub connector |
| Notion write | External blocker |
| Live index rate limits | Operational residual |
| CDX timeouts | Operational residual |
| Demo fixtures use `example-authorized.test` | UNATTRIBUTED noise when target is `example.com` (expected for multi-host fixtures) |

## Next highest-value work

1. Finish pushing research.py + report.py + cli.py to the feature branch; merge PR.
2. Optional: demote pure UNATTRIBUTED fixture hosts harder in demo-only path.
3. Live Actions run on an authorized target once token/secrets are available.
4. Notion charter page sync when write access exists.

## Resume point

- Branch: `feat/hypothesis-wire-human-queue-quality`
- Local commit: `e7d5a73`
- Patch: `/home/workdir/artifacts/0001-feat-wire-hypothesis-into-operator-queue-impact-orie.patch`
- Do not force-push main; merge via PR only.
