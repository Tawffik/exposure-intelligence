# Exposure Intelligence (EI)

Independent, evidence-driven system for discovering, classifying, correlating, and prioritizing **information-disclosure / exposure candidates** on **explicitly authorized** targets.

This repository is the implementation of the [Exposure Intelligence project charter](https://app.notion.com/p/3f6dac31e88081268529d3bec0e16616). It is **not** a fork of BugBountyCI and does not depend on it.

## Design principles

- **Evidence over inference** — every candidate retains provenance (source, fidelity, timestamps, hashes).
- **Honest run states** — `ERROR`, `RATE_LIMITED`, `PARTIAL`, `NOT_CONFIGURED`, and `COMPLETED_ZERO` are distinct; failures never look like clean empty success.
- **Source fidelity** — original observation ≠ AI summary ≠ mirror ≠ independently reproduced.
- **Explainable classification and ranking** — scores come with reason codes; an exposed artifact is not automatically a vulnerability.
- **Safety first** — offline fixtures by default; secrets are redacted; no live probing without separate authorization policy (not enabled in MVP).

## Status (v0.1.3)

| Capability | Status |
| --- | --- |
| Runnable CLI + demo fixture | Implemented |
| Observation / candidate contracts | Implemented |
| Source-fidelity labels | Implemented |
| Honest run states | Implemented |
| Deterministic content-shape classifier | Implemented + tested |
| Source maps / directory listings / OpenAPI / git metadata shapes | Implemented + tested (v0.1.1) |
| Provenance + redaction | Implemented + tested |
| Correlation + explainable ranking | Implemented + tested |
| Automated tests + CI workflow | Implemented |
| Live providers (GitHub search, URLScan, CDX) | Not yet |
| Target authorization registry / active probes | Not yet |
| Persistent store / scheduler | Not yet |

## Requirements

- Python 3.10+
- Optional: `pytest` for tests

## Setup

```bash
git clone https://github.com/Tawffik/exposure-intelligence.git
cd exposure-intelligence
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Run the demo

```bash
python -m ei.cli demo
# or after install:
ei demo
```

Example (abbreviated) output:

```json
{
  "run_id": "...",
  "status": "COMPLETED_WITH_RESULTS",
  "metrics": {
    "observations": 12,
    "candidates": 12,
    "potentially_sensitive": 3,
    "noise_or_low": 7,
    "redactions_applied": 1
  },
  "candidates": [ ... ]
}
```

Write the full report:

```bash
python -m ei.cli demo -o /tmp/ei-report.json
python -m ei.cli run examples/sample_observations.json -o /tmp/out.json
```



## Operational workflow (v0.1.3)

```bash
# 1. Validate program profile
python -m ei.cli profile-validate examples/program_profile.json

# 2. Research run (offline fixtures; persists to SQLite)
python -m ei.cli research \
  --profile examples/program_profile.json \
  --fixture examples/sample_observations.json \
  --github-fixture examples/github_code_search_sample.json \
  --db ei_data/research.db

# 3. History and research queue
python -m ei.cli history --db ei_data/research.db --target-id demo-program
python -m ei.cli queue --db ei_data/research.db --target-id demo-program

# Optional live GitHub index only (no target host probing)
GITHUB_TOKEN=... python -m ei.cli research --profile examples/program_profile.json \
  --live-github --query 'filename:.env API_KEY' --db ei_data/research.db
```

Profile gates **live host requests** only. Passive index leads are retained with
`PUBLIC_INDEX` / `UNATTRIBUTED` relevance labels — never silently dropped.

## Shadow mode — GitHub Code Search (v0.1.2)

Passive public-index provider integrated behind the existing observation contract.

```bash
# Offline (deterministic; default)
python -m ei.cli shadow

# Explicit fixtures
python -m ei.cli shadow \
  --baseline examples/sample_observations.json \
  --github-fixture examples/github_code_search_sample.json

# Optional live search (requires GITHUB_TOKEN; does NOT probe discovered hosts)
GITHUB_TOKEN=... python -m ei.cli shadow --live --query 'filename:.env API_KEY'
```

Provider failure/rate-limit/empty states are explicit and never erase baseline candidates.

## Input format

Fixture JSON is either a list of observation records or `{"observations": [...]}`.

Each record may include:

| Field | Description |
| --- | --- |
| `url` | Discovered URL / artifact reference |
| `status` | HTTP status if observed |
| `content_type` | MIME type |
| `body` | Response body (fixtures only; secrets redacted in output) |
| `discovery_mode` | `PASSIVE_INDEX` \| `HISTORICAL` \| `CURRENT_OBSERVATION` \| `FIXTURE` |
| `source_fidelity` | `ORIGINAL` \| `EXTRACTED` \| `SUMMARY` \| `AI_INFERENCE` \| `MIRROR` \| `INDEPENDENTLY_REPRODUCED` |
| `source_url` / `source_record_id` | Provenance |
| `scope_decision` | e.g. `IN_SCOPE` |
| `provider` | Provider name |

## Output contracts

See `ei/models.py` for `Observation`, `Candidate`, `RunReport`, and run-status enums.

**Run statuses:** `NOT_CONFIGURED`, `NOT_RUN`, `SKIPPED_BY_POLICY`, `ERROR`, `RATE_LIMITED`, `PARTIAL`, `COMPLETED_ZERO`, `COMPLETED_WITH_RESULTS`.

**Classifications (examples):** `POTENTIALLY_SENSITIVE`, `SPA_SHELL`, `GENERIC_ERROR`, `AUTH_REQUIRED`, `HISTORICAL_ONLY`, `KEYWORD_FALSE_POSITIVE`, `COPIED_RESEARCH`, …

## Tests

```bash
pytest -q
```

Coverage includes positive/negative classification, redaction, provenance, duplicates, historical vs current, zero-result completion, error/rate-limit/partial/not-configured states, and ranking determinism.

## Architecture (MVP)

```
Fixture / future provider
        │
        ▼
  Observation builder ──► Classifier (content-shape + path + fidelity)
        │
        ▼
  Ranker / correlator ──► Candidate list (explainable scores)
        │
        ▼
  RunReport (status + metrics + provenance)
```

## Non-goals (MVP)

- No autonomous exploitation or credential use
- No storage of raw secrets
- No live HTTP against real targets in this release
- No claim that classification accuracy is production-validated beyond fixtures

## License

MIT

## Next bounded tasks

1. Target-profile schema + fail-closed policy gate (still offline)
2. First passive provider adapter (GitHub code search) behind the same observation contract, shadow mode only
3. Expand labeled fixture corpus and measure precision denominators
