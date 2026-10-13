# Information Disclosure Research Method (EI v0.5)

## Product goal
Produce **attributable, evidence-backed exposure leads** for authorized programs — not confirmed vulnerabilities.

## Disclosure classes (bounty-oriented)
| Class | Signal | Typical next human step |
|---|---|---|
| ENV_CONFIG_EXPOSURE | `.env`, wp-config, appsettings | Review key names only; never use secrets |
| BACKUP_DUMP | zip/sql dumps | Scope check; sensitivity |
| SOURCE_MAP | `*.map` | Hunt embedded secrets/endpoints |
| API_SPEC | OpenAPI/Swagger | Map unauthenticated routes |
| VCS_METADATA | `.git`, `.svn` | Authorized reconstruction only |
| DIAGNOSTIC_SURFACE | phpinfo, actuator, elmah | Redacted evidence |
| SECRET_LIKE_TOKEN | AKIA, sk_live_, ghp_ | Pattern report; no auth attempts |
| HISTORICAL_INDEX | CDX/URLScan | Hypothesis for current-state if policy allows |

## Passive sources
1. **GitHub Code Search** — multi-family queries scoped to target host
2. **URLScan** — public scan index (DNS-boundary attribution)
3. **Internet Archive CDX** — historical URL paths (tight filters)

## Active (policy-gated only)
Authorized `CURRENT_OBSERVATION_*` probes against `examples/artifact_paths.json` catalog — low volume, fail-closed.

## Honesty rules
- Provider ERROR with partial results → **PARTIAL**, keep records
- No baseline run → **FIRST_SEEN**, not NEW
- Hostname attribution = DNS-boundary only
- Brand match ≠ authorization
- High rank ≠ confirmed finding

## External references (hypotheses, not guarantees)
Public writeups on .env/backup/OpenAPI/source-map exposure; Notion Information Disclosure Research Lab; OWASP information leakage guidance.
