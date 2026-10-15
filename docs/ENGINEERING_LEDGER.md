# Engineering Ledger — Exposure Intelligence

## Snapshot (2026-10-15 — RFC1918 / IPv6 host-safety continuation)

| Field | Value |
|-------|-------|
| main HEAD (verified) | `e936e034` |
| Feature branch start | `6b4f86f` |
| Feature branch after this cycle | (see git log on `feat/hypothesis-wire-human-queue-quality`) |
| Open PR | [#15](https://github.com/Tawffik/exposure-intelligence/pull/15) — **not merged** |
| Prior CI | 38680059601 success on `6b4f86f` |
| Notion | NOT UPDATED |

## Defect reproduced

`_safe_next_step` only substring-matched `localhost` / `127.0.0.1` / `0.0.0.0`.

Reproduced (before fix):
- `http://10.0.0.5/.env` → "Open the public blob…" (wrong)
- `http://172.16.0.1/.env`, `http://192.168.1.10/.env` → same
- `http://[::1]/.env`, `http://[fc00::1]/.env`, `http://[fe80::1]/.env` → same

Public path containing `10.0.0.1` as a path segment must **not** be treated as private.

## Policy implemented (`ei/host_safety.py`)

Conservative, explicit (not a single broad `is_private` flag):
- IPv4 loopback 127/8, unspecified 0.0.0.0
- RFC1918: 10/8, 172.16/12, 192.168/16
- IPv6 loopback `::1`, unspecified `::`, ULA `fc00::/7`, link-local `fe80::/10`
- IPv4-mapped IPv6 of the above
- `localhost` and `*.localhost`
- Hostname from `urllib.parse` (bracketed IPv6, ports); **no** path/query substring IP matching
- Malformed → not private (other gates still apply)

Wired into:
- `ei/hypothesis.py` `_safe_next_step` (gate before path/token templates)
- `ei/evidence_review.py` review demotion (URL host + body regex)

Precedence remains: LOW_PRIORITY → private/local host → UNATTRIBUTED/OUT_OF_SCOPE/INDEX_ONLY → path templates.

## Benchmark integrity

- Corpus size after private-host fixtures: **29** cases (1 AMBIGUOUS excluded from P/R)
- Metric definitions unchanged (schema 2.0); tests added for empty corpus, invalid schema, FP/FN adversarial labels, ambiguous exclusion, zero-denominator safety, family denominators
- Project corpus measured offline: P=1.0 R=1.0 on synthetic fixtures only — **not** real-world effectiveness
- TP/FP/FN/TN reconcile with labeled_for_review_metrics

## Verification commands (this cycle)

```text
python -m pytest tests/ -q          # full suite green
python -m ei.cli demo -o /tmp/ei-host-demo   # HUMAN_QUEUE.md present; INDEX_ONLY next steps attribution-safe
```

## Remaining limitations

- Real-world precision/recall unknown without independent labeled historical sample
- No live provider calls in this cycle (by design)
- PR #15 merge requires explicit human authorization

## Resume point

Branch `feat/hypothesis-wire-human-queue-quality` — push latest commit after this cycle; leave PR open for review.
