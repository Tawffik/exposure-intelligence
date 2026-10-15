# Lead quality evaluation (offline)

## Purpose

Answer, with reproducible evidence:

> Does EI produce useful, attributable, reviewable leads — and what can we *prove*?

## What exists in-repo today

| Dataset | Usable for supervised P/R? |
|---------|----------------------------|
| `examples/classification_benchmark.json` | **Synthetic only** — classification/review regression |
| Provider fixtures under `examples/` | Offline pipeline smoke |
| `reports/autonomous/*` | Engineering cycle notes — **not** lead labels |
| Independent historical HUMAN_QUEUE + human labels | **Not found** |

## Commands

```bash
# Full offline eval: synthetic benchmark + demo descriptive stats
python -m ei.cli eval -o artifacts/lead-quality-eval

# Synthetic benchmark only (existing)
python -m ei.cli benchmark
```

Outputs:

- `lead_quality_report.json` — machine-readable
- `lead_quality_summary.md` — human summary
- `demo_bundle/` — optional Actions-style demo artifacts including `HUMAN_QUEUE.md`

## Metrics honesty

- **Synthetic P/R** = performance on curated fixtures, not bounty programs.
- **Descriptive stats** (actionable rate, relationship mix, URL duplicate surplus) need **no** human labels but are **not** precision.
- **Real-world precision / recall / bounty conversion** = **unavailable** until an independently labeled historical sample exists (see protocol in the JSON report).

## Labeling protocol (future historical data)

1. Unit = one queue lead (URL + attribution + evidence).
2. Labels: `USEFUL_LEAD`, `NOT_USEFUL`, `DUPLICATE`, `MISATTRIBUTED`, `OUT_OF_SCOPE`, `INSUFFICIENT_EVIDENCE`, `AMBIGUOUS`.
3. Labels must **not** be copied from EI predictions.
4. Record labeler, time, evidence viewed; disclose single-reviewer limits.
5. Keep synthetic fixtures out of held-out historical splits.

## PR #15

This evaluation work lives on branch `feat/lead-quality-eval-harness` and does **not** merge PR #15.
