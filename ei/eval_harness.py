"""
Offline lead-quality evaluation harness (Historical Evaluation phase).

Purpose
-------
Measure what EI *can* measure without independent historical labels:
- Synthetic classification/review metrics (existing benchmark corpus)
- Descriptive lead-quality stats from offline demo/fixture pipeline runs
  (attribution mix, actionable rate, URL-level duplicate rate, provider status)

What this is NOT
----------------
- Real-world precision/recall (requires independently labeled historical leads)
- A claim that synthetic scores generalize to bounty programs

Network: none. Live targets: none.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from ei.benchmark import run_classification_benchmark
from ei.models import utc_now_iso

EVAL_SCHEMA_VERSION = "1.0"

# Human reference outcomes for future labeled historical data (protocol only).
LABEL_OUTCOMES = (
    "USEFUL_LEAD",
    "NOT_USEFUL",
    "DUPLICATE",
    "MISATTRIBUTED",
    "OUT_OF_SCOPE",
    "INSUFFICIENT_EVIDENCE",
    "AMBIGUOUS",
)


@dataclass
class LeadQualityReport:
    schema_version: str = EVAL_SCHEMA_VERSION
    generated_at: str = ""
    mode: str = ""  # synthetic_benchmark | descriptive_pipeline | combined_protocol
    data_kind: str = ""  # synthetic_fixtures | offline_historical | unlabeled_historical
    limitations: list[str] = field(default_factory=list)
    synthetic_benchmark: dict[str, Any] = field(default_factory=dict)
    descriptive: dict[str, Any] = field(default_factory=dict)
    protocol: dict[str, Any] = field(default_factory=dict)
    excluded: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_url_key(url: str) -> str:
    """Conservative URL key for duplicate *counting* (not aggressive rewrite)."""
    if not url:
        return ""
    try:
        p = urlparse(url.strip())
        host = (p.hostname or "").lower().rstrip(".")
        path = p.path or ""
        # Keep query: distinct resources may differ only by query
        q = p.query or ""
        return f"{host}{path}?{q}" if q else f"{host}{path}"
    except Exception:
        return url.strip().lower()


def descriptive_from_queue(
    research_queue: list[dict[str, Any]],
    *,
    provider_status: Optional[dict[str, Any]] = None,
    run_meta: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Descriptive stats from a research queue (no independent labels)."""
    n = len(research_queue)
    reviews = Counter((x.get("review_decision") or "UNKNOWN") for x in research_queue)
    rels = Counter((x.get("target_relationship") or "UNKNOWN") for x in research_queue)
    classes = Counter((x.get("classification") or "UNKNOWN") for x in research_queue)
    changes = Counter((x.get("change_type") or "UNKNOWN") for x in research_queue)

    actionable = sum(
        1
        for x in research_queue
        if (x.get("review_decision") or "")
        in {"NEEDS_REVIEW", "POTENTIAL_EXPOSURE_UNCONFIRMED"}
    )
    urls = [x.get("url") or x.get("primary_url") or "" for x in research_queue]
    keys = [_normalize_url_key(u) for u in urls]
    unique_keys = {k for k in keys if k}
    dup_surplus = max(0, n - len(unique_keys)) if n else 0

    # Hypothesis / next-step presence
    with_hyp = sum(1 for x in research_queue if isinstance(x.get("hypothesis"), dict))
    with_step = sum(1 for x in research_queue if x.get("suggested_next_step"))
    confirmed_true = sum(
        1
        for x in research_queue
        if (x.get("hypothesis") or {}).get("confirmed_vulnerability") is True
        or x.get("confirmed_vulnerability") is True
    )

    return {
        "queue_items": n,
        "actionable_items": actionable,
        "actionable_rate": round(actionable / n, 4) if n else None,
        "unique_url_keys": len(unique_keys),
        "duplicate_surplus": dup_surplus,
        "duplicate_rate": round(dup_surplus / n, 4) if n else None,
        "review_decision_counts": dict(reviews),
        "target_relationship_counts": dict(rels),
        "classification_counts": dict(classes),
        "change_type_counts": dict(changes),
        "items_with_hypothesis": with_hyp,
        "items_with_next_step": with_step,
        "confirmed_vulnerability_true_count": confirmed_true,
        "provider_status": provider_status or {},
        "run_meta_summary": {
            k: (run_meta or {}).get(k)
            for k in ("status", "target_host", "run_id", "research_mode", "data_source_label")
            if run_meta
        },
        "note": (
            "Descriptive only. actionable_rate is not human-acceptance rate. "
            "duplicate_rate is URL-key surplus within one run, not cross-run novelty."
        ),
    }


def labeling_protocol() -> dict[str, Any]:
    """Documented protocol for collecting independent historical labels later."""
    return {
        "evaluation_unit": "One HUMAN_QUEUE / research-queue lead (URL + attribution + evidence summary)",
        "outcomes": list(LABEL_OUTCOMES),
        "outcome_definitions": {
            "USEFUL_LEAD": "Human would spend time inspecting; may or may not become a report",
            "NOT_USEFUL": "Noise, template, or no investigative value",
            "DUPLICATE": "Same resource already represented by another lead in the set",
            "MISATTRIBUTED": "Host/relationship does not match the intended target",
            "OUT_OF_SCOPE": "Outside program scope even if interesting",
            "INSUFFICIENT_EVIDENCE": "Cannot judge without more evidence",
            "AMBIGUOUS": "Needs adjudication; exclude from binary P/R denominators",
        },
        "independence_rule": (
            "Human labels must not be copied from EI review_decision or classification. "
            "Record labeler, timestamp, and evidence viewed."
        ),
        "leakage_controls": [
            "Do not include synthetic benchmark cases in historical held-out sets",
            "Group near-duplicate URLs/hosts before train/val/test splits",
            "Disclose single-reviewer limitation if no second adjudicator",
        ],
        "required_fields_per_label": [
            "record_id",
            "url",
            "target_host",
            "label",
            "labeler",
            "labeled_at",
            "evidence_notes",
            "ei_prediction_snapshot",  # stored separately; not used as label
        ],
        "metrics_when_labels_exist": {
            "useful_lead_precision": "TP_useful / predicted_actionable_among_reviewed",
            "attribution_accuracy": "correct_relationship / labeled_attribution_cases",
            "human_acceptance_rate": "USEFUL_LEAD / reviewed (not identical to precision)",
            "recall": "Only if held-out set has a defensible relevant-positive universe",
        },
        "unavailable_until_labels": [
            "real_world_precision",
            "real_world_recall",
            "bounty_conversion_rate",
        ],
    }


def run_synthetic_and_descriptive(
    *,
    benchmark_path: Path,
    out_dir: Optional[Path] = None,
    run_demo_pipeline: bool = True,
) -> LeadQualityReport:
    """Execute offline evaluation: synthetic benchmark + optional demo descriptive stats."""
    limitations = [
        "No independently labeled historical lead corpus was found in the repository.",
        "Synthetic benchmark metrics are not real-world precision/recall.",
        "Demo descriptive stats use fixture providers only (research_mode=demo).",
        "confirmed_vulnerability must remain false in product outputs.",
    ]
    report = LeadQualityReport(
        generated_at=utc_now_iso(),
        mode="synthetic_benchmark+descriptive_pipeline",
        data_kind="synthetic_fixtures",
        limitations=limitations,
        protocol=labeling_protocol(),
    )

    if benchmark_path.is_file():
        bench = run_classification_benchmark(benchmark_path)
        report.synthetic_benchmark = {
            "corpus_path": str(benchmark_path),
            "total_cases": bench.total,
            "ambiguous_excluded": bench.ambiguous_excluded,
            "labeled_for_review_metrics": bench.labeled_for_review_metrics,
            "classification_accuracy": bench.classification_accuracy,
            "review_accuracy": bench.review_accuracy,
            "review_tp": bench.review_tp,
            "review_fp": bench.review_fp,
            "review_fn": bench.review_fn,
            "review_tn": bench.review_tn,
            "review_precision": bench.review_precision,
            "review_recall": bench.review_recall,
            "per_family": bench.per_family,
            "mismatches": bench.mismatches,
            "limitations": bench.limitations,
        }
    else:
        report.excluded.append(
            {"reason": "benchmark_missing", "path": str(benchmark_path)}
        )

    if run_demo_pipeline:
        from ei.actions_run import run_actions_job

        dest = out_dir or Path("/tmp/ei-eval-demo")
        dest.mkdir(parents=True, exist_ok=True)
        result = run_actions_job(
            target="example.com",
            out_dir=dest,
            db_path=dest / "ei.db",
            research_mode="demo",
            authorization_status="UNKNOWN",
            max_github_results=10,
        )
        queue = list(result.get("research_queue") or [])
        # Prefer provider status from artifact if present
        provider_status: dict[str, Any] = {}
        ps_path = dest / "provider-status.json"
        if ps_path.is_file():
            try:
                provider_status = json.loads(ps_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                provider_status = {"error": "invalid_provider_status_json"}
        report.descriptive = descriptive_from_queue(
            queue,
            provider_status=provider_status,
            run_meta=result if isinstance(result, dict) else {},
        )
        report.descriptive["artifact_dir"] = str(dest)
        report.descriptive["human_queue_exists"] = (dest / "HUMAN_QUEUE.md").is_file()

    return report


def write_report(report: LeadQualityReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")


def write_summary_md(report: LeadQualityReport, path: Path) -> None:
    d = report.to_dict()
    lines = [
        "# Lead quality evaluation summary",
        "",
        f"- **Generated:** {d.get('generated_at')}",
        f"- **Data kind:** `{d.get('data_kind')}`",
        f"- **Mode:** `{d.get('mode')}`",
        "",
        "## Limitations",
        "",
    ]
    for lim in d.get("limitations") or []:
        lines.append(f"- {lim}")
    sb = d.get("synthetic_benchmark") or {}
    if sb:
        lines.extend(
            [
                "",
                "## Synthetic classification benchmark",
                "",
                f"- Cases: {sb.get('total_cases')} (ambiguous excluded: {sb.get('ambiguous_excluded')})",
                f"- Review P/R: {sb.get('review_precision')} / {sb.get('review_recall')}",
                f"- TP/FP/FN/TN: {sb.get('review_tp')}/{sb.get('review_fp')}/{sb.get('review_fn')}/{sb.get('review_tn')}",
                "",
                "_Synthetic only — not real-world performance._",
            ]
        )
    desc = d.get("descriptive") or {}
    if desc:
        lines.extend(
            [
                "",
                "## Descriptive pipeline stats (demo fixtures)",
                "",
                f"- Queue items: {desc.get('queue_items')}",
                f"- Actionable: {desc.get('actionable_items')} (rate={desc.get('actionable_rate')})",
                f"- Unique URL keys: {desc.get('unique_url_keys')}; duplicate surplus: {desc.get('duplicate_surplus')}",
                f"- Relationships: `{desc.get('target_relationship_counts')}`",
                f"- confirmed_vulnerability true count: {desc.get('confirmed_vulnerability_true_count')}",
                "",
                str(desc.get("note") or ""),
            ]
        )
    lines.extend(
        [
            "",
            "## Historical labels",
            "",
            "Independent historical labels: **not available** in-repo.",
            "See `protocol` in the JSON report for the labeling specification.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
