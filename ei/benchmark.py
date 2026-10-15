"""
Classification / evidence-review benchmark runner (charter §10).

Measures classification and review decisions against a labeled fixture corpus.
A high candidate count is not a success metric — precision on labeled cases is.

Evaluation definitions (explicit):
- Positive review class: {POTENTIAL_EXPOSURE_UNCONFIRMED, NEEDS_REVIEW}
- Negative review class: {LOW_PRIORITY}
- Ambiguous cases: labeled expected_review == "AMBIGUOUS" — excluded from
  precision/recall denominators (never counted as silent negatives).
- Soft match: expected POTENTIAL_EXPOSURE_UNCONFIRMED may match actual NEEDS_REVIEW
  (both are actionable for a human queue).
- Corpus is synthetic + curated fixtures only — not independent historical cases
  unless a case sets source_kind explicitly.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ei.classifier import classify_observation
from ei.evidence_review import review_candidate
from ei.models import utc_now_iso

ACTIONABLE_REVIEWS = frozenset({"POTENTIAL_EXPOSURE_UNCONFIRMED", "NEEDS_REVIEW"})
NEGATIVE_REVIEWS = frozenset({"LOW_PRIORITY"})


@dataclass
class BenchmarkCaseResult:
    case_id: str
    expected_classification: str
    actual_classification: str
    classification_match: bool
    expected_review: str
    actual_review: str
    review_match: bool
    family: str = ""
    reason_codes: list[str] = field(default_factory=list)
    evidence_basis: str = ""
    note: str = ""
    ambiguous: bool = False


@dataclass
class BenchmarkReport:
    schema_version: str = "2.0"
    generated_at: str = ""
    corpus_path: str = ""
    total: int = 0
    labeled_for_review_metrics: int = 0
    ambiguous_excluded: int = 0
    classification_correct: int = 0
    review_correct: int = 0
    classification_accuracy: float = 0.0
    review_accuracy: float = 0.0
    # Review positive-class metrics (actionable vs noise)
    review_tp: int = 0
    review_fp: int = 0
    review_fn: int = 0
    review_tn: int = 0
    review_precision: float | None = None
    review_recall: float | None = None
    review_fpr: float | None = None
    review_fnr: float | None = None
    per_family: dict[str, dict[str, Any]] = field(default_factory=dict)
    cases: list[BenchmarkCaseResult] = field(default_factory=list)
    mismatches: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _is_actionable(decision: str) -> bool:
    return decision in ACTIONABLE_REVIEWS


def _soft_review_match(expected: str, actual: str) -> bool:
    if expected == actual:
        return True
    # Both actionable — treat as match for queue purposes
    if expected == "POTENTIAL_EXPOSURE_UNCONFIRMED" and actual == "NEEDS_REVIEW":
        return True
    if expected == "NEEDS_REVIEW" and actual == "POTENTIAL_EXPOSURE_UNCONFIRMED":
        return True
    return False


def run_classification_benchmark(corpus_path: Path) -> BenchmarkReport:
    cases = json.loads(Path(corpus_path).read_text(encoding="utf-8"))
    if not isinstance(cases, list):
        raise ValueError("Benchmark corpus must be a JSON list")

    report = BenchmarkReport(
        generated_at=utc_now_iso(),
        corpus_path=str(corpus_path),
        total=len(cases),
        limitations=[
            "Corpus is curated synthetic fixtures; not an independent historical sample.",
            "Accuracy=1.0 on this corpus does not imply real-world precision/recall.",
            "Ambiguous labels are excluded from precision/recall denominators.",
            "Positive class for review metrics = NEEDS_REVIEW ∪ POTENTIAL_EXPOSURE_UNCONFIRMED.",
        ],
    )
    family_stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"n": 0, "cls_ok": 0, "rev_ok": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0}
    )

    for case in cases:
        if not isinstance(case, dict):
            continue
        cid = case.get("id") or case.get("url") or "unknown"
        exp_cls = case.get("expected_classification") or ""
        exp_rev = case.get("expected_review") or ""
        family = (case.get("family") or case.get("query_family") or "unspecified").strip()
        ambiguous = exp_rev == "AMBIGUOUS" or bool(case.get("ambiguous"))

        cls, reasons, conf, rat, sens, fr = classify_observation(
            url=case.get("url", ""),
            status=case.get("status"),
            content_type=case.get("content_type", ""),
            body=case.get("body", "") or "",
            discovery_mode=case.get("discovery_mode", "FIXTURE"),
        )
        review = review_candidate(
            url=case.get("url", ""),
            classification=cls,
            reason_codes=reasons,
            body_preview_redacted=(case.get("body") or "")[:500],
            discovery_mode=case.get("discovery_mode", ""),
            target_relationship=case.get("target_relationship", ""),
        )
        actual_rev = review["review_decision"]
        cls_ok = (not exp_cls) or (cls == exp_cls)
        rev_ok = True if ambiguous else _soft_review_match(exp_rev, actual_rev)

        if exp_cls and cls_ok:
            report.classification_correct += 1
        elif not exp_cls:
            # No classification label — do not penalize accuracy denominator later
            pass
        if not ambiguous and rev_ok:
            report.review_correct += 1

        if ambiguous:
            report.ambiguous_excluded += 1
        else:
            report.labeled_for_review_metrics += 1
            exp_pos = _is_actionable(exp_rev)
            act_pos = _is_actionable(actual_rev)
            if exp_pos and act_pos:
                report.review_tp += 1
            elif not exp_pos and act_pos:
                report.review_fp += 1
            elif exp_pos and not act_pos:
                report.review_fn += 1
            else:
                report.review_tn += 1

            fs = family_stats[family]
            fs["n"] += 1
            if cls_ok:
                fs["cls_ok"] += 1
            if rev_ok:
                fs["rev_ok"] += 1
            if exp_pos and act_pos:
                fs["tp"] += 1
            elif not exp_pos and act_pos:
                fs["fp"] += 1
            elif exp_pos and not act_pos:
                fs["fn"] += 1
            else:
                fs["tn"] += 1

        row = BenchmarkCaseResult(
            case_id=str(cid),
            expected_classification=exp_cls,
            actual_classification=cls,
            classification_match=cls_ok,
            expected_review=exp_rev,
            actual_review=actual_rev,
            review_match=rev_ok,
            family=family,
            reason_codes=list(reasons),
            evidence_basis=review.get("evidence_basis", ""),
            note=case.get("note", ""),
            ambiguous=ambiguous,
        )
        report.cases.append(row)
        if not ambiguous and (not cls_ok or not rev_ok):
            report.mismatches.append(
                {
                    "id": cid,
                    "family": family,
                    "classification_match": cls_ok,
                    "review_match": rev_ok,
                    "expected_classification": exp_cls,
                    "actual_classification": cls,
                    "expected_review": exp_rev,
                    "actual_review": actual_rev,
                    "reasons": reasons,
                }
            )

    n = max(report.total, 1)
    # Classification accuracy only over cases that declared expected_classification
    labeled_cls = sum(1 for c in cases if isinstance(c, dict) and c.get("expected_classification"))
    report.classification_accuracy = round(
        report.classification_correct / max(labeled_cls, 1), 4
    )
    report.review_accuracy = round(
        report.review_correct / max(report.labeled_for_review_metrics, 1), 4
    )

    tp, fp, fn, tn = report.review_tp, report.review_fp, report.review_fn, report.review_tn
    report.review_precision = round(tp / (tp + fp), 4) if (tp + fp) else None
    report.review_recall = round(tp / (tp + fn), 4) if (tp + fn) else None
    report.review_fpr = round(fp / (fp + tn), 4) if (fp + tn) else None
    report.review_fnr = round(fn / (fn + tp), 4) if (fn + tp) else None

    for fam, fs in family_stats.items():
        prec = (
            round(fs["tp"] / (fs["tp"] + fs["fp"]), 4)
            if (fs["tp"] + fs["fp"])
            else None
        )
        rec = (
            round(fs["tp"] / (fs["tp"] + fs["fn"]), 4)
            if (fs["tp"] + fs["fn"])
            else None
        )
        report.per_family[fam] = {
            **fs,
            "classification_accuracy": round(fs["cls_ok"] / max(fs["n"], 1), 4),
            "review_accuracy": round(fs["rev_ok"] / max(fs["n"], 1), 4),
            "precision": prec,
            "recall": rec,
        }

    return report
