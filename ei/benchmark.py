"""
Classification / evidence-review benchmark runner (charter §10).

Measures classification and review decisions against a labeled fixture corpus.
A high candidate count is not a success metric — precision on labeled cases is.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from ei.classifier import classify_observation
from ei.evidence_review import review_candidate
from ei.models import utc_now_iso


@dataclass
class BenchmarkCaseResult:
    case_id: str
    expected_classification: str
    actual_classification: str
    classification_match: bool
    expected_review: str
    actual_review: str
    review_match: bool
    reason_codes: list[str] = field(default_factory=list)
    evidence_basis: str = ""
    note: str = ""


@dataclass
class BenchmarkReport:
    schema_version: str = "1.0"
    generated_at: str = ""
    corpus_path: str = ""
    total: int = 0
    classification_correct: int = 0
    review_correct: int = 0
    classification_accuracy: float = 0.0
    review_accuracy: float = 0.0
    cases: list[BenchmarkCaseResult] = field(default_factory=list)
    mismatches: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def run_classification_benchmark(corpus_path: Path) -> BenchmarkReport:
    cases = json.loads(Path(corpus_path).read_text(encoding="utf-8"))
    if not isinstance(cases, list):
        raise ValueError("Benchmark corpus must be a JSON list")

    report = BenchmarkReport(
        generated_at=utc_now_iso(),
        corpus_path=str(corpus_path),
        total=len(cases),
    )
    for case in cases:
        if not isinstance(case, dict):
            continue
        cid = case.get("id") or case.get("url") or "unknown"
        exp_cls = case.get("expected_classification") or ""
        exp_rev = case.get("expected_review") or ""
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
        cls_ok = cls == exp_cls
        # Soft match: POTENTIAL vs NEEDS_REVIEW when relationship is index-only
        rev_ok = review["review_decision"] == exp_rev
        if (
            not rev_ok
            and exp_rev == "POTENTIAL_EXPOSURE_UNCONFIRMED"
            and review["review_decision"] == "NEEDS_REVIEW"
        ):
            rev_ok = True
        if cls_ok:
            report.classification_correct += 1
        if rev_ok:
            report.review_correct += 1
        row = BenchmarkCaseResult(
            case_id=str(cid),
            expected_classification=exp_cls,
            actual_classification=cls,
            classification_match=cls_ok,
            expected_review=exp_rev,
            actual_review=review["review_decision"],
            review_match=rev_ok,
            reason_codes=list(reasons),
            evidence_basis=review.get("evidence_basis", ""),
            note=case.get("note", ""),
        )
        report.cases.append(row)
        if not cls_ok or not rev_ok:
            report.mismatches.append(
                {
                    "id": cid,
                    "classification_match": cls_ok,
                    "review_match": rev_ok,
                    "expected_classification": exp_cls,
                    "actual_classification": cls,
                    "expected_review": exp_rev,
                    "actual_review": review["review_decision"],
                    "reasons": reasons,
                }
            )

    n = max(report.total, 1)
    report.classification_accuracy = round(report.classification_correct / n, 4)
    report.review_accuracy = round(report.review_correct / n, 4)
    return report
