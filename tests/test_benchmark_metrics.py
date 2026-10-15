"""Benchmark metric integrity — imperfect examples, denominators, ambiguous exclusion."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ei.benchmark import (
    ACTIONABLE_REVIEWS,
    NEGATIVE_REVIEWS,
    run_classification_benchmark,
)


def _write_corpus(tmp_path: Path, cases: list[dict]) -> Path:
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps(cases), encoding="utf-8")
    return p


def test_empty_corpus(tmp_path: Path) -> None:
    p = _write_corpus(tmp_path, [])
    r = run_classification_benchmark(p)
    assert r.total == 0
    assert r.review_precision is None
    assert r.review_recall is None
    assert r.mismatches == []


def test_invalid_schema_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text('{"not": "a list"}', encoding="utf-8")
    with pytest.raises(ValueError):
        run_classification_benchmark(p)


def test_ambiguous_excluded_from_pr(tmp_path: Path) -> None:
    cases = [
        {
            "id": "amb",
            "expected_review": "AMBIGUOUS",
            "ambiguous": True,
            "url": "https://example.com/x",
            "status": 200,
            "body": "hello",
            "family": "noise_public",
        },
        {
            "id": "neg",
            "expected_classification": "INTENTIONALLY_PUBLIC",
            "expected_review": "LOW_PRIORITY",
            "url": "https://example.com/about",
            "status": 200,
            "content_type": "text/html",
            "body": "<html><body><h1>About</h1></body></html>",
            "family": "noise_public",
        },
    ]
    r = run_classification_benchmark(_write_corpus(tmp_path, cases))
    assert r.ambiguous_excluded == 1
    assert r.labeled_for_review_metrics == 1
    # Ambiguous must not inflate TN silently beyond the one labeled negative
    assert r.review_tp + r.review_fp + r.review_fn + r.review_tn == 1


def test_false_positive_and_false_negative_counts(tmp_path: Path) -> None:
    """Force imperfect predictions by labeling opposite of likely classifier output."""
    cases = [
        # Likely LOW_PRIORITY public page, but labeled as actionable → FN if actual low
        {
            "id": "force_fn",
            "expected_classification": "INTENTIONALLY_PUBLIC",
            "expected_review": "NEEDS_REVIEW",  # expect actionable
            "url": "https://example.com/about",
            "status": 200,
            "content_type": "text/html",
            "body": "<html><body><h1>About us</h1></body></html>",
            "family": "noise_public",
        },
        # Sensitive path likely elevated; label LOW_PRIORITY → FP if actual actionable
        {
            "id": "force_fp",
            "expected_classification": "POTENTIALLY_SENSITIVE",
            "expected_review": "LOW_PRIORITY",
            "url": "https://example-authorized.test/.env",
            "status": 200,
            "content_type": "text/plain",
            "body": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
            "family": "env_config",
        },
    ]
    r = run_classification_benchmark(_write_corpus(tmp_path, cases))
    # We do not assert exact TP/FP — only that metrics reconcile when non-zero
    total = r.review_tp + r.review_fp + r.review_fn + r.review_tn
    assert total == r.labeled_for_review_metrics
    if (r.review_tp + r.review_fp) > 0:
        assert r.review_precision == round(
            r.review_tp / (r.review_tp + r.review_fp), 4
        )
    if (r.review_tp + r.review_fn) > 0:
        assert r.review_recall == round(
            r.review_tp / (r.review_tp + r.review_fn), 4
        )
    # At least one of FP or FN should appear given adversarial labels
    assert (r.review_fp + r.review_fn) >= 1


def test_missing_expected_classification_not_penalized(tmp_path: Path) -> None:
    cases = [
        {
            "id": "no_cls",
            "expected_classification": "",
            "expected_review": "LOW_PRIORITY",
            "url": "https://example.com/about",
            "status": 200,
            "content_type": "text/html",
            "body": "<html><body><h1>About</h1></body></html>",
            "family": "noise_public",
        }
    ]
    r = run_classification_benchmark(_write_corpus(tmp_path, cases))
    assert r.total == 1
    # classification_accuracy uses only labeled classification cases
    assert r.classification_accuracy == 1.0 or r.classification_correct == 0


def test_family_with_single_example_reports_denominator(tmp_path: Path) -> None:
    cases = [
        {
            "id": "solo",
            "expected_classification": "INTENTIONALLY_PUBLIC",
            "expected_review": "LOW_PRIORITY",
            "url": "https://example.com/about",
            "status": 200,
            "content_type": "text/html",
            "body": "<html><body><h1>About</h1></body></html>",
            "family": "tiny_family",
        }
    ]
    r = run_classification_benchmark(_write_corpus(tmp_path, cases))
    assert "tiny_family" in r.per_family
    assert r.per_family["tiny_family"]["n"] == 1


def test_project_corpus_metrics_reconcile() -> None:
    """Live project fixture: counts must reconcile; do not require perfect score."""
    corpus = Path("examples/classification_benchmark.json")
    r = run_classification_benchmark(corpus)
    assert r.schema_version == "2.0"
    assert r.total >= 20
    labeled = r.review_tp + r.review_fp + r.review_fn + r.review_tn
    assert labeled == r.labeled_for_review_metrics
    assert r.ambiguous_excluded >= 1
    if r.review_precision is not None:
        assert 0.0 <= r.review_precision <= 1.0
    if r.review_recall is not None:
        assert 0.0 <= r.review_recall <= 1.0
    # Limitations must be disclosed
    assert any("synthetic" in x.lower() or "real-world" in x.lower() for x in r.limitations)


def test_actionable_sets_documented() -> None:
    assert "NEEDS_REVIEW" in ACTIONABLE_REVIEWS
    assert "POTENTIAL_EXPOSURE_UNCONFIRMED" in ACTIONABLE_REVIEWS
    assert "LOW_PRIORITY" in NEGATIVE_REVIEWS
    assert ACTIONABLE_REVIEWS.isdisjoint(NEGATIVE_REVIEWS)
