"""Offline lead-quality evaluation harness tests."""

from __future__ import annotations

import json
from pathlib import Path

from ei.eval_harness import (
    LABEL_OUTCOMES,
    descriptive_from_queue,
    labeling_protocol,
    run_synthetic_and_descriptive,
    write_report,
    write_summary_md,
)


def test_descriptive_empty_queue() -> None:
    d = descriptive_from_queue([])
    assert d["queue_items"] == 0
    assert d["actionable_rate"] is None
    assert d["duplicate_rate"] is None


def test_descriptive_counts_and_dup_surplus() -> None:
    q = [
        {
            "url": "https://example.com/a",
            "review_decision": "NEEDS_REVIEW",
            "target_relationship": "INDEX_ONLY",
            "classification": "POTENTIALLY_SENSITIVE",
            "change_type": "FIRST_SEEN",
            "hypothesis": {"confirmed_vulnerability": False},
            "suggested_next_step": "review",
        },
        {
            "url": "https://example.com/a",  # same URL key
            "review_decision": "LOW_PRIORITY",
            "target_relationship": "UNATTRIBUTED",
            "classification": "EMPTY_RESPONSE",
            "change_type": "FIRST_SEEN",
        },
        {
            "url": "https://example.com/b",
            "review_decision": "POTENTIAL_EXPOSURE_UNCONFIRMED",
            "target_relationship": "DIRECT_HOST",
            "classification": "POTENTIALLY_SENSITIVE",
            "change_type": "NEW",
            "hypothesis": {"confirmed_vulnerability": False},
            "suggested_next_step": "open",
        },
    ]
    d = descriptive_from_queue(q)
    assert d["queue_items"] == 3
    assert d["actionable_items"] == 2
    assert d["unique_url_keys"] == 2
    assert d["duplicate_surplus"] == 1
    assert d["confirmed_vulnerability_true_count"] == 0


def test_labeling_protocol_documents_independence() -> None:
    p = labeling_protocol()
    assert "USEFUL_LEAD" in p["outcomes"]
    assert "independence_rule" in p
    assert "real_world_precision" in p["unavailable_until_labels"]
    for o in LABEL_OUTCOMES:
        assert o in p["outcomes"]


def test_run_eval_offline(tmp_path: Path) -> None:
    corpus = Path("examples/classification_benchmark.json")
    report = run_synthetic_and_descriptive(
        benchmark_path=corpus,
        out_dir=tmp_path / "demo",
        run_demo_pipeline=True,
    )
    assert report.data_kind == "synthetic_fixtures"
    assert report.synthetic_benchmark.get("total_cases", 0) >= 20
    assert report.descriptive.get("queue_items", 0) >= 1
    assert report.descriptive.get("confirmed_vulnerability_true_count") == 0
    assert report.descriptive.get("human_queue_exists") is True
    # Real-world metrics must not be invented
    blob = json.dumps(report.to_dict())
    assert "real_world_precision" not in blob or "unavailable" in json.dumps(
        report.protocol
    )

    out = tmp_path / "report"
    write_report(report, out / "lead_quality_report.json")
    write_summary_md(report, out / "lead_quality_summary.md")
    assert (out / "lead_quality_report.json").is_file()
    text = (out / "lead_quality_summary.md").read_text(encoding="utf-8")
    assert "Synthetic" in text or "synthetic" in text.lower()
    assert "not available" in text.lower() or "not available" in text


def test_missing_benchmark_excluded(tmp_path: Path) -> None:
    report = run_synthetic_and_descriptive(
        benchmark_path=tmp_path / "missing.json",
        out_dir=tmp_path / "demo2",
        run_demo_pipeline=False,
    )
    assert any(e.get("reason") == "benchmark_missing" for e in report.excluded)
