from pathlib import Path

from ei.report import write_report_bundle, _build_human_queue_md


def test_human_queue_filters_low_priority(tmp_path: Path):
    result = {
        "run_id": "run-1",
        "target_id": "example.com",
        "status": "PARTIAL",
        "summary": {"candidates": 2},
        "provider_summaries": [
            {
                "provider": "github_code_search",
                "status": "PARTIAL",
                "records_received": 2,
                "error_summary": "429 after partial",
            }
        ],
        "research_queue": [
            {
                "url": "https://github.com/a/b/.env",
                "classification": "IMPACT_UNPROVEN",
                "review_decision": "NEEDS_REVIEW",
                "change_type": "NEW",
                "evidence_summary": "path hit",
                "suggested_next_step": "Open the blob",
            },
            {
                "url": "https://github.com/a/b/.env.example",
                "classification": "KEYWORD_FALSE_POSITIVE",
                "review_decision": "LOW_PRIORITY",
                "change_type": "NEW",
            },
        ],
        "live_host_requests": 0,
    }
    paths = write_report_bundle(result, tmp_path, target_host="example.com", research_mode="demo")
    assert "HUMAN_QUEUE.md" in paths
    text = (tmp_path / "HUMAN_QUEUE.md").read_text(encoding="utf-8")
    assert "NEEDS_REVIEW" in text or "https://github.com/a/b/.env" in text
    assert ".env.example" not in text  # low priority omitted
    assert "PARTIAL" in text
    assert "confirmed_vulnerability" in text.lower() or "Confirmed vulnerability" in text


def test_empty_human_queue_explains_not_clean():
    text = _build_human_queue_md(
        {
            "run_id": "x",
            "status": "RATE_LIMITED",
            "research_queue": [],
            "provider_summaries": [
                {"provider": "github_code_search", "status": "RATE_LIMITED", "records_received": 0}
            ],
        },
        research_mode="passive",
        target_host="t.com",
    )
    assert "not" in text.lower() and "clean" in text.lower()
    assert "RATE_LIMITED" in text


def test_research_queue_attaches_hypothesis(tmp_path: Path):
    """Operator queue must carry structured hypothesis + impact-oriented next step."""
    from ei.actions_run import run_actions_job

    out = tmp_path / "out"
    result = run_actions_job(
        target="example.com",
        out_dir=out,
        db_path=tmp_path / "ei.db",
        research_mode="demo",
        authorization_status="UNKNOWN",
        max_github_results=5,
    )
    assert result.get("ok") is not False
    queue = result.get("research_queue") or []
    actionable = [
        c
        for c in queue
        if (c.get("review_decision") or "") in {"NEEDS_REVIEW", "POTENTIAL_EXPOSURE_UNCONFIRMED"}
    ]
    assert actionable, "demo fixtures should produce at least one actionable lead"
    for item in actionable:
        hyp = item.get("hypothesis")
        assert isinstance(hyp, dict), f"missing hypothesis on {item.get('url')}"
        assert hyp.get("confirmed_vulnerability") is False
        assert hyp.get("safe_next_step")
        assert item.get("suggested_next_step")
    hq = (out / "HUMAN_QUEUE.md").read_text(encoding="utf-8")
    assert "Attribution legend" in hq or "DIRECT_HOST" in hq
    assert "Safe next step" in hq


def test_hypothesis_unattributed_overrides_path_template():
    """UNATTRIBUTED must not get path-only 'open the blob' guidance."""
    from ei.hypothesis import build_hypothesis

    h = build_hypothesis(
        {
            "url": "https://evil.test/.env",
            "classification": "POTENTIALLY_SENSITIVE",
            "review_decision": "NEEDS_REVIEW",
            "target_relationship": "UNATTRIBUTED",
            "classification_reason_codes": ["sensitive_path"],
        }
    )
    assert h["confirmed_vulnerability"] is False
    step = h["safe_next_step"].lower()
    assert "does not match" in step or "ownership" in step
    assert "open the public blob" not in step


def test_hypothesis_index_only_before_env_path():
    from ei.hypothesis import build_hypothesis

    h = build_hypothesis(
        {
            "url": "https://github.com/other/repo/blob/main/.env",
            "classification": "POTENTIALLY_SENSITIVE",
            "review_decision": "NEEDS_REVIEW",
            "target_relationship": "INDEX_ONLY",
            "classification_reason_codes": ["sensitive_path"],
        }
    )
    step = h["safe_next_step"].lower()
    assert "index" in step or "ownership" in step


def test_benchmark_precision_recall_definitions():
    from pathlib import Path
    from ei.benchmark import run_classification_benchmark

    r = run_classification_benchmark(Path("examples/classification_benchmark.json"))
    assert r.total >= 20
    assert r.ambiguous_excluded >= 1
    assert r.review_precision is not None
    assert r.review_recall is not None
    assert r.schema_version == "2.0"
    assert r.mismatches == []
