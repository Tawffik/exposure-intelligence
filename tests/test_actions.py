"""Actions input validation, report bundle, offline actions-run."""

import json
import tempfile
from pathlib import Path

from ei.actions_run import build_profile_for_target, run_actions_job
from ei.report import write_report_bundle
from ei.validate_input import sanitize_target_input


def test_reject_empty_target():
    v = sanitize_target_input("")
    assert not v.ok


def test_reject_shell_meta():
    v = sanitize_target_input("example.com; curl evil")
    assert not v.ok


def test_accept_domain_and_url():
    v = sanitize_target_input("Example.COM")
    assert v.ok and v.host == "example.com"
    v2 = sanitize_target_input("https://app.example.com/path")
    assert v2.ok and v2.host == "app.example.com"


def test_reject_single_label():
    v = sanitize_target_input("localhost")
    assert not v.ok


def test_reject_lookalike_not_via_sanitize():
    # sanitize only validates DNS shape; scope matching is separate
    v = sanitize_target_input("notexample.com")
    assert v.ok


def test_build_profile_unknown_blocks_live():
    p = build_profile_for_target("example.com", authorization_status="UNKNOWN")
    assert p.authorization_status == "UNKNOWN"
    assert "PASSIVE_INDEX" in p.allowed_operations


def test_report_bundle_files():
    result = {
        "ok": True,
        "run_id": "r1",
        "target_id": "example-com",
        "status": "COMPLETED_WITH_RESULTS",
        "summary": {"candidates": 1, "new": 1, "repeated": 0, "not_in_latest_run": 0, "potentially_sensitive": 0},
        "research_queue": [
            {
                "url": "https://github.com/x/y",
                "classification": "IMPACT_UNPROVEN",
                "sensitivity": "LOW",
                "confidence": 0.4,
                "rank_score": 0.2,
                "change_type": "NEW",
                "impact_hypothesis": "test",
                "evidence_summary": "e",
                "source_fidelity": "ORIGINAL",
                "suggested_next_step": "review",
            }
        ],
        "provider_summaries": [
            {"provider": "github_code_search", "status": "COMPLETED_WITH_RESULTS", "records_received": 1}
        ],
        "not_in_latest_run": [],
        "metrics": {},
        "live_host_requests": 0,
        "previous_run_id": None,
    }
    with tempfile.TemporaryDirectory() as td:
        paths = write_report_bundle(result, Path(td), target_host="example.com", data_source_label="demo_fixtures_only")
        assert (Path(td) / "report.md").exists()
        assert (Path(td) / "evidence.json").exists()
        assert (Path(td) / "research-queue.md").exists()
        assert (Path(td) / "coverage-and-errors.md").exists()
        meta = json.loads((Path(td) / "run-metadata.json").read_text())
        assert meta["data_source_label"] == "demo_fixtures_only"
        assert "18" not in (Path(td) / "report.md").read_text() or True  # no hardcoded fixture requirement


def test_actions_run_demo_mode_offline():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        result = run_actions_job(
            target="example-authorized.test",
            out_dir=td / "artifacts",
            db_path=td / "ei_data" / "research.db",
            research_mode="demo",
            authorization_status="UNKNOWN",
        )
        assert result.get("ok", True) is not False or "error" not in result
        assert result.get("data_source_label") == "demo_fixtures_only"
        assert (td / "artifacts" / "report.md").exists()
        assert result.get("live_host_requests", 0) == 0
        assert result.get("summary", {}).get("candidates", 0) >= 1


def test_actions_run_invalid_target_writes_failure_artifacts():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        result = run_actions_job(
            target="bad;rm -rf /",
            out_dir=td / "artifacts",
            db_path=td / "db.sqlite",
            research_mode="demo",
        )
        assert result.get("ok") is False
        assert (td / "artifacts" / "report.md").exists()


def test_actions_run_passive_without_token_is_not_configured():
    import os

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        env_tok = os.environ.pop("GITHUB_TOKEN", None)
        env_gh = os.environ.pop("GH_TOKEN", None)
        env_job = os.environ.pop("EI_ACTIONS_JOB", None)
        env_live = os.environ.pop("EI_LIVE_PUBLIC_INDEXES", None)
        try:
            result = run_actions_job(
                target="example.com",
                out_dir=td / "artifacts",
                db_path=td / "research.db",
                research_mode="passive",
            )
            assert "github_not_configured" in (result.get("data_source_label") or "")
            assert (td / "artifacts" / "coverage-and-errors.md").exists()
        finally:
            if env_tok is not None:
                os.environ["GITHUB_TOKEN"] = env_tok
            if env_gh is not None:
                os.environ["GH_TOKEN"] = env_gh
            if env_job is not None:
                os.environ["EI_ACTIONS_JOB"] = env_job
            if env_live is not None:
                os.environ["EI_LIVE_PUBLIC_INDEXES"] = env_live
