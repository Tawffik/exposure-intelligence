"""Pipeline, provenance, redaction, run-state, and ranking tests."""

import json
from pathlib import Path

import pytest

from ei.models import RunStatus, redact_text
from ei.pipeline import run_from_fixture_path, run_pipeline
from ei.ranker import observations_to_candidates
from ei.classifier import build_observation_from_fixture

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "sample_observations.json"


def test_demo_fixture_runs_with_results():
    report = run_from_fixture_path(EXAMPLE, target_id="demo")
    assert report.status == RunStatus.COMPLETED_WITH_RESULTS.value
    assert report.metrics["observations"] >= 10
    assert len(report.candidates) >= 1
    # Sensitive candidates should rank above SPA noise
    classes = {c.classification for c in report.candidates}
    assert "POTENTIALLY_SENSITIVE" in classes
    assert "SPA_SHELL" in classes
    top = report.candidates[0]
    assert top.rank_score >= report.candidates[-1].rank_score


def test_completed_zero():
    report = run_pipeline([])
    assert report.status == RunStatus.COMPLETED_ZERO.value
    assert report.metrics["observations"] == 0


def test_error_state_not_zero():
    report = run_pipeline([], inject_error="provider timeout")
    assert report.status == RunStatus.ERROR.value
    assert report.provider_summaries[0].error_summary == "provider timeout"
    assert report.metrics.get("candidates", 0) == 0


def test_not_configured():
    report = run_pipeline([], inject_status=RunStatus.NOT_CONFIGURED.value)
    assert report.status == RunStatus.NOT_CONFIGURED.value


def test_rate_limited():
    report = run_pipeline([], inject_status=RunStatus.RATE_LIMITED.value)
    assert report.status == RunStatus.RATE_LIMITED.value


def test_skipped_by_policy():
    report = run_pipeline([], inject_status=RunStatus.SKIPPED_BY_POLICY.value)
    assert report.status == RunStatus.SKIPPED_BY_POLICY.value


def test_partial():
    report = run_pipeline(
        [{"url": "https://t.example/a", "status": 200, "content_type": "text/plain", "body": "x"}],
        inject_status=RunStatus.PARTIAL.value,
    )
    assert report.status == RunStatus.PARTIAL.value
    assert report.metrics["observations"] == 1


def test_redaction_strips_secrets():
    text, changed = redact_text("password=hunter2secretvalue\nsafe")
    assert "[REDACTED]" in text
    assert changed
    assert "hunter2secretvalue" not in text


def test_provenance_preserved():
    obs = build_observation_from_fixture(
        {
            "url": "https://t.example/backup.zip",
            "status": 200,
            "content_type": "application/zip",
            "body": "PK\x03\x04",
            "source_url": "https://source.example/1",
            "source_record_id": "rec-1",
            "discovery_mode": "CURRENT_OBSERVATION",
            "source_fidelity": "ORIGINAL",
        },
        run_id="run-abc",
        target_id="tgt-1",
    )
    assert obs.run_id == "run-abc"
    assert obs.target_id == "tgt-1"
    assert obs.source_url == "https://source.example/1"
    assert obs.source_record_id == "rec-1"
    assert obs.body_sha256
    assert obs.source_fidelity == "ORIGINAL"
    assert "password" not in (obs.preview_redacted or "").lower() or "[REDACTED]" in obs.preview_redacted


def test_env_secret_redacted_in_observation():
    obs = build_observation_from_fixture(
        {
            "url": "https://t.example/.env",
            "status": 200,
            "content_type": "text/plain",
            "body": "API_KEY=supersecretvalue12345\n",
        }
    )
    assert obs.redaction_applied
    assert "supersecretvalue12345" not in obs.preview_redacted
    assert "[REDACTED]" in obs.preview_redacted


def test_ranking_explainable():
    obs_list = [
        build_observation_from_fixture(
            {
                "url": "https://t.example/backup.zip",
                "status": 200,
                "content_type": "application/zip",
                "body": "PK\x03\x04",
                "discovery_mode": "CURRENT_OBSERVATION",
            }
        ),
        build_observation_from_fixture(
            {
                "url": "https://t.example/",
                "status": 200,
                "content_type": "text/html",
                "body": '<div id="root"></div>',
            }
        ),
    ]
    cands = observations_to_candidates(obs_list)
    assert cands[0].rank_explanation
    assert cands[0].primary_url.endswith("backup.zip")


def test_invalid_fixture_raises():
    from ei.pipeline import load_fixture_file
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write('{"nope": true}')
        path = Path(f.name)
    with pytest.raises(ValueError):
        load_fixture_file(path)


def test_report_json_roundtrip_fields():
    report = run_from_fixture_path(EXAMPLE)
    data = json.loads(report.to_json())
    assert data["schema_version"] == "1.0"
    assert data["status"] == RunStatus.COMPLETED_WITH_RESULTS.value
    assert len(data["observations"]) == len(report.observations)
    for o in data["observations"]:
        assert "observation_id" in o
        assert "classification" in o
        assert "source_fidelity" in o