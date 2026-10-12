"""Offline tests for GitHub code-search adapter and shadow mode."""

from pathlib import Path

from ei.models import RunStatus
from ei.pipeline import load_fixture_file, run_pipeline
from ei.providers.github_code_search import (
    GitHubCodeSearchProvider,
    normalize_github_search_response,
    load_github_fixture,
)
from ei.shadow import run_shadow_from_paths, run_shadow_comparison

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "examples" / "sample_observations.json"
GH_SAMPLE = ROOT / "examples" / "github_code_search_sample.json"
GH_EMPTY = ROOT / "examples" / "github_code_search_empty.json"
GH_ERROR = ROOT / "examples" / "github_code_search_error.json"
GH_PARTIAL = ROOT / "examples" / "github_code_search_partial.json"


def test_normalize_items_to_observation_records():
    result = load_github_fixture(GH_SAMPLE)
    assert result.status == RunStatus.COMPLETED_WITH_RESULTS.value
    assert len(result.records) == 3
    env = result.records[0]
    assert env["provider"] == "github_code_search"
    assert env["discovery_mode"] == "PASSIVE_INDEX"
    assert env["source_fidelity"] == "ORIGINAL"
    assert "github.com" in env["url"]
    assert env["source_record_id"]
    assert "API_KEY" in env["body"] or "supersecret" in env["body"]
    assert env["scope_decision"] == "UNKNOWN"


def test_empty_search_is_completed_zero_not_error():
    result = load_github_fixture(GH_EMPTY)
    assert result.status == RunStatus.COMPLETED_ZERO.value
    assert result.records == []
    assert result.error_summary == ""


def test_rate_limit_message_is_rate_limited():
    result = load_github_fixture(GH_ERROR)
    assert result.status == RunStatus.RATE_LIMITED.value
    assert "rate limit" in result.error_summary.lower()
    assert result.records == []


def test_incomplete_results_is_partial():
    result = load_github_fixture(GH_PARTIAL)
    assert result.status == RunStatus.PARTIAL.value
    assert len(result.records) == 1
    assert result.incomplete_results is True


def test_malformed_payload_is_error():
    result = normalize_github_search_response({"no_items": True}, query="x")
    assert result.status == RunStatus.ERROR.value


def test_live_without_token_is_not_configured():
    p = GitHubCodeSearchProvider(token="")
    result = p.collect_live("filename:.env")
    assert result.status == RunStatus.NOT_CONFIGURED.value
    assert result.records == []


def test_shadow_adds_novel_candidates_without_losing_baseline():
    out = run_shadow_from_paths(BASELINE, GH_SAMPLE, target_id="t1")
    cmp_ = out["comparison"]
    assert cmp_["baseline"]["candidates"] >= 10
    assert cmp_["provider"]["status"] == RunStatus.COMPLETED_WITH_RESULTS.value
    assert cmp_["incremental"]["novel_candidate_urls"] >= 1
    assert cmp_["incremental"]["candidate_loss_vs_baseline"] == 0
    assert cmp_["merged"]["observations"] > cmp_["baseline"]["observations"]
    assert cmp_["shadow_mode"]["active_target_validation"] is False
    # Baseline sensitive count should not drop
    assert cmp_["merged"]["potentially_sensitive"] >= cmp_["baseline"]["potentially_sensitive"]


def test_shadow_provider_failure_preserves_baseline():
    out = run_shadow_from_paths(BASELINE, GH_ERROR, target_id="t2")
    cmp_ = out["comparison"]
    assert cmp_["provider"]["status"] == RunStatus.RATE_LIMITED.value
    assert cmp_["incremental"]["novel_candidate_urls"] == 0
    assert cmp_["incremental"]["candidate_loss_vs_baseline"] == 0
    assert cmp_["baseline"]["candidates"] == cmp_["merged"]["candidates"]


def test_shadow_empty_provider_no_loss():
    out = run_shadow_from_paths(BASELINE, GH_EMPTY, target_id="t3")
    cmp_ = out["comparison"]
    assert cmp_["provider"]["status"] == RunStatus.COMPLETED_ZERO.value
    assert cmp_["incremental"]["candidate_loss_vs_baseline"] == 0


def test_provider_records_flow_through_classifier():
    result = load_github_fixture(GH_SAMPLE)
    report = run_pipeline(result.records, provider_name="github_code_search")
    assert report.status == RunStatus.COMPLETED_WITH_RESULTS.value
    classes = {c.classification for c in report.candidates}
    # .env fragment with secret pattern and source map should surface as sensitive/unproven
    assert report.metrics["candidates"] == 3
    assert any(c.primary_url.endswith(".env") for c in report.candidates)


def test_not_configured_shadow_without_fixture():
    out = run_shadow_from_paths(BASELINE, None, target_id="t4")
    assert out["comparison"]["provider"]["status"] == RunStatus.NOT_CONFIGURED.value
    assert out["comparison"]["incremental"]["candidate_loss_vs_baseline"] == 0
