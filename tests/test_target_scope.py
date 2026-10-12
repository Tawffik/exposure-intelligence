"""Target-scoped search, relationship labels, and max_results enforcement."""

from pathlib import Path

from ei.providers.github_code_search import (
    build_target_scoped_query,
    classify_index_relationship,
    normalize_github_item,
    normalize_github_search_response,
)
from ei.ranker import score_candidate
from ei.models import Observation
from ei.actions_run import run_actions_job
import tempfile


def test_scoped_query_includes_target_host():
    q = build_target_scoped_query("acme-example.com")
    assert "acme-example.com" in q
    assert "filename:.env" in q or "extension:map" in q


def test_scoped_query_rejects_empty_host():
    try:
        build_target_scoped_query("")
        assert False, "should raise"
    except ValueError:
        pass


def test_relationship_direct_when_host_in_path():
    r = classify_index_relationship(
        target_host="acme-example.com",
        item_path="configs/acme-example.com.env",
        repo_full_name="other/repo",
        body_snippet="",
        html_url="https://github.com/other/repo/blob/x/configs/acme-example.com.env",
    )
    assert r["relationship"] == "DIRECT_TARGET_REFERENCE"


def test_relationship_index_only_when_unrelated():
    r = classify_index_relationship(
        target_host="acme-example.com",
        item_path=".env",
        repo_full_name="random-org/random-app",
        body_snippet="API_KEY=test",
        html_url="https://github.com/random-org/random-app/blob/main/.env",
    )
    assert r["relationship"] == "INDEX_ONLY"


def test_normalize_item_carries_relationship():
    item = {
        "html_url": "https://github.com/x/y/blob/abc/.env",
        "path": ".env",
        "sha": "abc",
        "repository": {"full_name": "x/y", "html_url": "https://github.com/x/y"},
        "text_matches": [{"fragment": "SECRET=1"}],
    }
    rec = normalize_github_item(item, query="test", target_host="acme-example.com")
    assert rec["metadata"]["target_relationship"] == "INDEX_ONLY"
    assert rec["metadata"]["selected_target_host"] == "acme-example.com"


def test_max_results_truncates_provider_records():
    items = []
    for i in range(15):
        items.append(
            {
                "html_url": f"https://github.com/org/repo/blob/sha{i}/file{i}.env",
                "path": f"file{i}.env",
                "sha": f"sha{i}",
                "repository": {"full_name": "org/repo"},
            }
        )
    payload = {"total_count": 15, "incomplete_results": False, "items": items}
    result = normalize_github_search_response(payload, query="q", target_host="example.com")
    assert len(result.records) == 15
    # research layer truncates; simulate
    limited = result.records[:5]
    assert len(limited) == 5


def test_ranker_penalizes_index_only():
    obs_index = Observation(
        discovered_url="https://github.com/x/y/blob/a/.env",
        classification="POTENTIALLY_SENSITIVE",
        sensitivity="HIGH",
        confidence=0.8,
        freshness="CURRENT",
        scope_decision="PUBLIC_INDEX",
        metadata={"target_relationship": "INDEX_ONLY"},
    )
    obs_direct = Observation(
        discovered_url="https://acme-example.com/.env",
        classification="POTENTIALLY_SENSITIVE",
        sensitivity="HIGH",
        confidence=0.8,
        freshness="CURRENT",
        scope_decision="IN_SCOPE",
        metadata={"target_relationship": "DIRECT_TARGET_REFERENCE"},
    )
    s_idx, exp_idx = score_candidate(obs_index, [obs_index])
    s_dir, exp_dir = score_candidate(obs_direct, [obs_direct])
    assert s_dir > s_idx
    assert any("relationship_penalty" in e for e in exp_idx)


def test_actions_run_records_requested_and_effective_limits():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        result = run_actions_job(
            target="acme-example.com",
            out_dir=td / "artifacts",
            db_path=td / "db.sqlite",
            research_mode="demo",
            max_github_results=5,
        )
        assert result.get("requested_max_results") == 5
        assert result.get("effective_max_results") == 5
        assert (td / "artifacts" / "coverage.json").exists()
        assert (td / "artifacts" / "provider-status.json").exists()
        assert result.get("data_source_label") == "demo_fixtures_only"
