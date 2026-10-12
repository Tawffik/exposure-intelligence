"""Operational vertical slice: profile, store, research workflow."""

import json
import tempfile
from pathlib import Path

from ei.profile import (
    assess_relevance,
    live_request_permitted,
    load_profile,
    profile_from_dict,
    validate_profile,
)
from ei.research import run_research
from ei.store import ResearchStore

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "examples" / "program_profile.json"
BASELINE = ROOT / "examples" / "sample_observations.json"
GH = ROOT / "examples" / "github_code_search_sample.json"
GH_ERROR = ROOT / "examples" / "github_code_search_error.json"


def test_profile_valid():
    p = load_profile(PROFILE)
    v = validate_profile(p)
    assert v.ok
    assert p.target_id == "demo-program"


def test_profile_missing_target_id():
    p = profile_from_dict({"target_id": "", "authorization_status": "ACTIVE"})
    v = validate_profile(p)
    assert not v.ok


def test_profile_bad_auth_status():
    p = profile_from_dict({"target_id": "x", "authorization_status": "MAYBE"})
    v = validate_profile(p)
    assert not v.ok


def test_relevance_in_scope_and_github_public_index():
    p = load_profile(PROFILE)
    rel = assess_relevance(p, "https://example-authorized.test/backup.zip")
    assert rel["relevance"] == "IN_SCOPE"
    gh = assess_relevance(
        p, "https://github.com/example-org/demo-app/blob/abc/.env"
    )
    assert gh["relevance"] == "PUBLIC_INDEX"
    assert gh["live_allowed"] is False


def test_out_of_scope():
    p = load_profile(PROFILE)
    rel = assess_relevance(p, "https://out-of-scope.example/secret")
    assert rel["relevance"] == "OUT_OF_SCOPE"


def test_live_denied_when_not_active():
    p = profile_from_dict(
        {
            "target_id": "t",
            "authorization_status": "EXPIRED",
            "in_scope_hosts": ["example-authorized.test"],
            "allowed_operations": ["CURRENT_OBSERVATION_GET"],
        }
    )
    gate = live_request_permitted(p, "https://example-authorized.test/")
    assert gate["allowed"] is False


def test_live_denied_for_github_host():
    p = load_profile(PROFILE)
    gate = live_request_permitted(p, "https://github.com/org/repo/blob/x/.env")
    assert gate["allowed"] is False


def test_research_persists_and_compares():
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "ei.db"
        store = ResearchStore(db)
        profile = load_profile(PROFILE)

        r1 = run_research(
            profile,
            store=store,
            fixture_path=BASELINE,
            github_fixture=None,
        )
        assert r1["ok"]
        assert r1["summary"]["candidates"] >= 10
        assert r1["previous_run_id"] is None
        assert r1["summary"]["new"] == r1["summary"]["candidates"]
        assert r1["live_host_requests"] == 0

        r2 = run_research(
            profile,
            store=store,
            fixture_path=BASELINE,
            github_fixture=GH,
        )
        assert r2["ok"]
        assert r2["previous_run_id"] == r1["run_id"]
        assert r2["summary"]["repeated"] >= 1
        assert r2["summary"]["new"] >= 1
        assert r2["summary"]["candidates"] > r1["summary"]["candidates"]

        runs = store.list_runs(profile.target_id)
        assert len(runs) == 2
        queue = store.queue_for_target(profile.target_id)
        assert len(queue) >= r1["summary"]["candidates"]
        store.close()


def test_provider_failure_does_not_erase_fixture_candidates():
    with tempfile.TemporaryDirectory() as td:
        store = ResearchStore(Path(td) / "ei.db")
        profile = load_profile(PROFILE)
        r = run_research(
            profile,
            store=store,
            fixture_path=BASELINE,
            github_fixture=GH_ERROR,
        )
        assert r["ok"]
        assert r["summary"]["candidates"] >= 10
        gh_sum = [p for p in r["provider_summaries"] if p["provider"] == "github_code_search"]
        assert gh_sum and gh_sum[0]["status"] == "RATE_LIMITED"
        store.close()


def test_second_identical_run_marks_repeated():
    with tempfile.TemporaryDirectory() as td:
        store = ResearchStore(Path(td) / "ei.db")
        profile = load_profile(PROFILE)
        run_research(profile, store=store, fixture_path=BASELINE)
        r2 = run_research(profile, store=store, fixture_path=BASELINE)
        assert r2["summary"]["new"] == 0
        assert r2["summary"]["repeated"] >= 10
        store.close()


def test_queue_entries_have_next_step():
    with tempfile.TemporaryDirectory() as td:
        store = ResearchStore(Path(td) / "ei.db")
        profile = load_profile(PROFILE)
        r = run_research(profile, store=store, fixture_path=BASELINE, github_fixture=GH)
        assert r["research_queue"]
        top = r["research_queue"][0]
        assert "suggested_next_step" in top
        assert "change_type" in top
        store.close()
