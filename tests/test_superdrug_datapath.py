"""P0 regressions from Superdrug passive run audit."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from ei.classifier import build_observation_from_fixture
from ei.models import RunReport, RunStatus, Candidate
from ei.providers.base import ProviderCollectResult
from ei.providers.github_code_search import GitHubCodeSearchProvider
from ei.providers.urlscan import normalize_urlscan_item
from ei.research import compare_runs


def test_collect_live_multi_keeps_records_on_later_error():
    """Successful query records must survive later ERROR → status PARTIAL."""
    gh = GitHubCodeSearchProvider(token="fake-token")
    ok = ProviderCollectResult(
        status=RunStatus.COMPLETED_WITH_RESULTS.value,
        records=[{"url": "https://github.com/a/b/blob/x/.env", "status": 200, "body": "K=v"}],
        query="q1",
    )
    err = ProviderCollectResult(
        status=RunStatus.ERROR.value,
        records=[],
        error_summary="HTTP 422",
        query="q2",
    )
    with patch.object(gh, "collect_live", side_effect=[ok, err]):
        r = gh.collect_live_multi(["host filename:.env", "host AKIA"], per_page=5, max_total=10, target_host="example.com")
    assert len(r.records) == 1
    assert r.status == RunStatus.PARTIAL.value
    assert "422" in (r.error_summary or "") or "error" in (r.coverage_notes or "").lower() or r.error_summary


def test_urlscan_record_not_empty_response():
    item = {
        "page": {
            "url": "https://www.superdrug.com/",
            "domain": "www.superdrug.com",
            "title": "Superdrug",
            "status": 200,
            "server": "cloudflare",
        },
        "task": {"uuid": "scan1", "time": "2024-01-01T00:00:00Z"},
        "_id": "scan1",
    }
    rec = normalize_urlscan_item(item, target_host="superdrug.com")
    assert rec.get("status") == 200
    assert rec.get("body")
    obs = build_observation_from_fixture(rec, run_id="r1", target_id="t1")
    assert obs.classification != "EMPTY_RESPONSE"
    assert obs.http_status == 200


def test_first_seen_when_no_baseline():
    report = RunReport(run_id="r1", started_at="2024-01-01T00:00:00Z", status="COMPLETED_WITH_RESULTS")
    report.candidates = [
        Candidate(stable_key="k1", primary_url="https://example.com/a", classification="IMPACT_UNPROVEN"),
    ]
    q = compare_runs(report, set(), set(), baseline_available=False)
    assert q[0]["change_type"] == "FIRST_SEEN"
    q2 = compare_runs(report, set(), set(), baseline_available=True)
    assert q2[0]["change_type"] == "NEW"
