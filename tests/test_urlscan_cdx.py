"""URLScan and Internet Archive CDX provider tests (offline fixtures)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from ei.actions_run import run_actions_job
from ei.profile import load_profile
from ei.providers.cdx import (
    CDXProvider,
    build_cdx_url_pattern,
    normalize_cdx_payload,
)
from ei.providers.urlscan import (
    URLScanProvider,
    build_urlscan_query,
    normalize_urlscan_search_response,
)
from ei.research import run_research
from ei.store import ResearchStore

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "examples" / "program_profile.json"
URLSCAN_SAMPLE = ROOT / "examples" / "urlscan_sample.json"
URLSCAN_EMPTY = ROOT / "examples" / "urlscan_empty.json"
CDX_SAMPLE = ROOT / "examples" / "cdx_sample.json"
CDX_EMPTY = ROOT / "examples" / "cdx_empty.json"
GH = ROOT / "examples" / "github_code_search_sample.json"
BASELINE = ROOT / "examples" / "sample_observations.json"


def test_urlscan_query_builder():
    assert build_urlscan_query("example.com") == "domain:example.com"


def test_urlscan_fixture_normalize():
    payload = json.loads(URLSCAN_SAMPLE.read_text())
    recs = normalize_urlscan_search_response(
        payload, query="domain:example-authorized.test", target_host="example-authorized.test"
    )
    assert len(recs) == 2
    assert recs[0]["provider"] == "urlscan"
    assert recs[0]["discovery_mode"] == "PASSIVE_INDEX"
    assert recs[0]["metadata"]["target_relationship"] in {
        "RELATED_CANDIDATE",
        "INDEX_ONLY",
    }
    # first item domain matches target
    assert recs[0]["metadata"]["page_domain"] == "example-authorized.test"


def test_urlscan_collect_fixture():
    r = URLScanProvider().collect_from_fixture(
        URLSCAN_SAMPLE, target_host="example-authorized.test"
    )
    assert r.status == "COMPLETED_WITH_RESULTS"
    assert len(r.records) == 2
    assert r.provider == "urlscan"


def test_urlscan_empty_fixture():
    r = URLScanProvider().collect_from_fixture(
        URLSCAN_EMPTY, target_host="example-authorized.test"
    )
    assert r.status == "COMPLETED_ZERO"
    assert r.records == []


def test_urlscan_live_mocked():
    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return URLSCAN_SAMPLE.read_bytes()

        status = 200

    with patch("urllib.request.urlopen", return_value=FakeResp()):
        r = URLScanProvider().collect_live("example-authorized.test", size=5)
    assert r.status == "COMPLETED_WITH_RESULTS"
    assert r.actual_queries and "domain:example-authorized.test" in r.query


def test_cdx_pattern():
    assert build_cdx_url_pattern("example.com") == "example.com/*"


def test_cdx_fixture_object():
    r = CDXProvider().collect_from_fixture(
        CDX_SAMPLE, target_host="example-authorized.test"
    )
    assert r.status == "COMPLETED_WITH_RESULTS"
    assert len(r.records) == 3
    assert r.records[0]["discovery_mode"] == "HISTORICAL"
    assert r.records[0]["metadata"]["path_sensitive_hint"] is True  # backup.zip
    assert "wayback_url" in r.records[0]["metadata"]


def test_cdx_empty_array_headers_only():
    r = CDXProvider().collect_from_fixture(CDX_EMPTY, target_host="example.com")
    assert r.status == "COMPLETED_ZERO"


def test_cdx_array_of_arrays_normalize():
    payload = [
        ["timestamp", "original", "statuscode", "mimetype", "digest", "length"],
        ["20240101000000", "https://example.com/.env", "200", "text/plain", "X", "10"],
    ]
    recs = normalize_cdx_payload(payload, target_host="example.com")
    assert len(recs) == 1
    assert recs[0]["metadata"]["path_sensitive_hint"] is True


def test_research_multi_provider_fixtures():
    with tempfile.TemporaryDirectory() as td:
        store = ResearchStore(Path(td) / "db.sqlite")
        profile = load_profile(PROFILE)
        r = run_research(
            profile,
            store=store,
            fixture_path=BASELINE,
            github_fixture=GH,
            urlscan_fixture=URLSCAN_SAMPLE,
            cdx_fixture=CDX_SAMPLE,
            max_results=10,
            target_host="example-authorized.test",
            research_mode="demo",
        )
        providers = {p["provider"]: p["status"] for p in r["provider_summaries"]}
        assert providers.get("fixture") in {"COMPLETED_WITH_RESULTS", "COMPLETED_ZERO"}
        assert providers.get("github_code_search") == "COMPLETED_WITH_RESULTS"
        assert providers.get("urlscan") == "COMPLETED_WITH_RESULTS"
        assert providers.get("internet_archive_cdx") == "COMPLETED_WITH_RESULTS"
        assert r["summary"]["candidates"] >= 1
        store.close()


def test_actions_demo_includes_all_providers():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        result = run_actions_job(
            target="example.com",
            out_dir=td / "artifacts",
            db_path=td / "db.sqlite",
            research_mode="demo",
            max_github_results=10,
        )
        assert result.get("data_source_label") == "demo_fixtures_only"
        names = {p.get("provider") for p in result.get("provider_summaries") or []}
        assert "urlscan" in names
        assert "internet_archive_cdx" in names
        assert "github_code_search" in names
        assert (td / "artifacts" / "report.md").exists()
        assert (td / "artifacts" / "provider-status.json").exists()


def test_cdx_live_mocked():
    payload = [
        ["timestamp", "original", "statuscode", "mimetype", "digest", "length"],
        ["20240101000000", "https://example.com/backup.sql", "200", "application/sql", "D", "99"],
    ]

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(payload).encode()

    with patch("urllib.request.urlopen", return_value=FakeResp()):
        r = CDXProvider().collect_live("example.com", limit=5)
    assert r.status == "COMPLETED_WITH_RESULTS"
    assert len(r.records) == 1
    assert r.records[0]["metadata"]["path_sensitive_hint"] is True
