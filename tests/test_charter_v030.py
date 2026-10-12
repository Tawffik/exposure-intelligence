"""Registry, probe policy, benchmark, export — charter v0.3.0."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from ei.benchmark import run_classification_benchmark
from ei.export_adapter import build_export_bundle
from ei.probe import collect_probes, plan_probe_urls
from ei.profile import profile_from_dict
from ei.registry import load_registry

ROOT = Path(__file__).resolve().parents[1]


def test_registry_loads_example():
    r = load_registry(ROOT / "examples" / "targets_registry.json")
    assert r.ok
    assert len(r.profiles) >= 2
    statuses = {p.authorization_status for p in r.profiles}
    assert "UNKNOWN" in statuses
    assert "ACTIVE" in statuses


def test_registry_rejects_bad_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    r = load_registry(p)
    assert not r.ok
    assert r.errors


def test_probe_skipped_when_not_active():
    profile = profile_from_dict(
        {
            "target_id": "t1",
            "authorization_status": "UNKNOWN",
            "in_scope_hosts": ["example-authorized.test"],
            "allowed_operations": ["CURRENT_OBSERVATION_HEAD", "PASSIVE_INDEX"],
        }
    )
    r = collect_probes(profile, ["https://example-authorized.test/.env"], budget=3)
    assert r.status == "SKIPPED_BY_POLICY"


def test_probe_skips_github_urls_even_if_listed():
    profile = profile_from_dict(
        {
            "target_id": "t1",
            "authorization_status": "ACTIVE",
            "in_scope_hosts": ["example-authorized.test"],
            "allowed_operations": ["CURRENT_OBSERVATION_HEAD", "PASSIVE_INDEX"],
        }
    )
    urls = plan_probe_urls(
        profile,
        [
            "https://github.com/org/repo/blob/main/.env",
            "https://example-authorized.test/backup.zip",
        ],
        budget=5,
    )
    assert urls == ["https://example-authorized.test/backup.zip"]


def test_probe_mocked_head():
    profile = profile_from_dict(
        {
            "target_id": "t1",
            "authorization_status": "ACTIVE",
            "in_scope_hosts": ["example-authorized.test"],
            "allowed_operations": ["CURRENT_OBSERVATION_HEAD", "PASSIVE_INDEX"],
        }
    )

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def getcode(self):
            return 200

        def geturl(self):
            return "https://example-authorized.test/backup.zip"

        @property
        def status(self):
            return 200

        headers = {"Content-Type": "application/zip"}

        def read(self, n=-1):
            return b""

    with patch("urllib.request.urlopen", return_value=FakeResp()):
        r = collect_probes(
            profile,
            ["https://example-authorized.test/backup.zip"],
            budget=2,
            prefer_head=True,
        )
    assert r.status == "COMPLETED_WITH_RESULTS"
    assert len(r.records) == 1
    assert r.records[0]["discovery_mode"] == "CURRENT_OBSERVATION"
    assert r.records[0]["metadata"]["probe_method"] == "HEAD"


def test_benchmark_perfect_on_corpus():
    report = run_classification_benchmark(ROOT / "examples" / "classification_benchmark.json")
    assert report.total >= 9
    assert report.classification_accuracy == 1.0
    assert report.review_accuracy == 1.0
    assert report.mismatches == []


def test_export_bundle_schema():
    result = {
        "run_id": "r1",
        "target_id": "t1",
        "status": "COMPLETED_WITH_RESULTS",
        "summary": {"candidates": 1},
        "provider_summaries": [],
        "research_queue": [
            {
                "url": "https://example-authorized.test/.env",
                "classification": "POTENTIALLY_SENSITIVE",
                "review_decision": "NEEDS_REVIEW",
                "rank_score": 0.5,
            }
        ],
        "live_host_requests": 0,
    }
    b = build_export_bundle(result, target_host="example-authorized.test", research_mode="demo")
    assert b["schema"] == "ei.export.v1"
    assert b["candidates"][0]["confirmed_vulnerability"] is False
