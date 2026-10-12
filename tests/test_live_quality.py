
"""Live-quality regressions: CDX junk filter, queue noise ordering."""

from __future__ import annotations

from ei.providers.cdx import _is_junk_url, normalize_cdx_payload
from ei.evidence_review import review_candidate


def test_junk_cdx_urls_detected():
    assert _is_junk_url("https://shopify.com/%22") is True
    assert _is_junk_url("http://gitlab.com:80/") is True
    assert _is_junk_url("https://example.com/%0Afoo") is True
    assert _is_junk_url("https://example-authorized.test/backup.zip") is False


def test_normalize_filters_junk():
    payload = {
        "results": [
            {"timestamp": "20200101000000", "original": "http://example.com:80/", "statuscode": "200", "mimetype": "text/html", "digest": "A", "length": "1"},
            {"timestamp": "20200101000000", "original": "https://example.com/backup.zip", "statuscode": "200", "mimetype": "application/zip", "digest": "B", "length": "9"},
        ]
    }
    recs = normalize_cdx_payload(payload, target_host="example.com", limit=10)
    assert len(recs) == 1
    assert "backup.zip" in recs[0]["url"]


def test_historical_only_is_low_priority_review():
    r = review_candidate(
        url="https://example.com/",
        classification="HISTORICAL_ONLY",
        reason_codes=["empty_body", "historical_index_without_content"],
        body_preview_redacted="",
        discovery_mode="HISTORICAL",
    )
    assert r["review_decision"] == "LOW_PRIORITY"
