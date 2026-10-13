"""Adversarial hostname attribution regressions (P0)."""

from __future__ import annotations

from ei.host_relationship import (
    classify_url_host_relationship,
    host_is_or_subdomain_of,
    hostname_from_url,
    hosts_match_exact,
    normalize_hostname,
    to_provider_relationship,
)
from ei.providers.cdx import normalize_cdx_row
from ei.providers.urlscan import normalize_urlscan_item


def test_exact_and_subdomain_boundaries():
    assert hosts_match_exact("Example.COM.", "example.com")
    assert host_is_or_subdomain_of("api.example.com", "example.com")
    assert not host_is_or_subdomain_of("notexample.com", "example.com")
    assert not host_is_or_subdomain_of("example.com.evil.com", "example.com")
    assert not host_is_or_subdomain_of("example.com.attacker", "example.com")


def test_path_only_is_not_related_candidate():
    d = classify_url_host_relationship(
        target_host="example.com",
        url="https://github.com/user/repo/blob/main/example.com/.env",
    )
    assert d["relationship"] == "INDEX_ONLY"
    assert d["textual_match"] is True
    assert to_provider_relationship(d) == "INDEX_ONLY"


def test_query_fragment_only():
    d = classify_url_host_relationship(
        target_host="example.com",
        url="https://evil.test/page?redirect=example.com#example.com",
    )
    assert d["relationship"] == "INDEX_ONLY"
    assert to_provider_relationship(d) == "INDEX_ONLY"


def test_port_and_uppercase():
    d = classify_url_host_relationship(
        target_host="Example.COM",
        url="https://EXAMPLE.COM:8443/admin",
    )
    assert d["relationship"] == "DIRECT_HOST"
    assert normalize_hostname(d["hostname"]) == "example.com"


def test_deceptive_suffix_notexample():
    d = classify_url_host_relationship(
        target_host="example.com",
        url="https://notexample.com/.env",
    )
    assert d["relationship"] == "INDEX_ONLY"
    assert to_provider_relationship(d) != "RELATED_CANDIDATE"


def test_malformed_url():
    d = classify_url_host_relationship(target_host="example.com", url="not a url")
    assert d["relationship"] in {"INDEX_ONLY", "UNATTRIBUTED"}


def test_urlscan_no_longer_uses_path_substring():
    item = {
        "page": {
            "url": "https://github.com/x/y/blob/main/sites/example.com/config",
            "domain": "github.com",
            "title": "example.com config",
            "status": "200",
        },
        "task": {"uuid": "abc", "time": "2024-01-01T00:00:00Z"},
        "_id": "abc",
    }
    rec = normalize_urlscan_item(item, target_host="example.com")
    assert rec["metadata"]["target_relationship"] == "INDEX_ONLY"
    assert rec["metadata"]["textual_match"] is True


def test_urlscan_exact_domain():
    item = {
        "page": {
            "url": "https://example.com/.env",
            "domain": "example.com",
            "title": "env",
            "status": "200",
        },
        "task": {"uuid": "x", "time": "2024-01-01T00:00:00Z"},
        "_id": "x",
    }
    rec = normalize_urlscan_item(item, target_host="example.com")
    assert rec["metadata"]["target_relationship"] == "RELATED_CANDIDATE"
    assert rec["metadata"]["host_relationship_detail"] == "DIRECT_HOST"


def test_cdx_path_substring_not_related():
    row = {
        "original": "https://cdn.other.com/cache/example.com/backup.zip",
        "timestamp": "20200101000000",
        "statuscode": "200",
        "mimetype": "application/zip",
        "digest": "ABC",
        "length": "10",
    }
    rec = normalize_cdx_row(row, target_host="example.com")
    assert rec["metadata"]["target_relationship"] == "INDEX_ONLY"


def test_cdx_exact_host_related():
    row = {
        "original": "https://example.com/backup.zip",
        "timestamp": "20200101000000",
        "statuscode": "200",
        "mimetype": "application/zip",
        "digest": "ABC",
        "length": "10",
    }
    rec = normalize_cdx_row(row, target_host="example.com")
    assert rec["metadata"]["target_relationship"] == "RELATED_CANDIDATE"
    assert rec["metadata"]["host_relationship_detail"] == "DIRECT_HOST"


def test_hostname_from_url_with_port():
    assert hostname_from_url("https://API.Example.com:443/a") == "api.example.com"
