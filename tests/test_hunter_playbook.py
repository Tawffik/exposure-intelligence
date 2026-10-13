
"""Hunter playbook adaptations: noise filters, localhost demotion, hypothesis steps."""

from ei.providers.github_code_search import (
    append_hunter_noise_filters,
    build_target_scoped_query,
)
from ei.evidence_review import review_candidate
from ei.hypothesis import build_hypothesis


def test_noise_filters_append_localhost():
    q = append_hunter_noise_filters("example.com filename:.env")
    assert "NOT localhost" in q
    assert "NOT 127.0.0.1" in q


def test_scoped_query_includes_noise_filters():
    q = build_target_scoped_query("shopify.com", "filename:.env")
    assert "shopify.com" in q
    assert "NOT localhost" in q


def test_localhost_snippet_demoted():
    r = review_candidate(
        url="https://github.com/x/y/blob/main/.env",
        classification="POTENTIALLY_SENSITIVE",
        reason_codes=["secret_pattern:generic"],
        body_preview_redacted="DB_HOST=127.0.0.1\nDB_PASSWORD=supersecret",
        target_relationship="INDEX_ONLY",
    )
    assert r["review_decision"] == "LOW_PRIORITY"


def test_hypothesis_never_confirms():
    h = build_hypothesis(
        {
            "url": "https://github.com/x/y/.env",
            "classification": "POTENTIALLY_SENSITIVE",
            "review_decision": "NEEDS_REVIEW",
            "target_relationship": "INDEX_ONLY",
            "classification_reason_codes": ["secret_pattern:generic"],
        }
    )
    assert h["confirmed_vulnerability"] is False
    assert "safe_next_step" in h
    assert len(h["safe_next_step"]) > 10
