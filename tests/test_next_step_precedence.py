"""Decision-precedence matrix for _safe_next_step (safety before interest)."""

from __future__ import annotations

import pytest

from ei.hypothesis import _safe_next_step


def _step(**kwargs) -> str:
    base = {
        "url": "https://example.com/.env",
        "review_decision": "NEEDS_REVIEW",
        "target_relationship": "DIRECT_HOST",
        "classification_reason_codes": ["sensitive_path"],
    }
    base.update(kwargs)
    return _safe_next_step(base)


def test_precedence_low_priority_wins() -> None:
    s = _step(review_decision="LOW_PRIORITY", url="http://10.0.0.5/.env")
    assert s.startswith("Skip unless")


def test_precedence_private_before_env_path() -> None:
    s = _step(url="http://10.0.0.5/.env", target_relationship="DIRECT_HOST")
    assert "Open the public blob" not in s
    assert "local" in s.lower() or "private" in s.lower()


def test_precedence_private_before_git_path() -> None:
    s = _step(
        url="http://192.168.0.2/.git/HEAD",
        classification_reason_codes=["git_metadata_exposure"],
    )
    assert "clone" not in s.lower()
    assert "local" in s.lower() or "private" in s.lower()


def test_precedence_private_before_source_map() -> None:
    s = _step(
        url="http://[fc00::2]/static/app.js.map",
        classification_reason_codes=["source_map_with_sources_content"],
    )
    assert "Open the map" not in s
    assert "local" in s.lower() or "private" in s.lower()


def test_precedence_unattributed_before_env_on_public_host() -> None:
    s = _step(
        url="https://evil.test/.env",
        target_relationship="UNATTRIBUTED",
    )
    assert "Open the public blob" not in s
    assert "does not match" in s.lower() or "ownership" in s.lower()


def test_precedence_out_of_scope_before_env() -> None:
    s = _step(
        url="https://other.example/.env",
        target_relationship="OUT_OF_SCOPE",
    )
    assert "Open the public blob" not in s


def test_precedence_index_only_before_env() -> None:
    s = _step(
        url="https://github.com/x/y/blob/main/.env",
        target_relationship="INDEX_ONLY",
    )
    assert "index" in s.lower() or "ownership" in s.lower()
    assert "Open the public blob" not in s


def test_missing_fields_safe_fallback() -> None:
    s = _safe_next_step({})
    assert "Human review" in s or "probing" in s.lower()
    s2 = _safe_next_step({"url": None, "review_decision": None})
    assert isinstance(s2, str) and len(s2) > 10


def test_token_reason_on_public_direct() -> None:
    s = _step(
        url="https://example.com/config",
        classification_reason_codes=["secret_pattern:aws"],
        target_relationship="DIRECT_HOST",
    )
    assert "never call customer" in s.lower() or "vendor docs" in s.lower()


def test_hypothesis_never_confirms() -> None:
    from ei.hypothesis import build_hypothesis

    for rel in ("DIRECT_HOST", "UNATTRIBUTED", "INDEX_ONLY", "OUT_OF_SCOPE"):
        h = build_hypothesis(
            {
                "url": "https://example.com/.env",
                "classification": "POTENTIALLY_SENSITIVE",
                "review_decision": "NEEDS_REVIEW",
                "target_relationship": rel,
                "classification_reason_codes": ["sensitive_path"],
            }
        )
        assert h["confirmed_vulnerability"] is False
