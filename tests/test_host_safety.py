"""RFC1918 / IPv6 / localhost host-safety policy and next-step gating."""

from __future__ import annotations

import pytest

from ei.host_safety import is_private_or_local_host, local_or_private_next_step_message
from ei.hypothesis import _safe_next_step, build_hypothesis


PRIVATE_URLS = [
    "http://10.0.0.5/.env",
    "http://172.16.0.1/.env",
    "http://192.168.1.10/.env",
    "http://127.0.0.1:3000/.env",
    "http://[::1]/.env",
    "http://[fc00::1]/.env",
    "http://[fd12:3456:789a::1]/.env",
    "http://[fe80::1]/.env",
    "http://0.0.0.0/.env",
    "http://localhost/.env",
    "http://app.localhost/.env",
    "http://[::ffff:127.0.0.1]/.env",  # IPv4-mapped loopback
    "http://[::ffff:10.1.2.3]/.env",  # IPv4-mapped RFC1918
]


PUBLIC_URLS = [
    "https://example.com/.env",
    "http://8.8.8.8/.env",
    "http://203.0.113.10/.env",  # TEST-NET-3 documentation — not RFC1918
    "https://cdn.example.com/assets/10.0.0.1/bundle.js",  # path only
    "http://[2001:db8::1]/.env",  # documentation IPv6 — not ULA/link-local
]


@pytest.mark.parametrize("url", PRIVATE_URLS)
def test_private_or_local_detected(url: str) -> None:
    assert is_private_or_local_host(url) is True


@pytest.mark.parametrize("url", PUBLIC_URLS)
def test_public_not_private(url: str) -> None:
    assert is_private_or_local_host(url) is False


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "not a url", "http://", "://broken", None],  # type: ignore[list-item]
)
def test_malformed_not_private(raw: str | None) -> None:
    assert is_private_or_local_host(raw) is False  # type: ignore[arg-type]


@pytest.mark.parametrize("url", PRIVATE_URLS)
def test_safe_next_step_demotes_private_before_path_template(url: str) -> None:
    step = _safe_next_step(
        {
            "url": url,
            "review_decision": "NEEDS_REVIEW",
            "target_relationship": "DIRECT_HOST",
            "classification_reason_codes": ["sensitive_path", "secret_pattern:aws"],
        }
    )
    assert "Open the public blob" not in step
    assert "local-only" in step.lower() or "private-network" in step.lower()


def test_public_env_still_gets_path_guidance() -> None:
    step = _safe_next_step(
        {
            "url": "https://example.com/.env",
            "review_decision": "NEEDS_REVIEW",
            "target_relationship": "DIRECT_HOST",
            "classification_reason_codes": ["sensitive_path"],
        }
    )
    assert "Open the public blob" in step


def test_low_priority_precedes_private_host() -> None:
    step = _safe_next_step(
        {
            "url": "http://10.0.0.5/.env",
            "review_decision": "LOW_PRIORITY",
            "target_relationship": "DIRECT_HOST",
            "classification_reason_codes": ["sensitive_path"],
        }
    )
    assert "Skip unless program policy" in step


def test_private_precedes_attribution_and_path() -> None:
    """Private host gate runs before path templates; attribution still recorded in hyp."""
    h = build_hypothesis(
        {
            "url": "http://192.168.1.10/.env",
            "classification": "POTENTIALLY_SENSITIVE",
            "review_decision": "NEEDS_REVIEW",
            "target_relationship": "UNATTRIBUTED",
            "classification_reason_codes": ["sensitive_path"],
        }
    )
    assert h["confirmed_vulnerability"] is False
    assert "local-only" in h["safe_next_step"].lower() or "private" in h["safe_next_step"].lower()


def test_message_helper_stable() -> None:
    msg = local_or_private_next_step_message()
    assert "local-only" in msg.lower() or "private" in msg.lower()
    assert "production" in msg.lower()


def test_evidence_review_body_ip_alone_does_not_demote_public_host() -> None:
    """Docs mentioning 10.x must not be auto-demoted without credential-like evidence."""
    from ei.evidence_review import review_candidate

    rev = review_candidate(
        url="https://example.com/api/status",
        classification="IMPACT_UNPROVEN",
        reason_codes=["opaque_json"],
        body_preview_redacted="upstream 10.0.0.5 healthy",
    )
    assert rev["review_decision"] != "LOW_PRIORITY" or "private" not in (
        rev.get("review_rationale") or ""
    ).lower()
    # Prefer: not LOW_PRIORITY solely due to body IP
    assert rev["review_decision"] == "NEEDS_REVIEW"


def test_evidence_review_private_host_demotes_without_secrets() -> None:
    from ei.evidence_review import review_candidate

    rev = review_candidate(
        url="http://192.168.1.10/status",
        classification="IMPACT_UNPROVEN",
        reason_codes=[],
        body_preview_redacted="ok",
    )
    assert rev["review_decision"] == "LOW_PRIORITY"


def test_boundary_172_15_and_172_32_not_rfc1918() -> None:
    assert is_private_or_local_host("http://172.15.255.255/") is False
    assert is_private_or_local_host("http://172.32.0.1/") is False
    assert is_private_or_local_host("http://172.16.0.0/") is True
    assert is_private_or_local_host("http://172.31.255.255/") is True
