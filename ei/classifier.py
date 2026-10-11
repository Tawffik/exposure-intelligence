"""Deterministic, explainable classification of observations."""

from __future__ import annotations

import re
from typing import Optional

from ei.models import (
    Classification,
    DiscoveryMode,
    Freshness,
    Observation,
    SensitivityClass,
    content_hash,
    redact_text,
)

# Content-shape fingerprints (case-insensitive substring / simple regex)
SPA_MARKERS = [
    re.compile(r"<div\s+id=[\"']root[\"']", re.I),
    re.compile(r"<div\s+id=[\"']app[\"']", re.I),
    re.compile(r"You need to enable JavaScript", re.I),
    re.compile(r"__NEXT_DATA__", re.I),
]
WAF_MARKERS = [
    re.compile(r"Attention Required! \| Cloudflare", re.I),
    re.compile(r"Access Denied", re.I),
    re.compile(r"Request blocked", re.I),
    re.compile(r"aws_waf", re.I),
]
LOGIN_MARKERS = [
    re.compile(r"<form[^>]+(login|signin|auth)", re.I),
    re.compile(r"name=[\"']password[\"']", re.I),
    re.compile(r"Sign in to continue", re.I),
]
GENERIC_ERROR_MARKERS = [
    re.compile(r"404 Not Found", re.I),
    re.compile(r"Page not found", re.I),
    re.compile(r"Internal Server Error", re.I),
    re.compile(r"nginx/\d", re.I),
]
ARCHIVE_SIGNATURES = [
    re.compile(r"^PK\x03\x04"),  # zip
    re.compile(r"^Rar!"),
    re.compile(r"ustar"),  # tar
]
SENSITIVE_PATH_HINTS = re.compile(
    r"(?i)(backup|dump|\.env|config\.ya?ml|\.git/|id_rsa|\.pem|credentials|secret|trace\.axd|web\.config)",
)
TRACE_MARKERS = [
    re.compile(r"Application Trace", re.I),
    re.compile(r"Trace Information", re.I),
    re.compile(r"Request Details", re.I),
]


def _matches_any(text: str, patterns: list[re.Pattern]) -> bool:
    return any(p.search(text) for p in patterns)


def classify_observation(
    *,
    url: str = "",
    status: Optional[int] = None,
    content_type: str = "",
    body: str = "",
    discovery_mode: str = DiscoveryMode.FIXTURE.value,
    is_duplicate: bool = False,
    source_fidelity: str = "ORIGINAL",
) -> tuple[str, list[str], float, str, str, str]:
    """
    Return (classification, reason_codes, confidence, rationale, sensitivity, freshness).
    """
    reasons: list[str] = []
    body = body or ""
    ct = (content_type or "").lower()
    url_l = (url or "").lower()

    if is_duplicate:
        return (
            Classification.DUPLICATE.value,
            ["duplicate_observation"],
            0.95,
            "Observation matches an existing candidate fingerprint.",
            SensitivityClass.NONE.value,
            Freshness.UNKNOWN.value,
        )

    if discovery_mode == DiscoveryMode.HISTORICAL.value:
        freshness = Freshness.HISTORICAL.value
    elif discovery_mode == DiscoveryMode.CURRENT_OBSERVATION.value:
        freshness = Freshness.CURRENT.value
    else:
        freshness = Freshness.UNKNOWN.value

    if source_fidelity in ("SUMMARY", "AI_INFERENCE", "MIRROR"):
        if source_fidelity == "AI_INFERENCE":
            return (
                Classification.COPIED_RESEARCH.value,
                ["ai_inference_not_observation"],
                0.4,
                "AI-generated inference is not treated as direct observation.",
                SensitivityClass.UNKNOWN.value,
                freshness,
            )
        if source_fidelity == "MIRROR":
            reasons.append("mirror_source")

    if status is not None and status in (401, 403):
        return (
            Classification.AUTH_REQUIRED.value,
            ["http_auth_status"],
            0.85,
            f"HTTP {status} indicates authentication or authorization is required.",
            SensitivityClass.NONE.value,
            freshness,
        )

    if status is not None and status in (404, 410):
        if discovery_mode == DiscoveryMode.HISTORICAL.value:
            return (
                Classification.HISTORICAL_ONLY.value,
                ["historical_not_found_currently"],
                0.7,
                "Historical observation; current request returned not-found.",
                SensitivityClass.UNKNOWN.value,
                Freshness.HISTORICAL.value,
            )
        return (
            Classification.UNREACHABLE.value,
            ["http_not_found"],
            0.8,
            f"HTTP {status} — resource not currently reachable.",
            SensitivityClass.NONE.value,
            freshness,
        )

    if status is not None and status >= 500:
        return (
            Classification.GENERIC_ERROR.value,
            ["http_server_error"],
            0.7,
            f"HTTP {status} server error page.",
            SensitivityClass.NONE.value,
            freshness,
        )

    if not body.strip() and (status is None or status == 200):
        return (
            Classification.EMPTY_RESPONSE.value,
            ["empty_body"],
            0.75,
            "Empty response body.",
            SensitivityClass.NONE.value,
            freshness,
        )

    if _matches_any(body, WAF_MARKERS):
        return (
            Classification.GENERIC_ERROR.value,
            ["waf_or_block_page"],
            0.9,
            "Response matches WAF/block page fingerprints.",
            SensitivityClass.NONE.value,
            freshness,
        )

    if _matches_any(body, SPA_MARKERS) and "text/html" in ct:
        return (
            Classification.SPA_SHELL.value,
            ["spa_shell_fingerprint"],
            0.88,
            "HTML application shell (SPA fallback), not discrete content exposure.",
            SensitivityClass.NONE.value,
            freshness,
        )

    if _matches_any(body, LOGIN_MARKERS):
        return (
            Classification.AUTH_REQUIRED.value,
            ["login_form_fingerprint"],
            0.85,
            "Login/sign-in form detected.",
            SensitivityClass.NONE.value,
            freshness,
        )

    if _matches_any(body, TRACE_MARKERS):
        return (
            Classification.POTENTIALLY_SENSITIVE.value,
            ["diagnostic_trace_page"],
            0.8,
            "Diagnostic/trace page structure detected; impact unconfirmed.",
            SensitivityClass.HIGH.value,
            freshness,
        )

    if _matches_any(body, GENERIC_ERROR_MARKERS) and status in (None, 200, 404):
        return (
            Classification.GENERIC_ERROR.value,
            ["generic_error_page"],
            0.8,
            "Generic error page content.",
            SensitivityClass.NONE.value,
            freshness,
        )

    # Archive / binary-ish signatures in body or content-type
    if any(
        x in ct
        for x in (
            "application/zip",
            "application/x-tar",
            "application/gzip",
            "application/octet-stream",
            "application/x-rar",
        )
    ) or _matches_any(body[:16], ARCHIVE_SIGNATURES):
        sens = SensitivityClass.HIGH.value
        reasons.append("archive_or_binary_content_type")
        if SENSITIVE_PATH_HINTS.search(url_l):
            reasons.append("sensitive_path_hint")
            sens = SensitivityClass.CRITICAL.value
        return (
            Classification.POTENTIALLY_SENSITIVE.value,
            reasons or ["archive_response"],
            0.75,
            "Archive or binary response; sensitivity inferred from type/path, impact unproven.",
            sens,
            freshness,
        )

    if SENSITIVE_PATH_HINTS.search(url_l) and status == 200 and body.strip():
        # Keyword path match alone is weak without content support
        if len(body) < 40 and "text/html" in ct:
            return (
                Classification.KEYWORD_FALSE_POSITIVE.value,
                ["path_keyword_without_supporting_content"],
                0.55,
                "Sensitive-looking path but body does not support exposure claim.",
                SensitivityClass.LOW.value,
                freshness,
            )
        reasons.append("sensitive_path_with_content")
        # Check for secret patterns (presence only; values redacted elsewhere)
        from ei.models import SECRET_PATTERNS

        for pat, name in SECRET_PATTERNS:
            if pat.search(body):
                reasons.append(f"secret_pattern:{name}")
                return (
                    Classification.POTENTIALLY_SENSITIVE.value,
                    reasons,
                    0.7,
                    "Sensitive path and secret-like pattern present; values not stored; impact unproven.",
                    SensitivityClass.HIGH.value,
                    freshness,
                )
        return (
            Classification.IMPACT_UNPROVEN.value,
            reasons,
            0.5,
            "Sensitive-looking path with content; impact not demonstrated.",
            SensitivityClass.MEDIUM.value,
            freshness,
        )

    if status == 200 and body.strip() and "text/html" not in ct and "application/json" in ct:
        return (
            Classification.IMPACT_UNPROVEN.value,
            ["json_response_unclassified"],
            0.4,
            "JSON response without further authorization context.",
            SensitivityClass.UNKNOWN.value,
            freshness,
        )

    if status == 200 and "text/html" in ct:
        return (
            Classification.INTENTIONALLY_PUBLIC.value,
            ["public_html_page"],
            0.5,
            "Ordinary public HTML page without sensitive markers.",
            SensitivityClass.NONE.value,
            freshness,
        )

    return (
        Classification.UNKNOWN.value,
        ["insufficient_signals"],
        0.3,
        "Insufficient signals for a specific classification.",
        SensitivityClass.UNKNOWN.value,
        freshness,
    )


def build_observation_from_fixture(record: dict, run_id: str = "", target_id: str = "") -> Observation:
    """Build a fully classified Observation from a fixture/raw record."""
    body = record.get("body", "") or ""
    preview, redacted = redact_text(body)
    sha = content_hash(body) if body else ""
    is_dup = bool(record.get("is_duplicate", False))
    classification, reasons, conf, rationale, sens, fresh = classify_observation(
        url=record.get("url", ""),
        status=record.get("status"),
        content_type=record.get("content_type", ""),
        body=body,
        discovery_mode=record.get("discovery_mode", DiscoveryMode.FIXTURE.value),
        is_duplicate=is_dup,
        source_fidelity=record.get("source_fidelity", "ORIGINAL"),
    )
    return Observation(
        run_id=run_id,
        target_id=target_id or record.get("target_id", "fixture-target"),
        provider=record.get("provider", "fixture"),
        check_family=record.get("check_family", "fixture"),
        source_url=record.get("source_url", ""),
        source_record_id=record.get("source_record_id", ""),
        discovered_url=record.get("url", ""),
        discovery_mode=record.get("discovery_mode", DiscoveryMode.FIXTURE.value),
        source_fidelity=record.get("source_fidelity", "ORIGINAL"),
        http_status=record.get("status"),
        content_type=record.get("content_type", ""),
        body_byte_count=len(body.encode("utf-8", errors="replace")),
        body_sha256=sha,
        preview_redacted=preview,
        body_truncated=len(body) > 512,
        redaction_applied=redacted,
        classification=classification,
        classification_reason_codes=reasons,
        confidence=conf,
        confidence_rationale=rationale,
        sensitivity=sens,
        freshness=fresh,
        scope_decision=record.get("scope_decision", "IN_SCOPE"),
        metadata={k: v for k, v in record.items() if k not in ("body",)},
    )