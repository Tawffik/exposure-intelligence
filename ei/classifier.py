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
    re.compile(r"cf-error-details", re.I),
    re.compile(r"cloudflare ray id", re.I),
    re.compile(r"the requested URL was rejected", re.I),
    re.compile(r"Akamai|Reference\s*#", re.I),
    re.compile(r"blocked by.*security policy", re.I),
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
    r"(?i)(backup|dump|\.env|config\.ya?ml|\.git/|id_rsa|\.pem|credentials|secret|trace\.axd|web\.config|service-account|appsettings|\.aws/|wp-config|phpinfo|swagger|openapi|\.map$)",
)
TRACE_MARKERS = [
    re.compile(r"Application Trace", re.I),
    re.compile(r"Trace Information", re.I),
    re.compile(r"Request Details", re.I),
]
DIRECTORY_LISTING_MARKERS = [
    re.compile(r"<title>\s*Index of\s+/", re.I),
    re.compile(r"<h1>\s*Index of\s+/", re.I),
    re.compile(r"\[To Parent Directory\]", re.I),
    re.compile(r"<pre>(?:\s*<a href=)", re.I),
    re.compile(r"Directory Listing For", re.I),
]
SOURCE_MAP_MARKERS = [
    re.compile(r'"version"\s*:\s*3\b'),
    re.compile(r'"mappings"\s*:'),
    re.compile(r'"sources"\s*:\s*\['),
]
SOURCE_MAP_SOURCES_CONTENT = re.compile(r'"sourcesContent"\s*:\s*\[')
OPENAPI_MARKERS = [
    re.compile(r'"openapi"\s*:\s*"3\.'),
    re.compile(r'"swagger"\s*:\s*"2\.'),
    re.compile(r'"paths"\s*:\s*\{'),
    re.compile(r'"info"\s*:\s*\{[^}]*"title"', re.I),
]
GIT_METADATA_MARKERS = [
    re.compile(r"^ref:\s*refs/", re.M),
    re.compile(r"^\[core\]\s*$", re.M),
    re.compile(r"repositoryformatversion\s*="),
    re.compile(r"^\[remote \"origin\"\]", re.M),
]
GIT_PATH_HINT = re.compile(r"(?i)/\.git(/|$)")


def _matches_any(text: str, patterns: list[re.Pattern]) -> bool:
    return any(p.search(text) for p in patterns)


def _is_source_map(body: str, url: str, content_type: str) -> bool:
    url_l = (url or "").lower()
    ct = (content_type or "").lower()
    if url_l.endswith(".map") or "sourcemap" in ct or "source-map" in ct:
        # Path/type hint alone is weak; require at least one structural marker when body present
        if body.strip() and _matches_any(body, SOURCE_MAP_MARKERS):
            return True
        if not body.strip() and url_l.endswith(".map"):
            return True
    return bool(body.strip() and _matches_any(body, SOURCE_MAP_MARKERS) and '"mappings"' in body)


def _is_openapi(body: str, url: str) -> bool:
    url_l = (url or "").lower()
    path_hint = any(x in url_l for x in ("openapi", "swagger", "api-docs", "api/docs"))
    if not body.strip():
        return False
    has_spec = bool(
        re.search(r'"openapi"\s*:\s*"3\.', body) or re.search(r'"swagger"\s*:\s*"2\.', body)
    )
    has_paths = bool(re.search(r'"paths"\s*:\s*\{', body))
    if has_spec and has_paths:
        return True
    if path_hint and (has_spec or has_paths):
        return True
    return False


def _is_git_metadata(body: str, url: str) -> bool:
    if not body.strip():
        return False
    url_l = (url or "").lower()
    if GIT_PATH_HINT.search(url_l) and _matches_any(body, GIT_METADATA_MARKERS):
        return True
    # Body-only: strong git markers without requiring path
    if re.search(r"^ref:\s*refs/heads/", body, re.M) and len(body.strip()) < 200:
        return True
    if re.search(r"^\[core\]", body, re.M) and "repositoryformatversion" in body:
        return True
    return False


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
        # Status alone does not prove *why* access was denied.
        # Prefer body evidence: WAF/block pages vs login forms vs opaque deny.
        if body.strip() and _matches_any(body, WAF_MARKERS):
            return (
                Classification.GENERIC_ERROR.value,
                ["http_forbidden_status", "waf_or_block_page"],
                0.85,
                f"HTTP {status} with WAF/block-page fingerprints — access policy/edge block, "
                "not proven application authentication challenge.",
                SensitivityClass.NONE.value,
                freshness,
            )
        if body.strip() and _matches_any(body, LOGIN_MARKERS):
            return (
                Classification.AUTH_REQUIRED.value,
                ["http_auth_status", "login_form_markers"],
                0.88,
                f"HTTP {status} with login/sign-in form markers — authentication challenge likely.",
                SensitivityClass.NONE.value,
                freshness,
            )
        if not body.strip():
            return (
                Classification.AUTH_REQUIRED.value,
                ["http_auth_status", "empty_body"],
                0.7,
                f"HTTP {status} with empty body — often auth or ACL deny; reason not confirmed from content.",
                SensitivityClass.NONE.value,
                freshness,
            )
        return (
            Classification.AUTH_REQUIRED.value,
            ["http_auth_status", "opaque_deny_body"],
            0.75,
            f"HTTP {status} with non-WAF body — treated as auth/ACL deny without stronger evidence.",
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
        if (discovery_mode or "").upper() == "HISTORICAL":
            return (
                Classification.HISTORICAL_ONLY.value,
                ["empty_body", "historical_index_without_content"],
                0.55,
                "Historical index row without body content; not current exposure.",
                SensitivityClass.NONE.value,
                Freshness.HISTORICAL.value,
            )
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

    # Directory listing — must run before generic public-HTML classification.
    # Previously these were labeled INTENTIONALLY_PUBLIC and ranked as noise.
    if status in (None, 200) and body.strip() and _matches_any(body, DIRECTORY_LISTING_MARKERS):
        sens = SensitivityClass.MEDIUM.value
        listing_reasons = ["directory_listing_fingerprint"]
        if SENSITIVE_PATH_HINTS.search(body) or SENSITIVE_PATH_HINTS.search(url_l):
            listing_reasons.append("listing_contains_sensitive_name_hint")
            sens = SensitivityClass.HIGH.value
        return (
            Classification.POTENTIALLY_SENSITIVE.value,
            listing_reasons,
            0.78,
            "Directory listing response; may reveal filesystem layout. Impact not confirmed.",
            sens,
            freshness,
        )

    # Source maps (build artifact disclosure)
    if status in (None, 200) and _is_source_map(body, url_l, ct):
        has_sources = bool(SOURCE_MAP_SOURCES_CONTENT.search(body or ""))
        if has_sources:
            return (
                Classification.POTENTIALLY_SENSITIVE.value,
                ["source_map_with_sources_content"],
                0.82,
                "Source map includes sourcesContent; original source may be embedded. Impact unconfirmed.",
                SensitivityClass.HIGH.value,
                freshness,
            )
        return (
            Classification.IMPACT_UNPROVEN.value,
            ["source_map_structure"],
            0.65,
            "Source map structure observed; paths/build layout may leak. Sensitive content not confirmed.",
            SensitivityClass.MEDIUM.value,
            freshness,
        )

    # OpenAPI / Swagger public schema
    if status in (None, 200) and _is_openapi(body, url_l):
        return (
            Classification.IMPACT_UNPROVEN.value,
            ["openapi_or_swagger_schema"],
            0.6,
            "Public API schema document; may reveal internal routes/models. Not proof of authorization failure.",
            SensitivityClass.MEDIUM.value,
            freshness,
        )

    # Exposed git metadata (.git/HEAD, config, etc.)
    if status in (None, 200) and _is_git_metadata(body, url_l):
        return (
            Classification.POTENTIALLY_SENSITIVE.value,
            ["git_metadata_exposure"],
            0.8,
            "Git metadata content observed; repository structure may be exposed. Full source impact unconfirmed.",
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

    if SENSITIVE_PATH_HINTS.search(url_l) and status in (None, 200) and body.strip():
        # Keyword path match alone is weak without content support
        is_example_path = bool(
            re.search(
                r"(?i)("
                r"\.env\.example|"
                r"\.env\.[\w.-]*\.example|"
                r"\.env\.sample|\.env\.template|\.env\.dist|"
                r"\.env-sample|\.env\.mock|\.env copy|"
                r"example\.env|/examples?/|workshop|demo-store|sample-app)",
                url_l,
            )
        )
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
        if is_example_path:
            reasons.append("example_or_template_path")
        # Check for secret patterns (presence only; values redacted elsewhere)
        from ei.models import SECRET_PATTERNS

        for pat, name in SECRET_PATTERNS:
            if pat.search(body):
                reasons.append(f"secret_pattern:{name}")
                if is_example_path:
                    return (
                        Classification.IMPACT_UNPROVEN.value,
                        reasons,
                        0.45,
                        "Example/template path with secret-like pattern in snippet; "
                        "likely documentation/sample — impact unproven.",
                        SensitivityClass.LOW.value,
                        freshness,
                    )
                return (
                    Classification.POTENTIALLY_SENSITIVE.value,
                    reasons,
                    0.7,
                    "Sensitive path and secret-like pattern present; values not stored; impact unproven.",
                    SensitivityClass.HIGH.value,
                    freshness,
                )
        if is_example_path:
            return (
                Classification.IMPACT_UNPROVEN.value,
                reasons,
                0.35,
                "Example/template path; filename alone is not a confirmed exposure.",
                SensitivityClass.LOW.value,
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
    body = record.get("body", "") or record.get("body_preview_redacted", "") or ""
    preview, redacted = redact_text(body)
    sha = content_hash(body) if body else ""
    is_dup = bool(record.get("is_duplicate", False))
    classification, reasons, conf, rationale, sens, fresh = classify_observation(
        url=record.get("url", ""),
        status=record.get("status") if record.get("status") is not None else record.get("http_status"),
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
        http_status=record.get("status") if record.get("status") is not None else record.get("http_status"),
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