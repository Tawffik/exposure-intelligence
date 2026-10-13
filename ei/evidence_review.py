"""
Safe second-pass evidence review for exposure candidates.

Goals (charter + operator feedback):
- Explain *why* a candidate was elevated (path vs content vs index snippet).
- Extract configuration *key names* only — never persist secret values.
- Classify value *shapes* without storing the values themselves.
- Emit a conservative review decision that is not a confirmed vulnerability.

Review decisions:
  LOW_PRIORITY                 — example/placeholder/noise; no urgent human action
  NEEDS_REVIEW                 — mixed signals; human should inspect scope + context
  POTENTIAL_EXPOSURE_UNCONFIRMED — content-supported sensitive signals; still unconfirmed
"""

from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlparse

# Keys only — names that often appear in env/config files
CONFIG_KEY_RE = re.compile(
    r"(?im)^(?:export\s+)?([A-Z][A-Z0-9_]{1,64})\s*=\s*(.*)$"
)
# Generic assignment in ini/yaml-ish lines (key only)
GENERIC_KEY_RE = re.compile(
    r"(?im)^\s*([A-Za-z_][A-Za-z0-9_.-]{0,64})\s*[:=]\s*(\S.*)?$"
)

PLACEHOLDER_VALUE_RE = re.compile(
    r"(?i)^(your[_-].*|change[_-]?me.*|todo|fixme|xxx+|placeholder.*|example.*|"
    r"<[^>]+>|\$\{[^}]+\}|%\{[^}]+\}|none|null|nil|empty)$"
)
GENERIC_VALUE_RE = re.compile(
    r"(?i)^(true|false|yes|no|on|off|debug|info|warn|error|development|"
    r"production|test|localhost|127\.0\.0\.1|0\.0\.0\.0|http://localhost|"
    r"https?://example\.com.*|)$"
)
# Shape-only: long entropy-ish tokens — we never store the match group
SECRET_LIKE_SHAPE_RE = re.compile(
    r"(?i)^(?:sk_live_|sk_test_|rk_live_|ghp_|gho_|xox[baprs]-|AKIA[0-9A-Z]{16}|"
    r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}|-----BEGIN)"
)
LONG_TOKEN_RE = re.compile(r"^[A-Za-z0-9/+=_\-.]{16,}$")

EXAMPLE_PATH_RE = re.compile(
    r"(?i)(\.env\.example|\.env\.sample|\.env\.template|\.env\.dist|"
    r"example\.env|config\.example|credentials\.example|/examples?/|"
    r"workshop|demo-store|hydrogen-demo|tutorial|getting-started|"
    r"sample-app|starter-template)"
)

SENSITIVE_NAME_RE = re.compile(
    r"(?i)(\.env($|\.)|credentials|secret|id_rsa|\.pem|backup|dump|wp-config)"
)


def _basename(url: str) -> str:
    path = urlparse(url).path if "://" in (url or "") else (url or "")
    return path.rstrip("/").split("/")[-1] if path else ""


def classify_value_shape(raw: str) -> str:
    """
    Classify a value by shape only. Caller must not log/store `raw` after this.
    Returns: empty | placeholder | generic | secret_like | undetermined
    """
    v = (raw or "").strip().strip("'\"")
    if not v:
        return "empty"
    if PLACEHOLDER_VALUE_RE.match(v) or v in {"", '""', "''"}:
        return "placeholder"
    if GENERIC_VALUE_RE.match(v):
        return "generic"
    if SECRET_LIKE_SHAPE_RE.search(v) or (
        LONG_TOKEN_RE.match(v) and not v.startswith("http")
    ):
        return "secret_like"
    return "undetermined"


def extract_config_keys(text: str, *, max_keys: int = 40) -> list[dict[str, str]]:
    """
    Extract configuration key names and value *shapes* only.
    Never returns the raw value.
    """
    if not text:
        return []
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for rx in (CONFIG_KEY_RE, GENERIC_KEY_RE):
        for m in rx.finditer(text):
            key = m.group(1)
            if key.lower() in seen:
                continue
            # Skip HTML/noise keys
            if key.lower() in {"div", "span", "class", "style", "http", "https"}:
                continue
            seen.add(key.lower())
            val = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
            shape = classify_value_shape(val or "")
            found.append({"key": key, "value_shape": shape})
            if len(found) >= max_keys:
                return found
    return found


def evidence_basis(
    *,
    url: str,
    classification: str,
    reason_codes: list[str],
    body_preview: str = "",
    discovery_mode: str = "",
) -> dict[str, Any]:
    """Explain whether elevation was path-driven, content-driven, or index-only."""
    reasons = list(reason_codes or [])
    content_markers = {
        "secret_pattern",
        "diagnostic_trace_page",
        "directory_listing_fingerprint",
        "source_map_with_sources_content",
        "git_metadata_exposure",
        "archive_or_binary_content_type",
    }
    path_markers = {
        "sensitive_path_with_content",
        "sensitive_path_hint",
        "path_keyword_without_supporting_content",
        "listing_contains_sensitive_name_hint",
    }
    has_content = any(
        any(m in r for m in content_markers) or r.startswith("secret_pattern:")
        for r in reasons
    )
    has_path = any(any(m in r for m in path_markers) for r in reasons) or bool(
        SENSITIVE_NAME_RE.search(url or "")
    )
    is_example = bool(EXAMPLE_PATH_RE.search(url or ""))
    is_historical = (discovery_mode or "").upper() in {"HISTORICAL", "PASSIVE_INDEX"} or (
        "HISTORICAL" in (classification or "").upper()
    )

    if has_content and not is_example:
        basis = "content_supported"
    elif has_path and body_preview and not is_example:
        basis = "path_and_snippet"
    elif has_path or is_example:
        basis = "path_only"
    else:
        basis = "insufficient"

    return {
        "evidence_basis": basis,
        "path_sensitive_name": bool(SENSITIVE_NAME_RE.search(url or "")),
        "example_or_template_path": is_example,
        "content_reason_codes": [r for r in reasons if any(m in r for m in content_markers) or r.startswith("secret_pattern:")],
        "path_reason_codes": [r for r in reasons if any(m in r for m in path_markers)],
        "basename": _basename(url),
        "historical_or_index": is_historical,
    }


def review_candidate(
    *,
    url: str,
    classification: str,
    reason_codes: list[str],
    body_preview_redacted: str = "",
    discovery_mode: str = "",
    target_relationship: str = "",
    confidence_rationale: str = "",
) -> dict[str, Any]:
    """
    Second-pass review. Does not claim a confirmed vulnerability.
    """
    basis = evidence_basis(
        url=url,
        classification=classification,
        reason_codes=reason_codes,
        body_preview=body_preview_redacted,
        discovery_mode=discovery_mode,
    )
    keys = extract_config_keys(body_preview_redacted or "")
    shapes = {k["value_shape"] for k in keys}
    secret_like_keys = [k["key"] for k in keys if k["value_shape"] == "secret_like"]
    placeholder_keys = [
        k["key"] for k in keys if k["value_shape"] in {"placeholder", "empty", "generic"}
    ]

    decision = "NEEDS_REVIEW"
    rationale_parts: list[str] = []

    if basis["example_or_template_path"]:
        decision = "LOW_PRIORITY"
        rationale_parts.append("Path looks like an example/template file.")
    elif basis["evidence_basis"] == "path_only" and not secret_like_keys:
        decision = "LOW_PRIORITY"
        rationale_parts.append(
            "Elevation appears driven by filename/path, not content-supported secret evidence."
        )
    elif secret_like_keys and basis["evidence_basis"] in {
        "content_supported",
        "path_and_snippet",
    }:
        decision = "POTENTIAL_EXPOSURE_UNCONFIRMED"
        rationale_parts.append(
            f"Secret-like value shapes for keys {secret_like_keys[:5]} (values not stored)."
        )
    elif any(r.startswith("secret_pattern:") for r in (reason_codes or [])):
        decision = "POTENTIAL_EXPOSURE_UNCONFIRMED"
        rationale_parts.append("Classifier reported a secret_pattern reason code.")
    elif classification in {
        "SPA_SHELL",
        "GENERIC_ERROR",
        "AUTH_REQUIRED",
        "INTENTIONALLY_PUBLIC",
        "KEYWORD_FALSE_POSITIVE",
        "EMPTY_RESPONSE",
        "UNREACHABLE",
        "DUPLICATE",
        "HISTORICAL_ONLY",
    }:
        decision = "LOW_PRIORITY"
        rationale_parts.append(f"Classification {classification} is a low-priority/noise class.")
    else:
        decision = "NEEDS_REVIEW"
        rationale_parts.append("Mixed or incomplete signals; human scope/context review recommended.")

    if target_relationship in {"INDEX_ONLY", "UNATTRIBUTED"}:
        rationale_parts.append(
            f"target_relationship={target_relationship}: public index hit, not target confirmation."
        )
        if decision == "POTENTIAL_EXPOSURE_UNCONFIRMED":
            decision = "NEEDS_REVIEW"
        # Generic public-index pages without sensitive path/content are not bounty leads
        if classification in {"UNKNOWN", "IMPACT_UNPROVEN", "INTENTIONALLY_PUBLIC"} and not secret_like_keys:
            if not basis.get("path_sensitive_name"):
                decision = "LOW_PRIORITY"
                rationale_parts.append(
                    "Index-only generic page without sensitive path/content — deprioritized."
                )

    return {
        "review_decision": decision,
        "review_rationale": " ".join(rationale_parts),
        "evidence_basis": basis["evidence_basis"],
        "example_or_template_path": basis["example_or_template_path"],
        "path_sensitive_name": basis["path_sensitive_name"],
        "config_keys": [{"key": k["key"], "value_shape": k["value_shape"]} for k in keys],
        "secret_like_key_count": len(secret_like_keys),
        "placeholder_or_generic_key_count": len(placeholder_keys),
        "original_classification": classification,
        "original_reason_codes": list(reason_codes or []),
        "original_rationale": confidence_rationale or "",
        "target_relationship": target_relationship or "",
        "confirmed_vulnerability": False,
        "note": (
            "Review is a prioritization aid only. Zero pattern matches ≠ proof of no secrets; "
            "secret-like shapes ≠ valid in-scope credentials."
        ),
    }


def review_queue_item(item: dict[str, Any], *, body_preview: str = "") -> dict[str, Any]:
    """Attach a review block to a research-queue dict."""
    out = dict(item)
    md = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    rel = (
        item.get("target_relationship")
        or md.get("target_relationship")
        or ""
    )
    review = review_candidate(
        url=item.get("url") or item.get("primary_url") or "",
        classification=item.get("classification") or "",
        reason_codes=list(item.get("classification_reason_codes") or item.get("reason_codes") or []),
        body_preview_redacted=body_preview or item.get("evidence_summary") or "",
        discovery_mode=item.get("discovery_mode") or "",
        target_relationship=rel,
        confidence_rationale=item.get("confidence_rationale") or "",
    )
    out["evidence_review"] = review
    out["review_decision"] = review["review_decision"]
    return out
