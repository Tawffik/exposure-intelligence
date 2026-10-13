"""
Shared hostname/URL relationship helpers (charter attribution rules).

Technical hostname relationship is NOT authorization or vulnerability proof.
Textual matches (path/query/body) are discovery metadata only.

Authority rule for hostname relationship:
- If the URL yields a valid parsed hostname, that hostname is authoritative.
- provider_domain must NOT upgrade relationship when it conflicts with the
  parsed URL hostname. Conflicts are recorded for human review.
- provider_domain is used as a fallback only when the URL has no valid
  parsed hostname (documented fallback).
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse


def normalize_hostname(host: str) -> str:
    """Lowercase, strip trailing DNS dot, strip surrounding brackets/whitespace."""
    h = (host or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h.rstrip(".")



def hostname_from_url(url: str) -> Optional[str]:
    """
    Parse hostname from a URL-like string.
    Returns None for empty/malformed values (no false attribution).
    """
    u = (url or "").strip()
    if not u:
        return None
    # Bare host without scheme — require no whitespace and a plausible token
    if "://" not in u and "/" not in u:
        if any(c.isspace() for c in u):
            return None
        host = normalize_hostname(
            u.split(":")[0] if u.count(":") == 1 and not u.startswith("[") else u
        )
        if not host or " " in host or not any(c == "." for c in host):
            # Reject tokens that are not multi-label hostnames
            if not host or " " in host:
                return None
        return host or None
    try:
        if "://" not in u:
            parsed = urlparse("//" + u)
        else:
            parsed = urlparse(u)
    except Exception:
        return None
    host = parsed.hostname
    if not host:
        return None
    host = normalize_hostname(host)
    if not host or any(c.isspace() for c in host):
        return None
    return host



def hosts_match_exact(a: str, b: str) -> bool:
    return bool(a and b and normalize_hostname(a) == normalize_hostname(b))


def host_is_or_subdomain_of(host: str, parent: str) -> bool:
    """
    True if host == parent OR host is a DNS subdomain of parent.
    Uses label boundaries — notexample.com is NOT under example.com.
    """
    h = normalize_hostname(host)
    p = normalize_hostname(parent)
    if not h or not p:
        return False
    if h == p:
        return True
    return h.endswith("." + p)


def _relationship_for_host(host: str, target: str) -> str:
    """Map a single hostname against target → relationship enum."""
    if not host:
        return "UNATTRIBUTED"
    if hosts_match_exact(host, target):
        return "DIRECT_HOST"
    if host_is_or_subdomain_of(host, target):
        return "RELATED_SUBDOMAIN"
    return "INDEX_ONLY"


def classify_url_host_relationship(
    *,
    target_host: str,
    url: str = "",
    provider_domain: str = "",
) -> dict[str, Any]:
    """
    Classify relationship of a URL/domain field to selected target host.

    Returns keys include:
      relationship: DIRECT_HOST | RELATED_SUBDOMAIN | INDEX_ONLY | UNATTRIBUTED
      hostname: authoritative hostname used for the decision (URL parse preferred)
      provider_domain: normalized provider field (if any)
      provider_domain_conflict: True when provider_domain disagrees with URL host
      provider_domain_fallback: True when decision used provider_domain because URL had no host
      textual_match / textual_match_fields
      rationale

    Does NOT imply authorization, scope, or vulnerability confirmation.
    """
    target = normalize_hostname(target_host)
    if not target or "." not in target:
        return {
            "relationship": "UNATTRIBUTED",
            "hostname": "",
            "provider_domain": normalize_hostname(provider_domain) if provider_domain else "",
            "provider_domain_conflict": False,
            "provider_domain_fallback": False,
            "textual_match": False,
            "textual_match_fields": [],
            "rationale": "Selected target_host missing or not a multi-label domain.",
        }

    parsed = hostname_from_url(url) if url else None
    prov = normalize_hostname(provider_domain) if provider_domain else ""

    fields: list[str] = []
    if target in (url or "").lower():
        fields.append("url_text")

    # --- Case A: valid URL hostname is authoritative ---
    if parsed:
        rel = _relationship_for_host(parsed, target)
        conflict = bool(prov and not hosts_match_exact(prov, parsed))
        rationale_parts: list[str] = []
        if rel == "DIRECT_HOST":
            rationale_parts.append(
                f"Parsed URL hostname equals selected target '{target}'. "
                "Index evidence only unless current-state verified. "
                "Not authorization or vulnerability confirmation."
            )
            out_fields = ["hostname"]
            textual = True
        elif rel == "RELATED_SUBDOMAIN":
            rationale_parts.append(
                f"Parsed URL hostname '{parsed}' is a DNS subdomain of '{target}'. "
                "Technical relationship only — not automatic authorization."
            )
            out_fields = ["hostname"]
            textual = True
        else:
            rationale_parts.append(
                f"Parsed URL hostname '{parsed}' is not a DNS match for '{target}'. "
                "Not related by hostname."
            )
            textual = bool(fields) or (target in (url or "").lower())
            out_fields = list(fields)
            if textual and "url_text" not in out_fields and target in (url or "").lower():
                out_fields.append("url_text")
            if textual and target in (url or "").lower():
                rationale_parts.append(
                    f"Selected host string '{target}' may appear in URL text; "
                    "textual match only — not attribution."
                )

        if conflict:
            rationale_parts.append(
                f"Provider domain field '{prov}' conflicts with parsed URL hostname '{parsed}' "
                "and was NOT used to upgrade relationship."
            )

        return {
            "relationship": rel if rel != "UNATTRIBUTED" else "INDEX_ONLY",
            "hostname": parsed,
            "provider_domain": prov,
            "provider_domain_conflict": conflict,
            "provider_domain_fallback": False,
            "textual_match": textual,
            "textual_match_fields": out_fields,
            "rationale": " ".join(rationale_parts),
        }

    # --- Case B: no valid URL hostname — documented provider_domain fallback ---
    if prov:
        rel = _relationship_for_host(prov, target)
        if rel == "DIRECT_HOST":
            return {
                "relationship": "DIRECT_HOST",
                "hostname": prov,
                "provider_domain": prov,
                "provider_domain_conflict": False,
                "provider_domain_fallback": True,
                "textual_match": True,
                "textual_match_fields": ["provider_domain"],
                "rationale": (
                    f"No valid URL hostname; fallback to provider_domain '{prov}' "
                    f"which equals selected target '{target}'. "
                    "Verify against a real URL when available. "
                    "Not authorization or vulnerability confirmation."
                ),
            }
        if rel == "RELATED_SUBDOMAIN":
            return {
                "relationship": "RELATED_SUBDOMAIN",
                "hostname": prov,
                "provider_domain": prov,
                "provider_domain_conflict": False,
                "provider_domain_fallback": True,
                "textual_match": True,
                "textual_match_fields": ["provider_domain"],
                "rationale": (
                    f"No valid URL hostname; fallback to provider_domain '{prov}' "
                    f"which is a DNS subdomain of '{target}'. "
                    "Not automatic authorization."
                ),
            }
        return {
            "relationship": "INDEX_ONLY",
            "hostname": prov,
            "provider_domain": prov,
            "provider_domain_conflict": False,
            "provider_domain_fallback": True,
            "textual_match": bool(fields),
            "textual_match_fields": fields,
            "rationale": (
                f"No valid URL hostname; fallback provider_domain '{prov}' "
                f"is not a DNS match for '{target}'."
            ),
        }

    # --- Case C: nothing usable ---
    if target in (url or "").lower():
        return {
            "relationship": "INDEX_ONLY",
            "hostname": "",
            "provider_domain": "",
            "provider_domain_conflict": False,
            "provider_domain_fallback": False,
            "textual_match": True,
            "textual_match_fields": fields or ["url_text"],
            "rationale": (
                f"Selected host string '{target}' appears in URL text but no valid "
                "hostname could be parsed. Textual match only — not attribution."
            ),
        }

    return {
        "relationship": "INDEX_ONLY" if url else "UNATTRIBUTED",
        "hostname": "",
        "provider_domain": "",
        "provider_domain_conflict": False,
        "provider_domain_fallback": False,
        "textual_match": False,
        "textual_match_fields": [],
        "rationale": "No DNS-boundary hostname relationship to selected target.",
    }


def to_provider_relationship(detail: dict[str, Any]) -> str:
    """Map detailed host relationships into provider vocabulary used by ranker/queue."""
    rel = detail.get("relationship") or ""
    if rel in {"DIRECT_HOST", "RELATED_SUBDOMAIN"}:
        return "RELATED_CANDIDATE"
    if rel == "UNATTRIBUTED":
        return "UNATTRIBUTED"
    return "INDEX_ONLY"
