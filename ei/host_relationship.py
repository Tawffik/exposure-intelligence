"""
Shared hostname/URL relationship helpers (charter attribution rules).

Technical hostname relationship is NOT authorization or vulnerability proof.
Textual matches (path/query/body) are discovery metadata only.
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
    # Bare host without scheme
    if "://" not in u and "/" not in u and " " not in u:
        host = normalize_hostname(u.split(":")[0] if u.count(":") == 1 and not u.startswith("[") else u)
        return host or None
    try:
        if "://" not in u:
            parsed = urlparse("//" + u)
        else:
            parsed = urlparse(u)
    except Exception:
        return None
    host = parsed.hostname  # already strips port; handles IDNA when possible
    if not host:
        return None
    return normalize_hostname(host)


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


def classify_url_host_relationship(
    *,
    target_host: str,
    url: str = "",
    provider_domain: str = "",
) -> dict[str, Any]:
    """
    Classify relationship of a URL/domain field to selected target host.

    Returns:
      relationship: DIRECT_HOST | RELATED_SUBDOMAIN | INDEX_ONLY | UNATTRIBUTED
      hostname: parsed host or ""
      textual_match: target string appears somewhere in URL text (not proof)
      textual_match_fields: where the string appeared
      rationale: human-readable explanation
    """
    target = normalize_hostname(target_host)
    if not target or "." not in target:
        return {
            "relationship": "UNATTRIBUTED",
            "hostname": "",
            "textual_match": False,
            "textual_match_fields": [],
            "rationale": "Selected target_host missing or not a multi-label domain.",
        }

    parsed = hostname_from_url(url) if url else None
    prov = normalize_hostname(provider_domain) if provider_domain else ""

    # Prefer parsed URL hostname; fall back to provider domain field
    host = parsed or (prov if prov else "")

    fields: list[str] = []
    text_blob = (url or "").lower()
    if target in text_blob:
        # Locate approximate field
        if target in (url or "").lower():
            fields.append("url_text")
    if prov and target in prov:
        fields.append("provider_domain_text")

    textual = bool(fields) or (bool(host) and target in host and host != target and not host_is_or_subdomain_of(host, target))

    if host and hosts_match_exact(host, target):
        return {
            "relationship": "DIRECT_HOST",
            "hostname": host,
            "textual_match": True,
            "textual_match_fields": ["hostname"],
            "rationale": f"Parsed hostname equals selected target '{target}'. Index evidence only unless current-state verified.",
        }
    if host and host_is_or_subdomain_of(host, target):
        return {
            "relationship": "RELATED_SUBDOMAIN",
            "hostname": host,
            "textual_match": True,
            "textual_match_fields": ["hostname"],
            "rationale": (
                f"Parsed hostname '{host}' is a DNS subdomain of '{target}'. "
                "Technical relationship only — not automatic authorization."
            ),
        }
    if prov and hosts_match_exact(prov, target):
        return {
            "relationship": "DIRECT_HOST",
            "hostname": prov,
            "textual_match": True,
            "textual_match_fields": ["provider_domain"],
            "rationale": f"Provider domain field equals selected target '{target}'. Verify against parsed URL when available.",
        }
    if prov and host_is_or_subdomain_of(prov, target):
        return {
            "relationship": "RELATED_SUBDOMAIN",
            "hostname": prov,
            "textual_match": True,
            "textual_match_fields": ["provider_domain"],
            "rationale": f"Provider domain '{prov}' is a DNS subdomain of '{target}'. Not automatic authorization.",
        }

    # Textual only — path/query/title leakage
    if target in (url or "").lower():
        return {
            "relationship": "INDEX_ONLY",
            "hostname": host or "",
            "textual_match": True,
            "textual_match_fields": fields or ["url_text"],
            "rationale": (
                f"Selected host string '{target}' appears in URL text but parsed hostname "
                f"('{host or 'none'}') is not a DNS match. Textual match only — not attribution."
            ),
        }

    return {
        "relationship": "INDEX_ONLY" if (url or provider_domain) else "UNATTRIBUTED",
        "hostname": host or "",
        "textual_match": False,
        "textual_match_fields": [],
        "rationale": "No DNS-boundary hostname relationship to selected target.",
    }


# Map detailed host relationships into provider relationship vocabulary used by ranker/queue
def to_provider_relationship(detail: dict[str, Any]) -> str:
    rel = detail.get("relationship") or ""
    if rel in {"DIRECT_HOST", "RELATED_SUBDOMAIN"}:
        return "RELATED_CANDIDATE"
    if rel == "UNATTRIBUTED":
        return "UNATTRIBUTED"
    return "INDEX_ONLY"
