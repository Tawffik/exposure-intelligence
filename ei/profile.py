"""Program / target profile: explicit authorization and scope, fail-closed for live ops."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from ei.models import utc_now_iso

VALID_AUTH_STATUS = {"ACTIVE", "PAUSED", "EXPIRED", "UNKNOWN"}
VALID_OPS = {
    "PASSIVE_INDEX",
    "HISTORICAL",
    "CURRENT_OBSERVATION_GET",
    "CURRENT_OBSERVATION_HEAD",
}


@dataclass
class ProgramProfile:
    """Minimal operational profile. Live ops require ACTIVE + matching host."""

    target_id: str
    program_name: str = ""
    authorization_status: str = "UNKNOWN"
    authorization_reference: str = ""
    authorization_reviewed_at: str = ""
    authorization_expires_at: str = ""
    in_scope_hosts: list[str] = field(default_factory=list)
    in_scope_domains: list[str] = field(default_factory=list)
    out_of_scope_hosts: list[str] = field(default_factory=list)
    out_of_scope_domains: list[str] = field(default_factory=list)
    allowed_operations: list[str] = field(default_factory=lambda: ["PASSIVE_INDEX", "HISTORICAL"])
    notes: str = ""
    profile_version: str = "1"
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProfileValidation:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _norm_host(value: str) -> str:
    v = (value or "").strip().lower()
    if v.startswith("*."):
        return v
    # strip scheme if user pasted a URL
    if "://" in v:
        parsed = urlparse(v)
        v = parsed.hostname or v
    return v.rstrip(".")


def load_profile(path: Path) -> ProgramProfile:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Profile must be a JSON object")
    return profile_from_dict(data)


def profile_from_dict(data: dict[str, Any]) -> ProgramProfile:
    known = {f.name for f in ProgramProfile.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    filtered = {k: v for k, v in data.items() if k in known}
    if "in_scope_hosts" in filtered:
        filtered["in_scope_hosts"] = [_norm_host(h) for h in filtered["in_scope_hosts"]]
    if "in_scope_domains" in filtered:
        filtered["in_scope_domains"] = [_norm_host(h) for h in filtered["in_scope_domains"]]
    if "out_of_scope_hosts" in filtered:
        filtered["out_of_scope_hosts"] = [_norm_host(h) for h in filtered["out_of_scope_hosts"]]
    if "out_of_scope_domains" in filtered:
        filtered["out_of_scope_domains"] = [_norm_host(h) for h in filtered["out_of_scope_domains"]]
    return ProgramProfile(**filtered)


def validate_profile(profile: ProgramProfile) -> ProfileValidation:
    errors: list[str] = []
    warnings: list[str] = []
    if not profile.target_id or not str(profile.target_id).strip():
        errors.append("target_id is required")
    if profile.authorization_status not in VALID_AUTH_STATUS:
        errors.append(
            f"authorization_status must be one of {sorted(VALID_AUTH_STATUS)}; "
            f"got {profile.authorization_status!r}"
        )
    for op in profile.allowed_operations:
        if op not in VALID_OPS:
            errors.append(f"unknown allowed_operation: {op!r}")
    if not profile.in_scope_hosts and not profile.in_scope_domains:
        warnings.append(
            "No in_scope_hosts or in_scope_domains; live verification will always be denied. "
            "Passive index collection remains allowed separately."
        )
    if profile.authorization_status != "ACTIVE":
        warnings.append(
            f"authorization_status={profile.authorization_status}: live host requests denied; "
            "passive research and offline analysis still permitted."
        )
    if "PASSIVE_INDEX" not in profile.allowed_operations and "HISTORICAL" not in profile.allowed_operations:
        warnings.append("No passive operations listed; research runs may only process local fixtures.")
    return ProfileValidation(ok=len(errors) == 0, errors=errors, warnings=warnings)


def host_matches(host: str, patterns: list[str]) -> bool:
    """Exact host or domain-suffix match. No ambiguous substring matching."""
    h = _norm_host(host)
    if not h:
        return False
    for p in patterns:
        p = _norm_host(p)
        if not p:
            continue
        if p.startswith("*."):
            suffix = p[2:]
            if h == suffix or h.endswith("." + suffix):
                return True
        elif h == p:
            return True
        elif h.endswith("." + p) and p in patterns:
            # explicit domain entry matches subdomains only when listed as domain
            return True
    return False


def domain_list_match(host: str, domains: list[str]) -> bool:
    h = _norm_host(host)
    for d in domains:
        d = _norm_host(d)
        if not d:
            continue
        if d.startswith("*."):
            d = d[2:]
        if h == d or h.endswith("." + d):
            return True
    return False


def assess_relevance(profile: ProgramProfile, url: str) -> dict[str, Any]:
    """
    Label relationship of a URL/artifact to the program.

    Does NOT grant live authorization. Public leads stay retained with
    uncertain relevance when host cannot be tied to scope.
    """
    host = urlparse(url).hostname or ""
    host = _norm_host(host)

    if not host:
        return {
            "relevance": "UNKNOWN",
            "live_allowed": False,
            "reason": "No host in URL; cannot attribute to program scope.",
        }

    if host_matches(host, profile.out_of_scope_hosts) or domain_list_match(
        host, profile.out_of_scope_domains
    ):
        return {
            "relevance": "OUT_OF_SCOPE",
            "live_allowed": False,
            "reason": f"Host {host} matches out-of-scope rules.",
        }

    in_host = host_matches(host, profile.in_scope_hosts) or domain_list_match(
        host, profile.in_scope_domains
    )
    if in_host:
        live = (
            profile.authorization_status == "ACTIVE"
            and (
                "CURRENT_OBSERVATION_GET" in profile.allowed_operations
                or "CURRENT_OBSERVATION_HEAD" in profile.allowed_operations
            )
        )
        return {
            "relevance": "IN_SCOPE",
            "live_allowed": live,
            "reason": f"Host {host} matches in-scope rules."
            + (" Live ops permitted." if live else " Live ops not permitted by profile."),
        }

    # github.com / public index hosts are not the application target
    if host in {"github.com", "api.github.com", "raw.githubusercontent.com"}:
        return {
            "relevance": "PUBLIC_INDEX",
            "live_allowed": False,
            "reason": (
                "Public code-index host; lead retained. Not proof of production exposure "
                "on program assets."
            ),
        }

    return {
        "relevance": "UNATTRIBUTED",
        "live_allowed": False,
        "reason": (
            f"Host {host} not in program scope lists; retained as unattributed lead, "
            "not authorized for live requests."
        ),
    }


def live_request_permitted(profile: ProgramProfile, url: str) -> dict[str, Any]:
    """Fail-closed gate for live host requests only."""
    rel = assess_relevance(profile, url)
    if profile.authorization_status != "ACTIVE":
        return {
            "allowed": False,
            "reason": f"authorization_status={profile.authorization_status} (not ACTIVE).",
            "relevance": rel["relevance"],
        }
    if not rel.get("live_allowed"):
        return {
            "allowed": False,
            "reason": rel["reason"],
            "relevance": rel["relevance"],
        }
    return {"allowed": True, "reason": rel["reason"], "relevance": rel["relevance"]}
