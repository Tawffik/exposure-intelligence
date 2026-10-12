"""
Authorized target registry — source of truth for multi-target runs.

Charter §3–4: a domain list is not authorization. Each profile carries
status, scope, allowed operations, and expiry. Fail-closed for active work.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ei.profile import ProgramProfile, profile_from_dict, validate_profile


@dataclass
class RegistryLoadResult:
    profiles: list[ProgramProfile] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    path: str = ""

    @property
    def ok(self) -> bool:
        return not self.errors and bool(self.profiles)


def load_registry(path: Path) -> RegistryLoadResult:
    """
    Load a JSON registry.

    Formats accepted:
    - {"targets": [ {profile}, ... ], "schema_version": "1"}
    - [ {profile}, ... ]
    """
    result = RegistryLoadResult(path=str(path))
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        result.errors.append(f"Failed to read registry: {e}")
        return result

    items: list[Any]
    if isinstance(raw, dict):
        items = raw.get("targets") or raw.get("profiles") or []
        if not isinstance(items, list):
            result.errors.append("targets must be a list")
            return result
    elif isinstance(raw, list):
        items = raw
    else:
        result.errors.append("Registry must be a list or object with targets[]")
        return result

    seen_ids: set[str] = set()
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            result.errors.append(f"targets[{i}] is not an object")
            continue
        try:
            profile = profile_from_dict(item)
        except (TypeError, ValueError, KeyError) as e:
            result.errors.append(f"targets[{i}] parse error: {e}")
            continue
        v = validate_profile(profile)
        if not v.ok:
            result.errors.append(f"targets[{i}] invalid: {v.errors}")
            continue
        if profile.target_id in seen_ids:
            result.errors.append(f"duplicate target_id: {profile.target_id}")
            continue
        seen_ids.add(profile.target_id)
        result.profiles.append(profile)
    return result


def registry_summary(profiles: list[ProgramProfile]) -> list[dict[str, Any]]:
    out = []
    for p in profiles:
        out.append(
            {
                "target_id": p.target_id,
                "program_name": p.program_name,
                "authorization_status": p.authorization_status,
                "in_scope_hosts": list(p.in_scope_hosts),
                "allowed_operations": list(p.allowed_operations),
                "authorization_reference": p.authorization_reference,
            }
        )
    return out
