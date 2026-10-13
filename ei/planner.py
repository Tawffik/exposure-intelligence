"""
Daily planner / budget (charter §3 component 3, §8).

Chooses passive query families and optional probes from profile policy,
without executing network I/O itself.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from ei.profile import ProgramProfile
from ei.query_families import select_query_terms, DEFAULT_ACTIONS_TERMS


@dataclass
class PlanItem:
    kind: str  # passive_github | passive_urlscan | passive_cdx | probe_head
    provider: str
    query_or_note: str = ""
    budget: int = 10
    enabled: bool = True
    skip_reason: str = ""


@dataclass
class ResearchPlan:
    target_id: str
    target_host: str
    authorization_status: str
    items: list[PlanItem] = field(default_factory=list)
    policy_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "target_host": self.target_host,
            "authorization_status": self.authorization_status,
            "items": [asdict(i) for i in self.items],
            "policy_notes": self.policy_notes,
            "enabled_count": sum(1 for i in self.items if i.enabled),
        }


def plan_research(
    profile: ProgramProfile,
    *,
    max_github_results: int = 10,
    enable_probes: bool = False,
    query_family: str = "default",
    github_query: str = "",
) -> ResearchPlan:
    host = ""
    if profile.in_scope_hosts:
        host = profile.in_scope_hosts[0]
    elif profile.in_scope_domains:
        host = profile.in_scope_domains[0]

    plan = ResearchPlan(
        target_id=profile.target_id,
        target_host=host,
        authorization_status=profile.authorization_status,
    )
    ops = set(profile.allowed_operations or [])

    # Passive index always available as research capability when not blocked
    passive_ok = "PASSIVE_INDEX" in ops or not ops  # empty ops → treat as passive-friendly for research tooling
    if profile.authorization_status == "EXPIRED":
        plan.policy_notes.append("Authorization EXPIRED — plan limited to offline fixtures only.")
        passive_ok = False

    if passive_ok:
        terms = select_query_terms(base_terms=github_query, family=query_family, limit=min(8, max(1, max_github_results)))
        for term in terms:
            plan.items.append(
                PlanItem(
                    kind="passive_github",
                    provider="github_code_search",
                    query_or_note=f"{host} {term}" if host else term,
                    budget=max(1, max_github_results // max(len(terms), 1)),
                )
            )
        plan.items.append(
            PlanItem(kind="passive_urlscan", provider="urlscan", query_or_note=host or profile.target_id, budget=10)
        )
        plan.items.append(
            PlanItem(kind="passive_cdx", provider="internet_archive_cdx", query_or_note=host or profile.target_id, budget=10)
        )
    else:
        plan.items.append(
            PlanItem(
                kind="passive_github",
                provider="github_code_search",
                enabled=False,
                skip_reason="policy blocked passive collection",
            )
        )

    # Probes: separate capability
    can_probe = (
        enable_probes
        and profile.authorization_status == "ACTIVE"
        and ("CURRENT_OBSERVATION_HEAD" in ops or "CURRENT_OBSERVATION_GET" in ops)
    )
    if can_probe:
        plan.items.append(
            PlanItem(
                kind="probe_head",
                provider="current_state_probe",
                query_or_note="artifact_paths catalog + in-scope candidate URLs",
                budget=min(12, getattr(profile, "request_budget", 12) or 12),
            )
        )
    else:
        reason = "probes disabled"
        if profile.authorization_status != "ACTIVE":
            reason = f"authorization_status={profile.authorization_status}"
        elif "CURRENT_OBSERVATION_HEAD" not in ops and "CURRENT_OBSERVATION_GET" not in ops:
            reason = "CURRENT_OBSERVATION_* not in allowed_operations"
        plan.items.append(
            PlanItem(
                kind="probe_head",
                provider="current_state_probe",
                enabled=False,
                skip_reason=reason,
            )
        )
        plan.policy_notes.append(f"Probe skipped: {reason}")

    return plan
