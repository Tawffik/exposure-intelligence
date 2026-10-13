"""
Candidate lifecycle states (charter §5).

DISCOVERED → NORMALIZED → SCOPE_REVIEWED → TRIAGED → HUMAN_VALIDATION → CLOSED
Side states: OUT_OF_SCOPE, DUPLICATE, STALE_HISTORICAL, NOISE, BLOCKED_BY_POLICY, NEEDS_MORE_EVIDENCE
Never jumps to CONFIRMED automatically.
"""

from __future__ import annotations

from typing import Any

PRIMARY = [
    "DISCOVERED",
    "NORMALIZED",
    "SCOPE_REVIEWED",
    "TRIAGED",
    "HUMAN_VALIDATION",
    "CLOSED",
]
SIDE = [
    "OUT_OF_SCOPE",
    "DUPLICATE",
    "STALE_HISTORICAL",
    "NOISE",
    "BLOCKED_BY_POLICY",
    "NEEDS_MORE_EVIDENCE",
]


def infer_state(item: dict[str, Any]) -> str:
    """Map queue item signals to a lifecycle state. Not a confirmation."""
    scope = (item.get("scope_decision") or "").upper()
    rel = (item.get("target_relationship") or "").upper()
    cls = (item.get("classification") or "").upper()
    review = (item.get("review_decision") or "").upper()
    change = (item.get("change_type") or "").upper()

    if scope == "OUT_OF_SCOPE" or rel == "OUT_OF_SCOPE":
        return "OUT_OF_SCOPE"
    if cls in ("DUPLICATE",) or change == "DUPLICATE":
        return "DUPLICATE"
    if cls in ("HISTORICAL_ONLY",) or change in ("STALE", "NOT_IN_LATEST_RUN"):
        return "STALE_HISTORICAL"
    if review == "LOW_PRIORITY" or cls in ("SPA_SHELL", "GENERIC_ERROR", "EMPTY_RESPONSE", "KEYWORD_FALSE_POSITIVE"):
        return "NOISE"
    if review == "POTENTIAL_EXPOSURE_UNCONFIRMED":
        return "TRIAGED"
    if review == "NEEDS_REVIEW":
        return "NEEDS_MORE_EVIDENCE"
    if rel in ("INDEX_ONLY", "UNATTRIBUTED"):
        return "SCOPE_REVIEWED"
    return "NORMALIZED"


def attach_states(queue: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for item in queue:
        d = dict(item)
        d["candidate_state"] = infer_state(item)
        d["confirmed_vulnerability"] = False
        out.append(d)
    return out
