"""
Versioned export adapter (charter §3 component 11).

Produces a small, explicit evidence bundle for external consumers
(e.g. BugBountyCI) without coupling EI's core to them.
"""

from __future__ import annotations

from ei.hypothesis import build_hypothesis

import json
from pathlib import Path
from typing import Any

from ei.models import utc_now_iso

EXPORT_SCHEMA = "ei.export.v1"


def build_export_bundle(
    research_result: dict[str, Any],
    *,
    target_host: str = "",
    research_mode: str = "",
) -> dict[str, Any]:
    queue = research_result.get("research_queue") or []
    export_candidates = []
    for item in queue:
        export_candidates.append(
            {
                "url": item.get("url"),
                "classification": item.get("classification"),
                "sensitivity": item.get("sensitivity"),
                "confidence": item.get("confidence"),
                "rank_score": item.get("rank_score"),
                "change_type": item.get("change_type"),
                "review_decision": item.get("review_decision"),
                "evidence_review": item.get("evidence_review"),
                "classification_reason_codes": item.get("classification_reason_codes")
                or (item.get("evidence_review") or {}).get("original_reason_codes")
                or [],
                "impact_hypothesis": item.get("impact_hypothesis"),
                "suggested_next_step": item.get("suggested_next_step"),
                "confirmed_vulnerability": False,
                "hypothesis": build_hypothesis(item),
            }
        )
    return {
        "schema": EXPORT_SCHEMA,
        "generated_at": utc_now_iso(),
        "target_host": target_host,
        "target_id": research_result.get("target_id"),
        "run_id": research_result.get("run_id"),
        "research_mode": research_mode or research_result.get("research_mode") or "",
        "status": research_result.get("status"),
        "summary": research_result.get("summary") or {},
        "provider_summaries": research_result.get("provider_summaries") or [],
        "candidates": export_candidates,
        "live_host_requests": research_result.get("live_host_requests", 0),
        "notes": [
            "Export is evidence leads only — not confirmed findings.",
            "Consumers must re-check program scope before any active validation.",
        ],
    }


def write_export_bundle(bundle: dict[str, Any], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return path
