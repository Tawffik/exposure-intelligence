"""
Run-level research metrics (charter §10).

Yield-oriented: actionable reviews vs noise, not raw URL count.
"""

from __future__ import annotations

from typing import Any


def compute_run_metrics(result: dict[str, Any]) -> dict[str, Any]:
    queue = result.get("research_queue") or []
    providers = result.get("provider_summaries") or []
    reviews: dict[str, int] = {}
    classes: dict[str, int] = {}
    for q in queue:
        r = q.get("review_decision") or "UNKNOWN"
        c = q.get("classification") or "UNKNOWN"
        reviews[r] = reviews.get(r, 0) + 1
        classes[c] = classes.get(c, 0) + 1
    actionable = sum(
        1
        for q in queue
        if q.get("review_decision") in ("POTENTIAL_EXPOSURE_UNCONFIRMED", "NEEDS_REVIEW")
        and q.get("classification") not in ("HISTORICAL_ONLY", "EMPTY_RESPONSE", "SPA_SHELL", "GENERIC_ERROR")
    )
    noise = sum(
        1
        for q in queue
        if q.get("classification") in ("HISTORICAL_ONLY", "EMPTY_RESPONSE", "SPA_SHELL", "GENERIC_ERROR", "KEYWORD_FALSE_POSITIVE")
        or q.get("review_decision") == "LOW_PRIORITY"
    )
    prov_status = {p.get("provider"): p.get("status") for p in providers}
    complete_prov = sum(
        1
        for s in prov_status.values()
        if s in ("COMPLETED_WITH_RESULTS", "COMPLETED_ZERO")
    )
    return {
        "queue_size": len(queue),
        "actionable_candidates": actionable,
        "noise_or_low_priority": noise,
        "actionable_ratio": round(actionable / max(len(queue), 1), 4),
        "review_histogram": reviews,
        "classification_histogram": classes,
        "provider_statuses": prov_status,
        "providers_completed": complete_prov,
        "providers_total": len(providers),
        "live_host_requests": result.get("live_host_requests", 0),
        "run_status": result.get("status"),
        "data_source_label": result.get("data_source_label"),
    }
