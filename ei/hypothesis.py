"""Deterministic disclosure hypothesis templates (lead != confirmed finding)."""

from __future__ import annotations

from typing import Any


def build_hypothesis(candidate: dict[str, Any]) -> dict[str, Any]:
    """Produce a structured, non-confirming hypothesis for human review."""
    cls = candidate.get("classification") or "UNKNOWN"
    rel = candidate.get("target_relationship") or "UNKNOWN"
    review = candidate.get("review_decision") or "NEEDS_REVIEW"
    reasons = list(candidate.get("classification_reason_codes") or [])
    url = candidate.get("url") or candidate.get("primary_url") or ""

    claim = (
        f"Public index artifact at {url[:120]} may contain information-disclosure "
        f"material (class={cls}). Impact is unproven."
    )
    if review == "LOW_PRIORITY":
        claim = (
            f"Low-priority index hit at {url[:120]} (class={cls}); "
            "likely noise, template, or out-of-scope third-party material."
        )

    counter = []
    if rel in {"INDEX_ONLY", "UNATTRIBUTED", "OUT_OF_SCOPE"}:
        counter.append(f"Attribution is {rel}; not confirmed as target-owned exposure.")
    if "example_or_template_path" in reasons or review == "LOW_PRIORITY":
        counter.append("Path or review signals suggest template/example/noise.")
    if not reasons:
        counter.append("No strong classifier reason codes attached.")

    missing = [
        "Human inspection of full artifact content",
        "Scope confirmation against program policy",
    ]
    if rel != "DIRECT_HOST":
        missing.append("Stronger asset attribution evidence")
    auth_prereq = "ACTIVE authorization + in-scope host required for current-state validation"

    return {
        "claim": claim,
        "supporting_evidence": reasons[:12],
        "counter_evidence": counter,
        "target_attribution": rel,
        "freshness": candidate.get("freshness") or "UNKNOWN",
        "missing_evidence": missing,
        "potential_impact_boundary": (
            "At most: public artifact may expose configuration or secret-like material. "
            "Not a confirmed production compromise."
        ),
        "safe_next_step": candidate.get("suggested_next_step")
        or "Human review of evidence; no active probing without ACTIVE authorization.",
        "authorization_prerequisites": auth_prereq,
        "confirmed_vulnerability": False,
    }
