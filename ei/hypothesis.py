"""Deterministic disclosure hypothesis templates (lead != confirmed finding).

Next-step language is influenced by public hunter playbooks (e.g. Orwa Atyat):
focus on impact of a key type, demote localhost leaks, never claim confirmed vulns.
"""

from __future__ import annotations

from typing import Any


def _safe_next_step(candidate: dict[str, Any]) -> str:
    url = (candidate.get("url") or candidate.get("primary_url") or "").lower()
    reasons = " ".join(candidate.get("classification_reason_codes") or []).lower()
    review = candidate.get("review_decision") or ""
    rel = (candidate.get("target_relationship") or "").upper()
    if review == "LOW_PRIORITY":
        return "Skip unless program policy explicitly values this artifact class."
    if "localhost" in url or "127.0.0.1" in url:
        return "Likely local-only credentials — do not report without production host evidence."
    if "sk_live_" in reasons or "stripe" in reasons:
        return "If authorized: confirm whether any Stripe live key is revoked/scoped; do not use the key."
    if "akia" in reasons or "aws" in reasons:
        return "If authorized: check key scope via vendor docs only; never call customer resources with found keys."
    if "firebase" in url or "google" in reasons or "api_key" in reasons:
        return (
            "Hunter note: some API keys look informational until capability is understood "
            "(e.g. Identity Toolkit). Document capability only within program rules; no abuse."
        )
    if "source_map" in reasons or url.endswith(".map"):
        return (
            "Open the map; check sourcesContent for secrets/internal URLs; "
            "map any hosts back to program scope before reporting."
        )
    if "git_metadata" in reasons or "/.git/" in url:
        return (
            "Confirm .git is still reachable only under ACTIVE auth; "
            "document exposed objects — do not clone aggressively outside program rules."
        )
    if ".env" in url or "sensitive_path" in reasons:
        return "Open the public blob, confirm non-example content, map hostnames to program scope."
    if rel == "UNATTRIBUTED":
        return (
            "Host does not match the selected target — verify this is not fixture/third-party "
            "noise before spending time; only report if ownership is clear."
        )
    if rel == "INDEX_ONLY":
        return "Treat as public-index hit; verify org/employee ownership before any report."
    return "Human review of evidence; no active probing without ACTIVE authorization."


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
            "likely noise, template, local-only, or out-of-scope third-party material."
        )

    counter = []
    if rel in {"INDEX_ONLY", "UNATTRIBUTED", "OUT_OF_SCOPE"}:
        counter.append(f"Attribution is {rel}; not confirmed as target-owned exposure.")
    if "example_or_template_path" in reasons or review == "LOW_PRIORITY":
        counter.append("Path or review signals suggest template/example/noise/local-only.")
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
            "Not a confirmed production compromise. Key presence != key impact "
            "(validate capability only under program rules)."
        ),
        # Prefer impact-oriented template; fall back to any pre-set operator step.
        "safe_next_step": _safe_next_step(candidate)
        or candidate.get("suggested_next_step")
        or "Human review of evidence; no active probing without ACTIVE authorization.",
        "authorization_prerequisites": auth_prereq,
        "confirmed_vulnerability": False,
    }
