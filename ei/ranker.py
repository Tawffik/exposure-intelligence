"""Explainable ranking and correlation of candidates."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from ei.disclosure_taxonomy import classify_disclosure_signal
from ei.models import (
    Candidate,
    Classification,
    Observation,
    SensitivityClass,
    stable_candidate_key,
)

SENSITIVITY_WEIGHT = {
    SensitivityClass.CRITICAL.value: 1.0,
    SensitivityClass.HIGH.value: 0.8,
    SensitivityClass.MEDIUM.value: 0.5,
    SensitivityClass.LOW.value: 0.25,
    SensitivityClass.NONE.value: 0.0,
    SensitivityClass.UNKNOWN.value: 0.15,
}

# Classifications that should not rank high as actionable exposure
NOISE_CLASSES = {
    Classification.GENERIC_ERROR.value,
    Classification.SPA_SHELL.value,
    Classification.EMPTY_RESPONSE.value,
    Classification.UNREACHABLE.value,
    Classification.AUTH_REQUIRED.value,
    Classification.DUPLICATE.value,
    Classification.KEYWORD_FALSE_POSITIVE.value,
    Classification.INTENTIONALLY_PUBLIC.value,
    Classification.COPIED_RESEARCH.value,
}


def observations_to_candidates(observations: Iterable[Observation]) -> list[Candidate]:
    """Correlate observations by stable key; preserve provenance; rank."""
    groups: dict[str, list[Observation]] = defaultdict(list)
    for obs in observations:
        key = stable_candidate_key(obs.discovered_url, obs.body_sha256)
        groups[key].append(obs)

    candidates: list[Candidate] = []
    seen_primary: dict[str, str] = {}  # url-only key -> first candidate_id

    for key, group in groups.items():
        primary = group[0]
        url_only = stable_candidate_key(primary.discovered_url, "")
        is_dup = False
        dup_of = ""
        if url_only in seen_primary and len(group) == 1:
            # Same URL different body still distinct; pure URL re-see is duplicate signal
            pass

        # Prefer the highest-confidence / highest-sensitivity observation as representative
        primary = max(
            group,
            key=lambda o: (
                SENSITIVITY_WEIGHT.get(o.sensitivity, 0),
                o.confidence,
            ),
        )

        if primary.classification == Classification.DUPLICATE.value:
            is_dup = True

        rank, explanation = score_candidate(primary, group)
        disc = classify_disclosure_signal(
            url=primary.discovered_url or "",
            body=getattr(primary, "body_preview_redacted", "") or "",
            labels=list(getattr(primary, "labels", None) or []),
        )
        if disc.get("disclosure_class") and disc["disclosure_class"] != "GENERIC_PUBLIC":
            explanation = list(explanation) + [
                f"disclosure_class={disc['disclosure_class']}",
                disc.get("label") or "",
            ]

        cand = Candidate(
            stable_key=key,
            target_id=primary.target_id,
            primary_url=primary.discovered_url,
            classification=primary.classification,
            sensitivity=primary.sensitivity,
            freshness=primary.freshness,
            confidence=primary.confidence,
            confidence_rationale=primary.confidence_rationale,
            impact_hypothesis=_impact_hypothesis(primary),
            impact_confirmed=False,
            novelty_score=1.0 if primary.classification not in NOISE_CLASSES else 0.1,
            rank_score=rank,
            rank_explanation=explanation,
            observation_ids=[o.observation_id for o in group],
            duplicate_of=dup_of,
            source_fidelity=primary.source_fidelity,
            evidence_summary=_evidence_summary(primary, group),
            classification_reason_codes=list(primary.classification_reason_codes or []),
            target_relationship=(
                (primary.metadata or {}).get("target_relationship")
                or ((primary.metadata or {}).get("metadata") or {}).get("target_relationship")
                or ""
            ),
            scope_decision=primary.scope_decision or "",
            discovery_mode=primary.discovery_mode or "",
        )
        if is_dup:
            cand.rank_score = 0.0
            cand.rank_explanation.append("Marked duplicate; deprioritized.")
        candidates.append(cand)
        seen_primary.setdefault(url_only, cand.candidate_id)

    candidates.sort(key=lambda c: c.rank_score, reverse=True)
    return candidates


def score_candidate(primary: Observation, group: list[Observation]) -> tuple[float, list[str]]:
    explanation: list[str] = []
    sens_w = SENSITIVITY_WEIGHT.get(primary.sensitivity, 0.15)
    conf = max(0.0, min(1.0, primary.confidence))

    if primary.classification in NOISE_CLASSES:
        score = 0.05 * conf
        explanation.append(f"Noise/low-value class={primary.classification}")
        return round(score, 4), explanation

    freshness_w = 1.0 if primary.freshness == "CURRENT" else (0.45 if primary.freshness == "HISTORICAL" else 0.6)
    multi_source = min(1.0, 0.15 * (len({o.provider for o in group}) - 1))
    score = 0.45 * sens_w + 0.35 * conf + 0.15 * freshness_w + multi_source
    explanation.append(f"sensitivity_weight={sens_w:.2f}")
    explanation.append(f"confidence={conf:.2f}")
    explanation.append(f"freshness_weight={freshness_w:.2f}")
    if multi_source:
        explanation.append(f"multi_provider_bonus={multi_source:.2f}")
    explanation.append(f"class={primary.classification}")

    # Target-relationship penalties: public-index / unattributed leads stay visible but lower
    md = primary.metadata or {}
    nested = md.get("metadata") if isinstance(md.get("metadata"), dict) else {}
    rel = md.get("target_relationship") or nested.get("target_relationship") or ""
    scope = primary.scope_decision or ""
    if rel in {"INDEX_ONLY", "UNATTRIBUTED"} or scope in {"PUBLIC_INDEX", "UNATTRIBUTED"}:
        score *= 0.55
        explanation.append(
            f"relationship_penalty rel={rel or scope} (index/unattributed ≠ target finding)"
        )
    elif rel == "RELATED_CANDIDATE":
        score *= 0.75
        explanation.append("relationship_penalty RELATED_CANDIDATE")
    elif scope == "OUT_OF_SCOPE" or rel == "OUT_OF_SCOPE":
        score *= 0.15
        explanation.append("out_of_scope_penalty")
    elif rel == "DIRECT_TARGET_REFERENCE" or scope == "IN_SCOPE":
        explanation.append("target_relationship=DIRECT_OR_IN_SCOPE")

    # Demote example/template paths and path-only elevation without content reasons
    url_l = (primary.discovered_url or "").lower()
    reasons = set(primary.classification_reason_codes or [])
    if any(
        x in url_l
        for x in (
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.dist",
            "example.env",
            "/examples/",
            "/example/",
        )
    ):
        score *= 0.35
        explanation.append("example_template_path_penalty")
    content_supported = any(
        r.startswith("secret_pattern:")
        or r
        in {
            "diagnostic_trace_page",
            "directory_listing_fingerprint",
            "source_map_with_sources_content",
            "git_metadata_exposure",
            "archive_or_binary_content_type",
        }
        for r in reasons
    )
    path_driven = "sensitive_path_with_content" in reasons or "sensitive_path_hint" in reasons
    if path_driven and not content_supported:
        score *= 0.6
        explanation.append("path_only_without_content_secret_penalty")
        explanation.append(
            "rank_note=filename/path hints are not content-confirmed secrets"
        )

    # Boost official-looking org repos for the selected brand (still not a finding)
    md = primary.metadata or {}
    nested = md.get("metadata") if isinstance(md.get("metadata"), dict) else {}
    if md.get("org_brand_match") or nested.get("org_brand_match"):
        score = min(1.0, score * 1.25 + 0.05)
        explanation.append("org_brand_match_boost")

    if primary.classification == Classification.EMPTY_RESPONSE.value:

        score *= 0.2
        explanation.append("empty_response_penalty")
    if primary.classification == Classification.HISTORICAL_ONLY.value:
        score *= 0.15
        explanation.append("historical_only_penalty")
    for token in (
        "workshop",
        "demo-store",
        "hydrogen-demo",
        "/examples/",
        "tutorial",
        "getting-started",
        "sample-app",
        "starter-template",
    ):
        if token in url_l:
            score *= 0.4
            explanation.append(f"demo_or_workshop_path_penalty:{token}")
            break

    return round(min(1.0, score), 4), explanation


def _impact_hypothesis(obs: Observation) -> str:
    reasons = set(obs.classification_reason_codes or [])
    if "directory_listing_fingerprint" in reasons:
        return (
            "Directory listing may reveal file/layout information; "
            "individual object sensitivity and impact not confirmed."
        )
    if "source_map_with_sources_content" in reasons:
        return (
            "Source map embeds original sources; may disclose application logic or secrets. "
            "Impact not independently verified."
        )
    if "source_map_structure" in reasons:
        return "Source map present; build paths may leak. Sensitive source content not confirmed."
    if "openapi_or_swagger_schema" in reasons:
        return (
            "Public API schema may reveal routes and models; "
            "not proof of broken authorization or data exposure."
        )
    if "git_metadata_exposure" in reasons:
        return (
            "Git metadata exposure may enable further source recovery; "
            "full repository disclosure not demonstrated from this observation alone."
        )
    if obs.classification == Classification.POTENTIALLY_SENSITIVE.value:
        return (
            "Artifact may expose sensitive material; existence/accessibility observed, "
            "security impact not confirmed."
        )
    if obs.classification == Classification.IMPACT_UNPROVEN.value:
        return "Path or content is suggestive; impact remains unproven."
    if obs.classification == Classification.HISTORICAL_ONLY.value:
        return "Historical observation only; current accessibility not established."
    return "No strong impact hypothesis from available evidence."


def _evidence_summary(primary: Observation, group: list[Observation]) -> str:
    parts = [
        f"url={primary.discovered_url}",
        f"status={primary.http_status}",
        f"class={primary.classification}",
        f"reasons={','.join(primary.classification_reason_codes)}",
        f"observations={len(group)}",
        f"fidelity={primary.source_fidelity}",
        f"freshness={primary.freshness}",
    ]
    return "; ".join(parts)