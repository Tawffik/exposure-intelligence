"""
Operational research workflow: profile → collect → classify → persist → compare → queue.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Optional

from ei.classifier import build_observation_from_fixture
from ei.models import (
    Candidate,
    Observation,
    ProviderRunSummary,
    RunReport,
    RunStatus,
    stable_candidate_key,
    utc_now_iso,
)
from ei.pipeline import load_fixture_file, run_pipeline
from ei.profile import ProgramProfile, assess_relevance, live_request_permitted, validate_profile
from ei.providers.github_code_search import GitHubCodeSearchProvider, ProviderCollectResult
from ei.ranker import observations_to_candidates
from ei.store import ResearchStore


def _annotate_relevance(records: list[dict[str, Any]], profile: ProgramProfile) -> list[dict[str, Any]]:
    out = []
    for rec in records:
        r = dict(rec)
        rel = assess_relevance(profile, r.get("url") or "")
        meta = dict(r.get("metadata") or {})
        meta["scope_relevance"] = rel["relevance"]
        meta["scope_reason"] = rel["reason"]
        meta["live_allowed"] = rel["live_allowed"]
        r["metadata"] = meta
        # Do not overwrite IN_SCOPE from fixture; set when UNKNOWN/missing
        if r.get("scope_decision") in (None, "", "UNKNOWN"):
            r["scope_decision"] = rel["relevance"]
        out.append(r)
    return out


def compare_runs(
    current: RunReport,
    previous_keys: set[str],
    previous_url_keys: set[str],
) -> list[dict[str, Any]]:
    """
    Tag each current candidate with change_type relative to previous run keys.
    Absence from current is handled by caller (not_observed list).
    """
    queue: list[dict[str, Any]] = []
    for c in current.candidates:
        url_key = "url:" + (c.primary_url or "").lower()
        if c.stable_key in previous_keys or url_key in previous_url_keys:
            change = "REPEATED"
            if c.classification in ("HISTORICAL_ONLY",):
                change = "HISTORICAL_ONLY"
        else:
            change = "NEW"
        next_step = _suggest_next_step(c)
        queue.append(
            {
                "candidate_id": c.candidate_id,
                "url": c.primary_url,
                "classification": c.classification,
                "sensitivity": c.sensitivity,
                "confidence": c.confidence,
                "rank_score": c.rank_score,
                "change_type": change,
                "impact_hypothesis": c.impact_hypothesis,
                "confidence_rationale": c.confidence_rationale,
                "rank_explanation": c.rank_explanation,
                "evidence_summary": c.evidence_summary,
                "source_fidelity": c.source_fidelity,
                "suggested_next_step": next_step,
                "review_status": c.review_status,
            }
        )
    queue.sort(key=lambda x: (-(x["rank_score"] or 0), x["url"] or ""))
    return queue


def _suggest_next_step(c: Candidate) -> str:
    if c.classification == "POTENTIALLY_SENSITIVE":
        return (
            "Human review of evidence and scope attribution; "
            "bounded current-state check only if profile allows and host is in scope."
        )
    if c.classification == "IMPACT_UNPROVEN":
        return "Gather more content/context; do not treat as confirmed impact."
    if c.classification == "HISTORICAL_ONLY":
        return "Confirm whether artifact is still reachable under authorized methods."
    if c.classification in {
        "SPA_SHELL",
        "GENERIC_ERROR",
        "AUTH_REQUIRED",
        "EMPTY_RESPONSE",
        "INTENTIONALLY_PUBLIC",
        "KEYWORD_FALSE_POSITIVE",
    }:
        return "Low priority noise class; keep for audit, no urgent action."
    return "Retain with uncertainty; request additional evidence if relevant to program."


def run_research(
    profile: ProgramProfile,
    *,
    store: ResearchStore,
    fixture_path: Optional[Path] = None,
    github_fixture: Optional[Path] = None,
    github_live_query: Optional[str] = None,
    allow_live_github: bool = False,
) -> dict[str, Any]:
    """
    End-to-end operational run.

    Collects from local fixture and/or GitHub (fixture or optional live),
    classifies, persists, compares to previous run for the same target_id.
    Never probes application hosts discovered in search results.
    """
    v = validate_profile(profile)
    if not v.ok:
        return {
            "ok": False,
            "profile_validation": v.to_dict(),
            "error": "Invalid program profile",
        }

    all_records: list[dict[str, Any]] = []
    provider_summaries: list[ProviderRunSummary] = []
    started = utc_now_iso()
    run_id = str(uuid.uuid4())

    # --- local / baseline fixture (always optional) ---
    if fixture_path is not None:
        try:
            records = load_fixture_file(fixture_path)
            records = _annotate_relevance(records, profile)
            all_records.extend(records)
            provider_summaries.append(
                ProviderRunSummary(
                    provider="fixture",
                    status=RunStatus.COMPLETED_WITH_RESULTS.value
                    if records
                    else RunStatus.COMPLETED_ZERO.value,
                    started_at=started,
                    ended_at=utc_now_iso(),
                    records_received=len(records),
                    records_normalized=len(records),
                    coverage_notes=f"Loaded {len(records)} fixture record(s).",
                )
            )
        except (OSError, ValueError, json.JSONDecodeError) as e:
            provider_summaries.append(
                ProviderRunSummary(
                    provider="fixture",
                    status=RunStatus.ERROR.value,
                    started_at=started,
                    ended_at=utc_now_iso(),
                    error_summary=str(e),
                )
            )

    # --- GitHub passive provider ---
    gh = GitHubCodeSearchProvider()
    gh_result: Optional[ProviderCollectResult] = None
    if github_fixture is not None:
        gh_result = gh.collect_from_fixture(github_fixture)
    elif allow_live_github and github_live_query:
        if "PASSIVE_INDEX" not in profile.allowed_operations:
            gh_result = ProviderCollectResult(
                status=RunStatus.SKIPPED_BY_POLICY.value,
                error_summary="PASSIVE_INDEX not in profile.allowed_operations.",
                query=github_live_query or "",
            )
        else:
            gh_result = gh.collect_live(github_live_query)
    elif allow_live_github and not github_live_query:
        gh_result = ProviderCollectResult(
            status=RunStatus.ERROR.value,
            error_summary="Live GitHub requested but no query provided.",
        )

    if gh_result is not None:
        if gh_result.status in (
            RunStatus.COMPLETED_WITH_RESULTS.value,
            RunStatus.PARTIAL.value,
        ):
            annotated = _annotate_relevance(gh_result.records, profile)
            all_records.extend(annotated)
        provider_summaries.append(
            ProviderRunSummary(
                provider="github_code_search",
                status=gh_result.status,
                started_at=started,
                ended_at=utc_now_iso(),
                records_received=len(gh_result.records),
                records_normalized=len(gh_result.records)
                if gh_result.status
                in (RunStatus.COMPLETED_WITH_RESULTS.value, RunStatus.PARTIAL.value)
                else 0,
                error_summary=gh_result.error_summary,
                coverage_notes=gh_result.coverage_notes,
            )
        )

    # Pipeline
    report = run_pipeline(
        all_records,
        target_id=profile.target_id,
        provider_name="research",
    )
    report.run_id = run_id
    report.started_at = started
    report.ended_at = utc_now_iso()
    report.provider_summaries = provider_summaries
    # Overall status: prefer worst non-success provider if no observations
    if not report.observations:
        for ps in provider_summaries:
            if ps.status in (
                RunStatus.ERROR.value,
                RunStatus.RATE_LIMITED.value,
                RunStatus.NOT_CONFIGURED.value,
            ):
                report.status = ps.status
                break
        else:
            if any(ps.status == RunStatus.COMPLETED_ZERO.value for ps in provider_summaries):
                report.status = RunStatus.COMPLETED_ZERO.value

    # Cross-run comparison
    prev_id = store.previous_run_id(profile.target_id, run_id)
    prev_keys: set[str] = set()
    prev_urls: set[str] = set()
    if prev_id:
        prev_keys = store.observation_keys_for_run(prev_id)
        # also candidate keys
        prev_keys |= {k for k in store.candidate_keys_for_run(prev_id) if not k.startswith("url:")}
        prev_urls = {k for k in store.candidate_keys_for_run(prev_id) if k.startswith("url:")}

    queue = compare_runs(report, prev_keys, prev_urls)

    # not observed in this run but present previously
    not_observed: list[dict[str, Any]] = []
    if prev_id:
        prev_report = store.load_run_report(prev_id)
        if prev_report:
            current_urls = {c.primary_url for c in report.candidates}
            for pc in prev_report.get("candidates") or []:
                url = pc.get("primary_url")
                if url and url not in current_urls:
                    not_observed.append(
                        {
                            "url": url,
                            "change_type": "NOT_IN_LATEST_RUN",
                            "note": (
                                "Absent from latest run; not proof fixed — provider may have "
                                "failed, been partial, or omitted the record."
                            ),
                            "previous_classification": pc.get("classification"),
                        }
                    )

    # Persist after comparison annotations
    store.save_run(report, profile_version=profile.profile_version)

    new_count = sum(1 for q in queue if q["change_type"] == "NEW")
    repeated = sum(1 for q in queue if q["change_type"] == "REPEATED")

    return {
        "ok": True,
        "profile_validation": v.to_dict(),
        "run_id": run_id,
        "target_id": profile.target_id,
        "status": report.status,
        "metrics": report.metrics,
        "provider_summaries": [p.to_dict() for p in provider_summaries],
        "previous_run_id": prev_id,
        "research_queue": queue,
        "not_in_latest_run": not_observed,
        "summary": {
            "candidates": len(queue),
            "new": new_count,
            "repeated": repeated,
            "not_in_latest_run": len(not_observed),
            "potentially_sensitive": report.metrics.get("potentially_sensitive", 0),
        },
        "live_host_requests": 0,
        "note": "No application-host verification performed; passive/offline only.",
    }
