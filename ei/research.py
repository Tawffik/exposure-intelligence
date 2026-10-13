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
from ei.providers.base import ProviderCollectResult
from ei.providers.cdx import CDXProvider
from ei.query_families import select_query_terms
from ei.providers.github_code_search import (
    GitHubCodeSearchProvider,
    build_target_scoped_query_variants,
)
from ei.providers.urlscan import URLScanProvider
from ei.evidence_review import review_queue_item
from ei.candidate_state import attach_states
from ei.metrics import compute_run_metrics
from ei.probe import collect_probes
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
        # Provider may already set target_relationship (e.g. GitHub index)
        if "target_relationship" not in meta:
            # Map host scope labels to relationship vocabulary
            mapping = {
                "IN_SCOPE": "DIRECT_TARGET_REFERENCE",
                "OUT_OF_SCOPE": "OUT_OF_SCOPE",
                "PUBLIC_INDEX": "INDEX_ONLY",
                "UNATTRIBUTED": "UNATTRIBUTED",
                "UNKNOWN": "UNATTRIBUTED",
            }
            meta["target_relationship"] = mapping.get(rel["relevance"], "UNATTRIBUTED")
            meta["target_relationship_rationale"] = rel["reason"]
        # For PUBLIC_INDEX hosts, never elevate scope_decision to IN_SCOPE
        r["metadata"] = meta
        if r.get("scope_decision") in (None, "", "UNKNOWN"):
            r["scope_decision"] = rel["relevance"]
        out.append(r)
    return out


def compare_runs(
    current: RunReport,
    previous_keys: set[str],
    previous_url_keys: set[str],
    *,
    baseline_available: bool = True,
) -> list[dict[str, Any]]:
    """
    Tag each current candidate with change_type relative to previous run keys.
    When baseline_available is False (no prior compatible run), use FIRST_SEEN
    instead of NEW — first observation is not proven novelty vs a prior success.
    """
    queue: list[dict[str, Any]] = []
    for c in current.candidates:
        url_key = "url:" + (c.primary_url or "").lower()
        if c.stable_key in previous_keys or url_key in previous_url_keys:
            change = "REPEATED"
            if c.classification in ("HISTORICAL_ONLY",):
                change = "HISTORICAL_ONLY"
        elif not baseline_available:
            change = "FIRST_SEEN"
        else:
            change = "NEW"
        next_step = _suggest_next_step(c)
        item = {
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
            "classification_reason_codes": list(
                getattr(c, "classification_reason_codes", None) or []
            ),
            "target_relationship": getattr(c, "target_relationship", "") or "",
            "scope_decision": getattr(c, "scope_decision", "") or "",
            "discovery_mode": getattr(c, "discovery_mode", "") or "",
        }
        # Prefer reason codes from primary observation via evidence_summary parse fallback
        queue.append(review_queue_item(item))
    # Prefer actionable reviews; push historical/empty shells to the bottom
    _rev_w = {
        "POTENTIAL_EXPOSURE_UNCONFIRMED": 3,
        "NEEDS_REVIEW": 2,
        "LOW_PRIORITY": 0,
    }
    _noise_cls = {"EMPTY_RESPONSE", "HISTORICAL_ONLY", "SPA_SHELL", "GENERIC_ERROR"}
    queue.sort(
        key=lambda x: (
            1 if (x.get("classification") or "") in _noise_cls else 0,
            -_rev_w.get(x.get("review_decision") or "", 1),
            -(x["rank_score"] or 0),
            x["url"] or "",
        )
    )
    return attach_states(queue)


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
    urlscan_fixture: Optional[Path] = None,
    allow_live_urlscan: bool = False,
    cdx_fixture: Optional[Path] = None,
    allow_live_cdx: bool = False,
    max_results: int = 10,
    target_host: str = "",
    research_mode: str = "",
    enable_probes: bool = False,
    probe_budget: int = 5,
) -> dict[str, Any]:
    """
    End-to-end operational run.

    Collects from local fixture and/or passive providers (GitHub, URLScan, CDX)
    via fixture or optional live public APIs. Classifies, persists, compares
    to previous run for the same target_id and research_mode.
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
        gh_result = gh.collect_from_fixture(github_fixture, target_host=target_host or (profile.in_scope_hosts[0] if profile.in_scope_hosts else ""))
    elif allow_live_github and github_live_query:
        if "PASSIVE_INDEX" not in profile.allowed_operations:
            gh_result = ProviderCollectResult(
                status=RunStatus.SKIPPED_BY_POLICY.value,
                error_summary="PASSIVE_INDEX not in profile.allowed_operations.",
                query=github_live_query or "",
            )
        else:
            host_for_q = target_host or (profile.in_scope_hosts[0] if profile.in_scope_hosts else "")
            if host_for_q:
                gq = github_live_query or ""
                if gq.lower().startswith("family:") or not gq.strip():
                    fam = gq.split(":", 1)[1].strip() if ":" in gq else "all"
                    terms = select_query_terms(family=fam or "all", limit=max(1, min(int(max_results), 16)))
                    variants = [f"{host_for_q} {term}" for term in terms]
                else:
                    variants = build_target_scoped_query_variants(host_for_q, gq, limit=8)
                gh_result = gh.collect_live_multi(
                    variants,
                    per_page=max(1, min(int(max_results), 40)),
                    max_total=max(1, min(int(max_results), 40)),
                    target_host=host_for_q,
                )
            else:
                gh_result = gh.collect_live(
                    github_live_query or "",
                    per_page=max(1, min(int(max_results), 40)),
                )
    elif allow_live_github and not github_live_query:
        gh_result = ProviderCollectResult(
            status=RunStatus.ERROR.value,
            error_summary="Live GitHub requested but no query provided.",
        )

    def _merge_provider(result: Optional[ProviderCollectResult], name: str) -> None:
        if result is None:
            return
        if result.status in (
            RunStatus.COMPLETED_WITH_RESULTS.value,
            RunStatus.PARTIAL.value,
        ):
            limited = list(result.records)[: max(1, min(int(max_results), 40))]
            if len(result.records) > len(limited):
                result.coverage_notes = (
                    (result.coverage_notes or "")
                    + f" Truncated to max_results={len(limited)} (had {len(result.records)})."
                )
            annotated = _annotate_relevance(limited, profile)
            all_records.extend(annotated)
        provider_summaries.append(
            ProviderRunSummary(
                provider=name,
                status=result.status,
                started_at=started,
                ended_at=utc_now_iso(),
                records_received=len(result.records),
                records_normalized=min(len(result.records), max(1, min(int(max_results), 40)))
                if result.status
                in (
                    RunStatus.COMPLETED_WITH_RESULTS.value,
                    RunStatus.PARTIAL.value,
                )
                else 0,
                error_summary=result.error_summary or "",
                coverage_notes=result.coverage_notes or "",
            )
        )

    _merge_provider(gh_result, "github_code_search")

    # --- URLScan passive provider ---
    us_result: Optional[ProviderCollectResult] = None
    host_for_q = target_host or (profile.in_scope_hosts[0] if profile.in_scope_hosts else "")
    if urlscan_fixture is not None:
        us_result = URLScanProvider().collect_from_fixture(
            urlscan_fixture, target_host=host_for_q, limit=max_results
        )
    elif allow_live_urlscan:
        if "PASSIVE_INDEX" not in profile.allowed_operations:
            us_result = ProviderCollectResult(
                status=RunStatus.SKIPPED_BY_POLICY.value,
                error_summary="PASSIVE_INDEX not in profile.allowed_operations.",
                provider="urlscan",
            )
        elif not host_for_q:
            us_result = ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary="URLScan live requires target_host.",
                provider="urlscan",
            )
        else:
            try:
                us_result = URLScanProvider().collect_live(host_for_q, size=max_results)
            except Exception as e:  # noqa: BLE001 — provider must not crash research
                us_result = ProviderCollectResult(
                    status=RunStatus.ERROR.value,
                    error_summary=f"urlscan unhandled: {type(e).__name__}: {e}"[:400],
                    provider="urlscan",
                )
    _merge_provider(us_result, "urlscan")

    # --- Internet Archive CDX historical provider ---
    cdx_result: Optional[ProviderCollectResult] = None
    if cdx_fixture is not None:
        cdx_result = CDXProvider().collect_from_fixture(
            cdx_fixture, target_host=host_for_q, limit=max_results
        )
    elif allow_live_cdx:
        if "HISTORICAL" not in profile.allowed_operations and "PASSIVE_INDEX" not in profile.allowed_operations:
            cdx_result = ProviderCollectResult(
                status=RunStatus.SKIPPED_BY_POLICY.value,
                error_summary="HISTORICAL/PASSIVE_INDEX not in profile.allowed_operations.",
                provider="internet_archive_cdx",
            )
        elif not host_for_q:
            cdx_result = ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary="CDX live requires target_host.",
                provider="internet_archive_cdx",
            )
        else:
            try:
                cdx_result = CDXProvider().collect_live(host_for_q, limit=max_results)
            except Exception as e:  # noqa: BLE001
                cdx_result = ProviderCollectResult(
                    status=RunStatus.ERROR.value,
                    error_summary=f"cdx unhandled: {type(e).__name__}: {e}"[:400],
                    provider="internet_archive_cdx",
                )
    _merge_provider(cdx_result, "internet_archive_cdx")

    # --- Bounded current-state probes (fail-closed; ACTIVE only) ---
    if enable_probes:
        candidate_urls = [r.get("url") or "" for r in all_records]
        # Prefer same-host path variants from historical/index leads only if in scope
        probe_result = collect_probes(
            profile,
            candidate_urls,
            budget=max(0, min(int(probe_budget), 20)),
            prefer_head=True,
        )
        _merge_provider(probe_result, "current_state_probe")
        live_reqs = len(probe_result.actual_queries or []) if probe_result else 0
    else:
        live_reqs = 0

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
    # Overall status must reflect provider coverage honesty (charter §6).
    # Success from one provider must not hide ERROR/PARTIAL from another required source.
    _fail = {RunStatus.ERROR.value, RunStatus.RATE_LIMITED.value}
    _partial_markers = {RunStatus.PARTIAL.value, RunStatus.NOT_CONFIGURED.value}
    has_obs = bool(report.observations)
    any_fail = any(ps.status in _fail for ps in provider_summaries)
    any_partial = any(ps.status in _partial_markers for ps in provider_summaries)
    any_results = any(
        ps.status in (RunStatus.COMPLETED_WITH_RESULTS.value, RunStatus.PARTIAL.value)
        and (ps.records_normalized or 0) > 0
        for ps in provider_summaries
    )
    if has_obs or any_results:
        if any_fail or any_partial:
            report.status = RunStatus.PARTIAL.value
        else:
            report.status = RunStatus.COMPLETED_WITH_RESULTS.value
    else:
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

    # Cross-run comparison — only against a compatible research_mode
    mode_key = (research_mode or "").strip().lower()
    prev_id = store.previous_run_id(
        profile.target_id, run_id, research_mode=mode_key or None
    )
    prev_keys: set[str] = set()
    prev_urls: set[str] = set()
    history_note = ""
    if mode_key and prev_id is None:
        history_note = (
            f"No prior run with research_mode={mode_key!r}; cross-mode history "
            "is not compared (demo fixtures must not appear as missing after a "
            "passive live run)."
        )
    if prev_id:
        prev_keys = store.observation_keys_for_run(prev_id)
        prev_keys |= {k for k in store.candidate_keys_for_run(prev_id) if not k.startswith("url:")}
        prev_urls = {k for k in store.candidate_keys_for_run(prev_id) if k.startswith("url:")}

    queue = compare_runs(report, prev_keys, prev_urls, baseline_available=bool(prev_id))

    # not observed in this run but present previously (compatible mode only)
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
                                "Absent from latest compatible run; not proof fixed — "
                                "provider may have failed, been partial, or omitted the record."
                            ),
                            "previous_classification": pc.get("classification"),
                        }
                    )

    # Persist after comparison annotations
    store.save_run(
        report,
        profile_version=profile.profile_version,
        research_mode=mode_key,
    )

    new_count = sum(1 for q in queue if q["change_type"] == "NEW")
    first_seen = sum(1 for q in queue if q["change_type"] == "FIRST_SEEN")
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
        "research_mode": mode_key,
        "history_compatibility": (
            "same_mode" if prev_id else ("no_compatible_prior" if mode_key else "unspecified_mode")
        ),
        "research_queue": queue,
        "yield_metrics": compute_run_metrics({"research_queue": queue, "provider_summaries": [p.to_dict() for p in provider_summaries], "status": report.status, "data_source_label": "", "live_host_requests": live_reqs if enable_probes else 0}),
        "not_in_latest_run": not_observed,
        "summary": {
            "candidates": len(queue),
            "new": new_count,
            "first_seen": first_seen,
            "baseline_available": bool(prev_id),
            "repeated": repeated,
            "not_in_latest_run": len(not_observed),
            "potentially_sensitive": report.metrics.get("potentially_sensitive", 0),
        },
        "live_host_requests": live_reqs if enable_probes else 0,
        "note": (
            "No application-host verification performed; passive/offline only. "
            + history_note
        ).strip(),
    }
