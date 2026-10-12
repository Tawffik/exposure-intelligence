"""
Shadow-mode comparison: baseline pipeline vs baseline + passive provider.

Merges observations, reuses existing classifier/ranker, and reports
incremental candidates without triggering any active target validation.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Optional

from ei.classifier import build_observation_from_fixture
from ei.models import (
    Observation,
    ProviderRunSummary,
    RunReport,
    RunStatus,
    stable_candidate_key,
    utc_now_iso,
)
from ei.pipeline import load_fixture_file, run_pipeline
from ei.providers.github_code_search import (
    PROVIDER_NAME,
    GitHubCodeSearchProvider,
    ProviderCollectResult,
)
from ei.ranker import observations_to_candidates


def _observation_keys(observations: list[Observation]) -> set[str]:
    return {stable_candidate_key(o.discovered_url, o.body_sha256) for o in observations}


def run_shadow_comparison(
    *,
    baseline_records: list[dict[str, Any]],
    provider_result: ProviderCollectResult,
    target_id: str = "shadow-target",
) -> dict[str, Any]:
    """
    Run baseline alone, then baseline+provider, and diff candidate keys.

    Provider failure states are preserved in provider_summaries and must not
    erase baseline candidates.
    """
    baseline_report = run_pipeline(
        baseline_records,
        target_id=target_id,
        provider_name="fixture",
    )

    # Always keep baseline observations even if provider failed
    run_id = str(uuid.uuid4())
    started = utc_now_iso()
    merged_records = list(baseline_records)

    provider_summary = ProviderRunSummary(
        provider=provider_result.provider or PROVIDER_NAME,
        status=provider_result.status,
        started_at=started,
        ended_at=utc_now_iso(),
        records_received=len(provider_result.records),
        records_normalized=0,
        candidates_emitted=0,
        error_summary=provider_result.error_summary,
        coverage_notes=provider_result.coverage_notes,
    )

    provider_observations: list[Observation] = []
    if provider_result.status in (
        RunStatus.COMPLETED_WITH_RESULTS.value,
        RunStatus.PARTIAL.value,
        RunStatus.COMPLETED_ZERO.value,
    ):
        for rec in provider_result.records:
            merged_records.append(rec)
            obs = build_observation_from_fixture(rec, run_id=run_id, target_id=target_id)
            provider_observations.append(obs)
        provider_summary.records_normalized = len(provider_observations)

    merged_report = run_pipeline(
        merged_records,
        target_id=target_id,
        provider_name="fixture+github_code_search",
    )
    # Attach explicit provider summary alongside merged run
    merged_report.provider_summaries = [
        baseline_report.provider_summaries[0] if baseline_report.provider_summaries else ProviderRunSummary(
            provider="fixture", status=baseline_report.status
        ),
        provider_summary,
    ]

    base_keys = _observation_keys(baseline_report.observations)
    merged_keys = _observation_keys(merged_report.observations)
    new_keys = merged_keys - base_keys

    new_candidates = [
        c
        for c in merged_report.candidates
        if stable_candidate_key(c.primary_url, "") in {
            stable_candidate_key(o.discovered_url, "") for o in provider_observations
        }
        or any(
            stable_candidate_key(o.discovered_url, o.body_sha256) in new_keys
            for o in merged_report.observations
            if o.observation_id in c.observation_ids
        )
    ]
    # Simpler novelty: candidates whose primary_url was not in baseline URLs
    baseline_urls = {o.discovered_url for o in baseline_report.observations}
    novel_candidates = [c for c in merged_report.candidates if c.primary_url not in baseline_urls]

    provider_summary.candidates_emitted = len(novel_candidates)

    comparison = {
        "baseline": {
            "status": baseline_report.status,
            "observations": baseline_report.metrics.get("observations", 0),
            "candidates": baseline_report.metrics.get("candidates", 0),
            "potentially_sensitive": baseline_report.metrics.get("potentially_sensitive", 0),
            "noise_or_low": baseline_report.metrics.get("noise_or_low", 0),
        },
        "provider": {
            "name": provider_result.provider or PROVIDER_NAME,
            "status": provider_result.status,
            "records_received": len(provider_result.records),
            "error_summary": provider_result.error_summary,
            "coverage_notes": provider_result.coverage_notes,
            "query": provider_result.query,
            "incomplete_results": provider_result.incomplete_results,
            "raw_total_count": provider_result.raw_total_count,
        },
        "merged": {
            "status": merged_report.status,
            "observations": merged_report.metrics.get("observations", 0),
            "candidates": merged_report.metrics.get("candidates", 0),
            "potentially_sensitive": merged_report.metrics.get("potentially_sensitive", 0),
            "noise_or_low": merged_report.metrics.get("noise_or_low", 0),
        },
        "incremental": {
            "new_observation_keys": len(new_keys),
            "novel_candidate_urls": len(novel_candidates),
            "novel_candidates": [
                {
                    "url": c.primary_url,
                    "classification": c.classification,
                    "sensitivity": c.sensitivity,
                    "confidence": c.confidence,
                    "rank_score": c.rank_score,
                    "impact_hypothesis": c.impact_hypothesis,
                    "source_fidelity": c.source_fidelity,
                }
                for c in novel_candidates
            ],
            "baseline_candidates_retained": baseline_report.metrics.get("candidates", 0),
            "candidate_loss_vs_baseline": max(
                0,
                (baseline_report.metrics.get("candidates", 0) or 0)
                - sum(
                    1
                    for c in merged_report.candidates
                    if c.primary_url in baseline_urls
                ),
            ),
        },
        "shadow_mode": {
            "active_target_validation": False,
            "discovery_mode": "PASSIVE_INDEX",
            "note": "Provider results are public-index leads only; not confirmed exposures.",
        },
    }
    return {
        "comparison": comparison,
        "baseline_report": baseline_report,
        "merged_report": merged_report,
        "provider_result": provider_result,
    }


def run_shadow_from_paths(
    baseline_fixture: Path,
    github_fixture: Optional[Path] = None,
    *,
    target_id: str = "shadow-target",
    live_query: Optional[str] = None,
    allow_live: bool = False,
) -> dict[str, Any]:
    """CLI/helper entry: offline github fixture or optional live query."""
    baseline_records = load_fixture_file(baseline_fixture)
    provider = GitHubCodeSearchProvider()

    if github_fixture is not None:
        provider_result = provider.collect_from_fixture(github_fixture)
    elif allow_live and live_query:
        provider_result = provider.collect_live(live_query)
    else:
        provider_result = ProviderCollectResult(
            status=RunStatus.NOT_CONFIGURED.value,
            error_summary=(
                "No GitHub fixture provided and live mode not enabled. "
                "Pass a recorded search JSON or --live with GITHUB_TOKEN."
            ),
        )

    return run_shadow_comparison(
        baseline_records=baseline_records,
        provider_result=provider_result,
        target_id=target_id,
    )
