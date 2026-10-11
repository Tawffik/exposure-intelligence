"""Runnable pipeline: fixtures → classify → correlate → rank → report."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Optional

from ei.classifier import build_observation_from_fixture
from ei.models import (
    Observation,
    ProviderRunSummary,
    RunReport,
    RunStatus,
    utc_now_iso,
)
from ei.ranker import observations_to_candidates


def load_fixture_file(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "observations" in data:
        return data["observations"]
    if isinstance(data, list):
        return data
    raise ValueError(f"Fixture must be a list or object with 'observations': {path}")


def run_pipeline(
    records: list[dict[str, Any]],
    *,
    target_id: str = "example-target",
    provider_name: str = "fixture",
    inject_error: Optional[str] = None,
    inject_status: Optional[str] = None,
) -> RunReport:
    """
    Execute a complete offline pipeline against in-memory records.

    inject_status overrides the whole-run status (e.g. RATE_LIMITED, ERROR).
    inject_error sets ERROR status with a summary.
    """
    run_id = str(uuid.uuid4())
    started = utc_now_iso()
    report = RunReport(run_id=run_id, started_at=started, target_ids=[target_id])

    if inject_error:
        report.status = RunStatus.ERROR.value
        report.ended_at = utc_now_iso()
        report.provider_summaries.append(
            ProviderRunSummary(
                provider=provider_name,
                status=RunStatus.ERROR.value,
                started_at=started,
                ended_at=report.ended_at,
                error_summary=inject_error,
            )
        )
        report.metrics = {"observations": 0, "candidates": 0, "error": inject_error}
        return report

    if inject_status == RunStatus.NOT_CONFIGURED.value:
        report.status = RunStatus.NOT_CONFIGURED.value
        report.ended_at = utc_now_iso()
        report.provider_summaries.append(
            ProviderRunSummary(
                provider=provider_name,
                status=RunStatus.NOT_CONFIGURED.value,
                started_at=started,
                ended_at=report.ended_at,
                error_summary="Provider credentials or config missing.",
            )
        )
        report.metrics = {"observations": 0, "candidates": 0}
        return report

    if inject_status == RunStatus.RATE_LIMITED.value:
        report.status = RunStatus.RATE_LIMITED.value
        report.ended_at = utc_now_iso()
        report.provider_summaries.append(
            ProviderRunSummary(
                provider=provider_name,
                status=RunStatus.RATE_LIMITED.value,
                started_at=started,
                ended_at=report.ended_at,
                error_summary="Provider rate limit encountered.",
            )
        )
        report.metrics = {"observations": 0, "candidates": 0}
        return report

    if inject_status == RunStatus.SKIPPED_BY_POLICY.value:
        report.status = RunStatus.SKIPPED_BY_POLICY.value
        report.ended_at = utc_now_iso()
        report.provider_summaries.append(
            ProviderRunSummary(
                provider=provider_name,
                status=RunStatus.SKIPPED_BY_POLICY.value,
                started_at=started,
                ended_at=report.ended_at,
                coverage_notes="Active checks disabled by policy.",
            )
        )
        report.metrics = {"observations": 0, "candidates": 0}
        return report

    observations: list[Observation] = []
    for rec in records:
        obs = build_observation_from_fixture(rec, run_id=run_id, target_id=target_id)
        observations.append(obs)

    candidates = observations_to_candidates(observations)
    ended = utc_now_iso()

    if inject_status == RunStatus.PARTIAL.value:
        status = RunStatus.PARTIAL.value
        coverage = "Pagination or budget stopped early (simulated)."
    elif not observations:
        status = RunStatus.COMPLETED_ZERO.value
        coverage = "Provider completed query window; zero records."
    else:
        status = RunStatus.COMPLETED_WITH_RESULTS.value
        coverage = "All fixture records processed."

    summary = ProviderRunSummary(
        provider=provider_name,
        status=status,
        started_at=started,
        ended_at=ended,
        records_received=len(records),
        records_normalized=len(observations),
        candidates_emitted=len(candidates),
        duplicates=sum(1 for c in candidates if c.classification == "DUPLICATE"),
        coverage_notes=coverage,
    )

    report.ended_at = ended
    report.status = status
    report.provider_summaries = [summary]
    report.observations = observations
    report.candidates = candidates
    report.metrics = {
        "observations": len(observations),
        "candidates": len(candidates),
        "potentially_sensitive": sum(
            1 for c in candidates if c.classification == "POTENTIALLY_SENSITIVE"
        ),
        "noise_or_low": sum(
            1
            for c in candidates
            if c.classification
            in {
                "GENERIC_ERROR",
                "SPA_SHELL",
                "EMPTY_RESPONSE",
                "UNREACHABLE",
                "AUTH_REQUIRED",
                "KEYWORD_FALSE_POSITIVE",
                "INTENTIONALLY_PUBLIC",
                "DUPLICATE",
            }
        ),
        "redactions_applied": sum(1 for o in observations if o.redaction_applied),
    }
    return report


def run_from_fixture_path(path: Path, **kwargs: Any) -> RunReport:
    records = load_fixture_file(path)
    return run_pipeline(records, **kwargs)