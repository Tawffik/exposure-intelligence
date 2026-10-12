"""Generate evidence-backed report bundles for Actions / CLI export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from ei.models import utc_now_iso


def write_report_bundle(
    result: dict[str, Any],
    out_dir: Path,
    *,
    target_host: str = "",
    research_mode: str = "passive",
    commit_sha: str = "",
    workflow_run_id: str = "",
    data_source_label: str = "mixed",
) -> dict[str, Path]:
    """
    Write report.md, evidence.json, research-queue.md, run-diff.*, coverage, metadata.
    Returns map of logical name -> path.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}

    summary = result.get("summary") or {}
    queue = result.get("research_queue") or []
    providers = result.get("provider_summaries") or []
    not_in = result.get("not_in_latest_run") or []
    metrics = result.get("metrics") or {}

    # --- run-metadata.json ---
    meta = {
        "schema_version": "1.0",
        "run_id": result.get("run_id"),
        "target_id": result.get("target_id"),
        "target_host": target_host,
        "status": result.get("status"),
        "research_mode": research_mode,
        "commit_sha": commit_sha,
        "workflow_run_id": workflow_run_id,
        "generated_at": utc_now_iso(),
        "data_source_label": data_source_label,
        "summary": summary,
        "previous_run_id": result.get("previous_run_id"),
        "live_host_requests": result.get("live_host_requests", 0),
        "note": result.get("note"),
    }
    p_meta = out_dir / "run-metadata.json"
    p_meta.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    paths["run-metadata.json"] = p_meta

    # --- evidence.json ---
    evidence = {
        "run_id": result.get("run_id"),
        "target_id": result.get("target_id"),
        "provider_summaries": providers,
        "research_queue": queue,
        "not_in_latest_run": not_in,
        "metrics": metrics,
        "profile_validation": result.get("profile_validation"),
    }
    p_ev = out_dir / "evidence.json"
    p_ev.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    paths["evidence.json"] = p_ev

    # --- research-queue.md ---
    rq_lines = [
        "# Research queue",
        "",
        f"Target: `{result.get('target_id')}`  ",
        f"Run: `{result.get('run_id')}`  ",
        f"Mode: `{research_mode}`  ",
        "",
    ]
    if not queue:
        rq_lines.append("_No candidates in this run._")
    for i, item in enumerate(queue[:50], 1):
        rq_lines.extend(
            [
                f"## {i}. {item.get('url', '(no url)')}",
                "",
                f"- **Classification:** {item.get('classification')}",
                f"- **Sensitivity:** {item.get('sensitivity')}",
                f"- **Confidence:** {item.get('confidence')}",
                f"- **Rank:** {item.get('rank_score')}",
                f"- **Change:** {item.get('change_type')}",
                f"- **Source fidelity:** {item.get('source_fidelity')}",
                f"- **Hypothesis:** {item.get('impact_hypothesis')}",
                f"- **Evidence:** {item.get('evidence_summary')}",
                f"- **Next step:** {item.get('suggested_next_step')}",
                "",
                "> Public-index / passive leads are **not** confirmed production findings.",
                "",
            ]
        )
    p_rq = out_dir / "research-queue.md"
    p_rq.write_text("\n".join(rq_lines), encoding="utf-8")
    paths["research-queue.md"] = p_rq

    # --- run-diff ---
    new_c = [q for q in queue if q.get("change_type") == "NEW"]
    rep_c = [q for q in queue if q.get("change_type") == "REPEATED"]
    diff = {
        "previous_run_id": result.get("previous_run_id"),
        "new": [{"url": x.get("url"), "classification": x.get("classification")} for x in new_c],
        "repeated": len(rep_c),
        "not_in_latest_run": not_in,
        "note": (
            "NOT_IN_LATEST_RUN means absent from this run only — not proof of fix. "
            if not_in
            else "No prior-run absences recorded."
        ),
        "history_available": bool(result.get("previous_run_id")),
    }
    p_dj = out_dir / "run-diff.json"
    p_dj.write_text(json.dumps(diff, indent=2), encoding="utf-8")
    paths["run-diff.json"] = p_dj

    diff_md = [
        "# Run diff",
        "",
        f"Previous run: `{result.get('previous_run_id') or 'none (first run or history unavailable)'}`",
        "",
        f"- New candidates: **{len(new_c)}**",
        f"- Repeated: **{len(rep_c)}**",
        f"- Not in latest run: **{len(not_in)}**",
        "",
        diff["note"],
        "",
    ]
    if new_c:
        diff_md.append("## New")
        for x in new_c[:30]:
            diff_md.append(f"- `{x.get('url')}` — {x.get('classification')}")
        diff_md.append("")
    p_dm = out_dir / "run-diff.md"
    p_dm.write_text("\n".join(diff_md), encoding="utf-8")
    paths["run-diff.md"] = p_dm

    # --- coverage-and-errors.md ---
    cov = [
        "# Coverage and errors",
        "",
        f"Overall status: **{result.get('status')}**",
        f"Data source label: **{data_source_label}**",
        "",
        "## Providers",
        "",
    ]
    if not providers:
        cov.append("_No provider summaries recorded._")
    for ps in providers:
        cov.extend(
            [
                f"### {ps.get('provider')}",
                f"- Status: `{ps.get('status')}`",
                f"- Records received: {ps.get('records_received')}",
                f"- Normalized: {ps.get('records_normalized')}",
                f"- Error: {ps.get('error_summary') or '(none)'}",
                f"- Coverage: {ps.get('coverage_notes') or '(none)'}",
                "",
            ]
        )
    cov.extend(
        [
            "## Important",
            "",
            "- `COMPLETED_ZERO` means the provider finished and found nothing — not a failure.",
            "- `NOT_CONFIGURED` / `RATE_LIMITED` / `ERROR` / `PARTIAL` are not clean empty success.",
            "- Missing coverage is not evidence that a target is safe.",
            f"- Live application-host requests this run: **{result.get('live_host_requests', 0)}**",
            "",
        ]
    )
    p_cov = out_dir / "coverage-and-errors.md"
    p_cov.write_text("\n".join(cov), encoding="utf-8")
    paths["coverage-and-errors.md"] = p_cov

    # --- report.md ---
    top = queue[:10]
    report_lines = [
        "# Exposure Intelligence — Research Report",
        "",
        f"- **Target ID:** `{result.get('target_id')}`",
        f"- **Target host (operator input):** `{target_host or '(n/a)'}`",
        f"- **Run ID:** `{result.get('run_id')}`",
        f"- **Status:** `{result.get('status')}`",
        f"- **Mode:** `{research_mode}`",
        f"- **Commit:** `{commit_sha or 'unknown'}`",
        f"- **Workflow run:** `{workflow_run_id or 'local'}`",
        f"- **Generated:** {meta['generated_at']}",
        f"- **Data sources:** `{data_source_label}`",
        "",
        "## Executive summary",
        "",
        f"- Candidates: **{summary.get('candidates', 0)}**",
        f"- New: **{summary.get('new', 0)}**",
        f"- Repeated: **{summary.get('repeated', 0)}**",
        f"- Potentially sensitive (classifier): **{summary.get('potentially_sensitive', 0)}**",
        f"- Not in latest run: **{summary.get('not_in_latest_run', 0)}**",
        "",
        "Public GitHub / index leads are **research leads**, not confirmed production vulnerabilities.",
        "Live verification was "
        + (
            "**not performed** against application hosts."
            if not result.get("live_host_requests")
            else "performed (see coverage)."
        ),
        "",
        "## Highest-priority candidates",
        "",
    ]
    if not top:
        report_lines.append("_None._")
    for i, item in enumerate(top, 1):
        report_lines.append(
            f"{i}. `{item.get('url')}` — {item.get('classification')} "
            f"(rank {item.get('rank_score')}, {item.get('change_type')})"
        )
    report_lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- Classifier accuracy is fixture-validated, not a production guarantee.",
            "- Cross-run history depends on restored SQLite/cache; may be first-run if unavailable.",
            "- Index presence ≠ current production exposure.",
            f"- Profile validation: {json.dumps(result.get('profile_validation') or {})}",
            "",
            "## Artifacts in this bundle",
            "",
            "- `report.md` (this file)",
            "- `evidence.json`",
            "- `research-queue.md`",
            "- `run-diff.json` / `run-diff.md`",
            "- `coverage-and-errors.md`",
            "- `run-metadata.json`",
            "",
        ]
    )
    p_rep = out_dir / "report.md"
    p_rep.write_text("\n".join(report_lines), encoding="utf-8")
    paths["report.md"] = p_rep

    # full result snapshot (redaction already applied upstream in observations)
    p_full = out_dir / "research-result.json"
    p_full.write_text(json.dumps(result, indent=2), encoding="utf-8")
    paths["research-result.json"] = p_full

    return paths
