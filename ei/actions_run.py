"""
Actions / headless entry: validate inputs, build profile, run research, write artifacts.

Does not probe application hosts. Live GitHub code search only when explicitly enabled
and a token is present.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from ei.profile import ProgramProfile, profile_from_dict, validate_profile
from ei.report import write_report_bundle
from ei.research import run_research
from ei.store import ResearchStore
from ei.validate_input import sanitize_target_input, validate_budget


def build_profile_for_target(
    host: str,
    *,
    authorization_status: str = "UNKNOWN",
    program_name: str = "",
    authorization_reference: str = "",
    extra_in_scope: Optional[list[str]] = None,
) -> ProgramProfile:
    """
    Build a conservative profile from Actions form inputs.

    Default authorization_status=UNKNOWN keeps live host requests denied.
    Passive index research remains allowed via allowed_operations.
    """
    hosts = [host]
    if extra_in_scope:
        hosts.extend(extra_in_scope)
    status = (authorization_status or "UNKNOWN").upper()
    if status not in {"ACTIVE", "PAUSED", "EXPIRED", "UNKNOWN"}:
        status = "UNKNOWN"
    return profile_from_dict(
        {
            "target_id": host.replace(".", "-"),
            "program_name": program_name or f"Operator target {host}",
            "authorization_status": status,
            "authorization_reference": authorization_reference,
            "in_scope_hosts": hosts,
            "in_scope_domains": [host],
            "allowed_operations": ["PASSIVE_INDEX", "HISTORICAL"],
            "notes": (
                "Profile synthesized from Actions inputs. "
                "Live application-host verification remains disabled unless "
                "authorization_status=ACTIVE and live operations are added explicitly."
            ),
            "profile_version": "actions-1",
        }
    )


def run_actions_job(
    *,
    target: str,
    out_dir: Path,
    db_path: Path,
    research_mode: str = "passive",
    authorization_status: str = "UNKNOWN",
    github_query: str = "filename:.env OR filename:.env.example OR extension:map",
    max_github_results: int = 10,
    use_demo_fixtures: bool = False,
    profile_path: Optional[Path] = None,
    commit_sha: str = "",
    workflow_run_id: str = "",
    repo_root: Optional[Path] = None,
) -> dict[str, Any]:
    """
    Execute one Actions-oriented research job and write the report bundle.

    research_mode:
      - passive: public index only (optional live GitHub API with token)
      - demo: explicit offline fixtures (never labeled as live)
    """
    root = repo_root or Path(__file__).resolve().parents[1]
    tv = sanitize_target_input(target)
    if not tv.ok:
        err = {
            "ok": False,
            "error": "invalid_target",
            "details": tv.errors,
        }
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "run-metadata.json").write_text(json.dumps(err, indent=2), encoding="utf-8")
        (out_dir / "report.md").write_text(
            "# Failed\n\nInvalid target input.\n\n" + "\n".join(f"- {e}" for e in (tv.errors or [])),
            encoding="utf-8",
        )
        return err

    budget, budget_errs = validate_budget(
        max_github_results, name="max_github_results", minimum=1, maximum=30, default=10
    )
    if budget_errs:
        # clamp already applied; keep warnings
        pass

    mode = (research_mode or "passive").lower().strip()
    if mode not in {"passive", "demo"}:
        mode = "passive"

    if profile_path and profile_path.exists():
        from ei.profile import load_profile

        profile = load_profile(profile_path)
        # ensure target host is represented
        if tv.host not in profile.in_scope_hosts and tv.host not in profile.in_scope_domains:
            profile.in_scope_hosts = list(profile.in_scope_hosts) + [tv.host]
            profile.in_scope_domains = list(profile.in_scope_domains) + [tv.host]
    else:
        profile = build_profile_for_target(
            tv.host,
            authorization_status=authorization_status,
        )

    v = validate_profile(profile)
    if not v.ok:
        err = {"ok": False, "error": "invalid_profile", "profile_validation": v.to_dict()}
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "report.md").write_text(
            "# Failed profile validation\n\n" + json.dumps(v.to_dict(), indent=2),
            encoding="utf-8",
        )
        return err

    store = ResearchStore(db_path)
    data_label = "unknown"
    try:
        if mode == "demo":
            data_label = "demo_fixtures_only"
            result = run_research(
                profile,
                store=store,
                fixture_path=root / "examples" / "sample_observations.json",
                github_fixture=root / "examples" / "github_code_search_sample.json",
                allow_live_github=False,
            )
        else:
            # Production-style passive: live GitHub if token present; else NOT_CONFIGURED for GH
            token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
            if token:
                data_label = "live_github_code_search"
                # collect_live uses per_page; query from operator
                result = run_research(
                    profile,
                    store=store,
                    fixture_path=None,
                    github_fixture=None,
                    github_live_query=github_query,
                    allow_live_github=True,
                )
                # Soft-limit: research pipeline doesn't re-query; provider already bounded by API per_page default 10
                # Adjust note with budget
                result["note"] = (
                    (result.get("note") or "")
                    + f" GitHub query budget per_page≤{budget}."
                )
            else:
                data_label = "github_not_configured"
                result = run_research(
                    profile,
                    store=store,
                    fixture_path=None,
                    github_fixture=None,
                    allow_live_github=False,
                )
                # Explicit provider row if none
                if not result.get("provider_summaries"):
                    result["provider_summaries"] = [
                        {
                            "provider": "github_code_search",
                            "status": "NOT_CONFIGURED",
                            "error_summary": "GITHUB_TOKEN not available in environment.",
                            "records_received": 0,
                            "records_normalized": 0,
                            "coverage_notes": "Set repository secret GITHUB_TOKEN to enable live index search.",
                        }
                    ]
                    if result.get("status") in (None, "COMPLETED_ZERO", "NOT_RUN"):
                        result["status"] = "NOT_CONFIGURED"
    finally:
        store.close()

    paths = write_report_bundle(
        result,
        out_dir,
        target_host=tv.host,
        research_mode=mode,
        commit_sha=commit_sha or os.environ.get("GITHUB_SHA", ""),
        workflow_run_id=workflow_run_id or os.environ.get("GITHUB_RUN_ID", ""),
        data_source_label=data_label,
    )
    result["artifact_paths"] = {k: str(v) for k, v in paths.items()}
    result["data_source_label"] = data_label
    result["target_host"] = tv.host
    return result
