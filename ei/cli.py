"""Command-line entry point for Exposure Intelligence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ei import __version__
from ei.pipeline import run_from_fixture_path
from ei.profile import load_profile, validate_profile
from ei.research import run_research
from ei.shadow import run_shadow_from_paths
from ei.store import ResearchStore
from ei.actions_run import run_actions_job


def _print_report_summary(report) -> None:
    summary = {
        "run_id": report.run_id,
        "status": report.status,
        "metrics": report.metrics,
        "candidates": [
            {
                "url": c.primary_url,
                "classification": c.classification,
                "sensitivity": c.sensitivity,
                "confidence": c.confidence,
                "rank_score": c.rank_score,
                "rank_explanation": c.rank_explanation,
                "impact_hypothesis": c.impact_hypothesis,
            }
            for c in report.candidates
        ],
    }
    print(json.dumps(summary, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ei",
        description="Exposure Intelligence — operational information-disclosure research.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run pipeline against a fixture JSON file")
    run_p.add_argument("fixture", type=Path)
    run_p.add_argument("--target-id", default="example-target")
    run_p.add_argument("--provider", default="fixture")
    run_p.add_argument("-o", "--output", type=Path)

    demo_p = sub.add_parser("demo", help="Run built-in example fixture")
    demo_p.add_argument("-o", "--output", type=Path)

    shadow_p = sub.add_parser("shadow", help="Shadow-mode baseline + GitHub fixture/live")
    shadow_p.add_argument("--baseline", type=Path, default=None)
    shadow_p.add_argument("--github-fixture", type=Path, default=None)
    shadow_p.add_argument("--live", action="store_true")
    shadow_p.add_argument("--query", default="filename:.env API_KEY")
    shadow_p.add_argument("--target-id", default="shadow-target")
    shadow_p.add_argument("-o", "--output", type=Path)

    pv = sub.add_parser("profile-validate", help="Validate a program/target profile JSON")
    pv.add_argument("profile", type=Path)

    res = sub.add_parser(
        "research",
        help="Operational run: profile + fixtures/providers → persist → research queue",
    )
    res.add_argument("--profile", type=Path, required=True)
    res.add_argument("--db", type=Path, default=Path("ei_data/research.db"))
    res.add_argument("--fixture", type=Path, default=None, help="Local observation fixture")
    res.add_argument("--github-fixture", type=Path, default=None)
    res.add_argument("--live-github", action="store_true", help="Opt-in live GitHub search")
    res.add_argument("--query", default="filename:.env API_KEY")
    res.add_argument("-o", "--output", type=Path)

    q = sub.add_parser("queue", help="Show latest research queue for a target_id")
    q.add_argument("--db", type=Path, default=Path("ei_data/research.db"))
    q.add_argument("--target-id", required=True)
    q.add_argument("--limit", type=int, default=20)

    hist = sub.add_parser("history", help="List persisted runs for a target_id")
    hist.add_argument("--db", type=Path, default=Path("ei_data/research.db"))
    hist.add_argument("--target-id", required=True)
    hist.add_argument("--limit", type=int, default=20)

    ar = sub.add_parser(
        "actions-run",
        help="Headless Actions job: validate target, research, write report bundle",
    )
    ar.add_argument("--target", required=True, help="Hostname/domain")
    ar.add_argument("--mode", default="passive", choices=["passive", "demo"])
    ar.add_argument("--authorization-status", default="UNKNOWN")
    ar.add_argument("--github-query", default="filename:.env OR filename:.env.example OR extension:map")
    ar.add_argument("--max-results", default="10")
    ar.add_argument("--db", type=Path, default=Path("ei_data/research.db"))
    ar.add_argument("--out", type=Path, default=Path("artifacts"))
    ar.add_argument("--profile", type=Path, default=None)
    ar.add_argument("--commit-sha", default="")
    ar.add_argument("--workflow-run-id", default="")

    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]

    if args.command == "demo":
        fixture = root / "examples" / "sample_observations.json"
        report = run_from_fixture_path(fixture, target_id="demo-target", provider_name="fixture")
        _print_report_summary(report)
        if args.output:
            args.output.write_text(report.to_json(), encoding="utf-8")
        return 0 if report.status.startswith("COMPLETED") else 1

    if args.command == "run":
        if not args.fixture.exists():
            print(f"Fixture not found: {args.fixture}", file=sys.stderr)
            return 2
        report = run_from_fixture_path(
            args.fixture, target_id=args.target_id, provider_name=args.provider
        )
        _print_report_summary(report)
        if args.output:
            args.output.write_text(report.to_json(), encoding="utf-8")
        if report.status in ("ERROR", "NOT_CONFIGURED"):
            return 1
        if report.status in ("PARTIAL", "RATE_LIMITED"):
            return 3
        return 0

    if args.command == "shadow":
        baseline = args.baseline or (root / "examples" / "sample_observations.json")
        gh_fixture = args.github_fixture
        if gh_fixture is None and not args.live:
            gh_fixture = root / "examples" / "github_code_search_sample.json"
        out = run_shadow_from_paths(
            baseline,
            gh_fixture,
            target_id=args.target_id,
            live_query=args.query if args.live else None,
            allow_live=bool(args.live),
        )
        print(json.dumps(out["comparison"], indent=2))
        if args.output:
            args.output.write_text(json.dumps(out["comparison"], indent=2), encoding="utf-8")
        return 0

    if args.command == "profile-validate":
        if not args.profile.exists():
            print(f"Profile not found: {args.profile}", file=sys.stderr)
            return 2
        try:
            profile = load_profile(args.profile)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(json.dumps({"ok": False, "error": str(e)}, indent=2))
            return 2
        v = validate_profile(profile)
        print(json.dumps({"ok": v.ok, "errors": v.errors, "warnings": v.warnings, "profile": profile.to_dict()}, indent=2))
        return 0 if v.ok else 1

    if args.command == "research":
        if not args.profile.exists():
            print(f"Profile not found: {args.profile}", file=sys.stderr)
            return 2
        profile = load_profile(args.profile)
        store = ResearchStore(args.db)
        try:
            result = run_research(
                profile,
                store=store,
                fixture_path=args.fixture,
                github_fixture=args.github_fixture,
                github_live_query=args.query if args.live_github else None,
                allow_live_github=bool(args.live_github),
            )
        finally:
            store.close()
        print(json.dumps(result, indent=2))
        if args.output:
            args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return 0 if result.get("ok") else 1

    if args.command == "queue":
        if not args.db.exists():
            print(json.dumps({"error": f"database not found: {args.db}"}, indent=2))
            return 2
        store = ResearchStore(args.db)
        try:
            items = store.queue_for_target(args.target_id, limit=args.limit)
        finally:
            store.close()
        print(json.dumps({"target_id": args.target_id, "count": len(items), "queue": items}, indent=2))
        return 0

    if args.command == "history":
        if not args.db.exists():
            print(json.dumps({"error": f"database not found: {args.db}"}, indent=2))
            return 2
        store = ResearchStore(args.db)
        try:
            runs = store.list_runs(args.target_id, limit=args.limit)
        finally:
            store.close()
        print(json.dumps({"target_id": args.target_id, "runs": runs}, indent=2))
        return 0


    if args.command == "actions-run":
        result = run_actions_job(
            target=args.target,
            out_dir=args.out,
            db_path=args.db,
            research_mode=args.mode,
            authorization_status=args.authorization_status,
            github_query=args.github_query,
            max_github_results=int(args.max_results) if str(args.max_results).isdigit() else 10,
            profile_path=args.profile,
            commit_sha=args.commit_sha,
            workflow_run_id=args.workflow_run_id,
        )
        # Print compact summary (no secrets)
        public = {
            "ok": result.get("ok", True) if "error" not in result else False,
            "status": result.get("status"),
            "target_host": result.get("target_host"),
            "run_id": result.get("run_id"),
            "data_source_label": result.get("data_source_label"),
            "summary": result.get("summary"),
            "provider_summaries": result.get("provider_summaries"),
            "artifact_paths": result.get("artifact_paths"),
            "error": result.get("error"),
            "details": result.get("details"),
        }
        print(json.dumps(public, indent=2))
        if result.get("error"):
            return 2
        if result.get("status") in ("ERROR",):
            return 1
        if result.get("status") in ("PARTIAL", "RATE_LIMITED", "NOT_CONFIGURED"):
            return 3
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
