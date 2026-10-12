"""Command-line entry point for Exposure Intelligence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ei import __version__
from ei.pipeline import run_from_fixture_path
from ei.shadow import run_shadow_from_paths


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
        description="Exposure Intelligence — offline fixture runner, classifier, shadow providers.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run pipeline against a fixture JSON file")
    run_p.add_argument("fixture", type=Path, help="Path to fixture JSON")
    run_p.add_argument("--target-id", default="example-target")
    run_p.add_argument("--provider", default="fixture")
    run_p.add_argument("-o", "--output", type=Path, help="Write full JSON report to path")
    run_p.add_argument("--pretty", action="store_true", help="Pretty-print summary to stdout")

    demo_p = sub.add_parser("demo", help="Run built-in example fixture")
    demo_p.add_argument("-o", "--output", type=Path, help="Write full JSON report to path")

    shadow_p = sub.add_parser(
        "shadow",
        help="Shadow-mode: baseline fixture + passive GitHub code-search (offline fixture or optional live)",
    )
    shadow_p.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Baseline observation fixture (default: examples/sample_observations.json)",
    )
    shadow_p.add_argument(
        "--github-fixture",
        type=Path,
        default=None,
        help="Recorded GitHub search/code JSON (offline; preferred)",
    )
    shadow_p.add_argument(
        "--live",
        action="store_true",
        help="Opt-in live GitHub code search (requires GITHUB_TOKEN; no target probing)",
    )
    shadow_p.add_argument(
        "--query",
        default="filename:.env API_KEY",
        help="Live search query (only with --live)",
    )
    shadow_p.add_argument("--target-id", default="shadow-target")
    shadow_p.add_argument("-o", "--output", type=Path, help="Write comparison JSON to path")

    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]

    if args.command == "demo":
        fixture = root / "examples" / "sample_observations.json"
        if not fixture.exists():
            print(f"Demo fixture missing: {fixture}", file=sys.stderr)
            return 2
        report = run_from_fixture_path(fixture, target_id="demo-target", provider_name="fixture")
        _print_report_summary(report)
        if args.output:
            args.output.write_text(report.to_json(), encoding="utf-8")
            print(f"Wrote full report to {args.output}", file=sys.stderr)
        if report.status in ("ERROR", "NOT_CONFIGURED"):
            return 1
        if report.status in ("PARTIAL", "RATE_LIMITED"):
            return 3
        return 0

    if args.command == "run":
        if not args.fixture.exists():
            print(f"Fixture not found: {args.fixture}", file=sys.stderr)
            return 2
        try:
            report = run_from_fixture_path(
                args.fixture,
                target_id=args.target_id,
                provider_name=args.provider,
            )
        except (ValueError, json.JSONDecodeError) as e:
            print(f"Invalid fixture: {e}", file=sys.stderr)
            return 2
        _print_report_summary(report)
        if args.output:
            args.output.write_text(report.to_json(), encoding="utf-8")
            print(f"Wrote full report to {args.output}", file=sys.stderr)
        if report.status in ("ERROR", "NOT_CONFIGURED"):
            return 1
        if report.status in ("PARTIAL", "RATE_LIMITED"):
            return 3
        return 0

    if args.command == "shadow":
        baseline = args.baseline or (root / "examples" / "sample_observations.json")
        gh_fixture = args.github_fixture
        if gh_fixture is None and not args.live:
            # Default offline demo path
            gh_fixture = root / "examples" / "github_code_search_sample.json"
        if not baseline.exists():
            print(f"Baseline fixture not found: {baseline}", file=sys.stderr)
            return 2
        if gh_fixture is not None and not gh_fixture.exists():
            print(f"GitHub fixture not found: {gh_fixture}", file=sys.stderr)
            return 2
        out = run_shadow_from_paths(
            baseline,
            gh_fixture,
            target_id=args.target_id,
            live_query=args.query if args.live else None,
            allow_live=bool(args.live),
        )
        print(json.dumps(out["comparison"], indent=2))
        if args.output:
            payload = {
                "comparison": out["comparison"],
                "merged_status": out["merged_report"].status,
                "baseline_status": out["baseline_report"].status,
            }
            args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            print(f"Wrote comparison to {args.output}", file=sys.stderr)
        prov_status = out["comparison"]["provider"]["status"]
        if prov_status in ("ERROR", "NOT_CONFIGURED") and out["comparison"]["incremental"][
            "novel_candidate_urls"
        ] == 0:
            # Baseline still useful; exit 0 if baseline completed, else reflect provider
            if out["baseline_report"].status in ("COMPLETED_WITH_RESULTS", "COMPLETED_ZERO"):
                return 0
            return 1
        if prov_status in ("PARTIAL", "RATE_LIMITED"):
            return 3
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
