"""Command-line entry point for Exposure Intelligence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ei import __version__
from ei.pipeline import run_from_fixture_path, run_pipeline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ei",
        description="Exposure Intelligence — offline fixture runner and classifier (MVP).",
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

    args = parser.parse_args(argv)

    if args.command == "demo":
        root = Path(__file__).resolve().parents[1]
        fixture = root / "examples" / "sample_observations.json"
        if not fixture.exists():
            print(f"Demo fixture missing: {fixture}", file=sys.stderr)
            return 2
        report = run_from_fixture_path(fixture, target_id="demo-target", provider_name="fixture")
    elif args.command == "run":
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
    else:
        parser.print_help()
        return 2

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
    print(json.dumps(summary, indent=2 if getattr(args, "pretty", False) or True else None))

    out = getattr(args, "output", None)
    if out:
        out.write_text(report.to_json(), encoding="utf-8")
        print(f"Wrote full report to {out}", file=sys.stderr)

    # Exit codes: 0 success with results or zero; 1 error states; 3 partial/rate-limited
    if report.status in ("ERROR", "NOT_CONFIGURED"):
        return 1
    if report.status in ("PARTIAL", "RATE_LIMITED"):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())