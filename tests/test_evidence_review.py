"""Evidence-review and classification quality tests."""

from __future__ import annotations

import json
from pathlib import Path

from ei.classifier import classify_observation
from ei.evidence_review import (
    classify_value_shape,
    extract_config_keys,
    review_candidate,
)
from ei.pipeline import load_fixture_file, run_pipeline

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "examples" / "classification_benchmark.json"


def test_value_shapes_never_need_raw_secret():
    assert classify_value_shape("") == "empty"
    assert classify_value_shape("your_api_key_here") == "placeholder"
    assert classify_value_shape("true") == "generic"
    assert classify_value_shape("ghp_abcdefghijklmnopqrstuv") == "secret_like"


def test_extract_keys_omits_values():
    text = "API_KEY=supersecretvalue12345\nDEBUG=true\nEMPTY=\n"
    keys = extract_config_keys(text)
    assert any(k["key"] == "API_KEY" for k in keys)
    assert all("value" not in k for k in keys)
    assert all(set(k.keys()) == {"key", "value_shape"} for k in keys)
    api = next(k for k in keys if k["key"] == "API_KEY")
    assert api["value_shape"] == "secret_like"
    dbg = next(k for k in keys if k["key"] == "DEBUG")
    assert dbg["value_shape"] == "generic"


def test_example_path_not_potentially_sensitive_without_strong_need():
    cls, reasons, conf, rat, sens, fr = classify_observation(
        url="https://github.com/x/y/blob/main/.env.example",
        status=200,
        content_type="text/plain",
        body="API_KEY=your_api_key_here\n",
        discovery_mode="PASSIVE_INDEX",
    )
    assert cls == "IMPACT_UNPROVEN"
    assert "example_or_template_path" in reasons


def test_path_with_secret_pattern_is_potentially_sensitive():
    cls, reasons, conf, rat, sens, fr = classify_observation(
        url="https://example-authorized.test/.env",
        status=200,
        content_type="text/plain",
        body="password=hunter2hunter2\napi_key=abcd1234efgh5678\n",
        discovery_mode="CURRENT_OBSERVATION",
    )
    assert cls == "POTENTIALLY_SENSITIVE"
    assert any(r.startswith("secret_pattern:") for r in reasons)


def test_review_example_is_low_priority():
    r = review_candidate(
        url="https://github.com/x/y/blob/main/.env.example",
        classification="POTENTIALLY_SENSITIVE",
        reason_codes=["sensitive_path_with_content"],
        body_preview_redacted="API_KEY=your_api_key_here",
        discovery_mode="PASSIVE_INDEX",
        target_relationship="INDEX_ONLY",
    )
    assert r["review_decision"] == "LOW_PRIORITY"
    assert r["confirmed_vulnerability"] is False
    assert r["example_or_template_path"] is True


def test_review_content_supported_unconfirmed():
    r = review_candidate(
        url="https://example-authorized.test/.env",
        classification="POTENTIALLY_SENSITIVE",
        reason_codes=["sensitive_path_with_content", "secret_pattern:credential_pattern"],
        body_preview_redacted="API_KEY=ghp_abcdefghijklmnopqrstuvwx",
        discovery_mode="CURRENT_OBSERVATION",
        target_relationship="DIRECT_TARGET_REFERENCE",
    )
    assert r["review_decision"] == "POTENTIAL_EXPOSURE_UNCONFIRMED"
    assert r["evidence_basis"] in {"content_supported", "path_and_snippet"}
    assert r["secret_like_key_count"] >= 1


def test_classification_benchmark_fixture():
    """Labeled positive/negative cases for precision-oriented regression."""
    cases = json.loads(BENCH.read_text(encoding="utf-8"))
    assert len(cases) >= 5
    mismatches = []
    for case in cases:
        cls, reasons, conf, rat, sens, fr = classify_observation(
            url=case["url"],
            status=case.get("status"),
            content_type=case.get("content_type", ""),
            body=case.get("body", ""),
            discovery_mode=case.get("discovery_mode", "FIXTURE"),
        )
        review = review_candidate(
            url=case["url"],
            classification=cls,
            reason_codes=reasons,
            body_preview_redacted=case.get("body", "")[:500],
            discovery_mode=case.get("discovery_mode", ""),
        )
        exp_cls = case.get("expected_classification") or ""
        exp_rev = case.get("expected_review") or ""
        # Ambiguous labels are excluded from hard regression (see ei.benchmark)
        if exp_rev == "AMBIGUOUS" or case.get("ambiguous"):
            continue
        if exp_cls and cls != exp_cls:
            mismatches.append((case["id"], "class", cls, exp_cls, reasons))
        if review["review_decision"] != exp_rev:
            # Soft match between actionable review labels
            if not (
                exp_rev in {"POTENTIAL_EXPOSURE_UNCONFIRMED", "NEEDS_REVIEW"}
                and review["review_decision"]
                in {"POTENTIAL_EXPOSURE_UNCONFIRMED", "NEEDS_REVIEW"}
            ):
                mismatches.append(
                    (case["id"], "review", review["review_decision"], exp_rev, reasons)
                )
    assert mismatches == [], mismatches


def test_ranker_demotes_example_paths():
    records = [
        {
            "url": "https://github.com/o/r/blob/main/.env.example",
            "status": 200,
            "content_type": "text/plain",
            "body": "KEY=your_key_here\n",
            "discovery_mode": "PASSIVE_INDEX",
            "scope_decision": "PUBLIC_INDEX",
        },
        {
            "url": "https://example-authorized.test/.env",
            "status": 200,
            "content_type": "text/plain",
            "body": "password=notaplaceholder12\n",
            "discovery_mode": "CURRENT_OBSERVATION",
            "scope_decision": "IN_SCOPE",
        },
    ]
    report = run_pipeline(records, target_id="bench", provider_name="fixture")
    by_url = {c.primary_url: c for c in report.candidates}
    example = by_url["https://github.com/o/r/blob/main/.env.example"]
    realish = by_url["https://example-authorized.test/.env"]
    assert example.rank_score < realish.rank_score
    assert any("example_template_path_penalty" in x for x in example.rank_explanation)


def test_env_local_example_is_low_priority():
    """Regression: .env.local.example must not stay NEEDS_REVIEW as a secret lead."""
    from ei.evidence_review import EXAMPLE_PATH_RE, review_queue_item
    url = "https://github.com/acme/app/blob/main/.env.local.example"
    assert EXAMPLE_PATH_RE.search(url)
    item = {
        "url": url,
        "classification": "POTENTIALLY_SENSITIVE",
        "classification_reason_codes": [
            "sensitive_path_with_content",
            "secret_pattern:credential_pattern",
        ],
        "confidence_rationale": "Sensitive path and secret-like pattern present",
        "body_preview_redacted": "API_KEY=changeme\nSECRET=xxx",
        "discovery_mode": "PASSIVE_INDEX",
        "target_relationship": "INDEX_ONLY",
    }
    out = review_queue_item(item)
    assert out["review_decision"] == "LOW_PRIORITY"
    assert out.get("example_or_template_path") is True or (out.get("evidence_review") or {}).get("example_or_template_path")


def test_env_integration_example_matched():
    from ei.evidence_review import EXAMPLE_PATH_RE
    assert EXAMPLE_PATH_RE.search(
        "https://github.com/x/y/blob/abc/.env.integration.example"
    )
