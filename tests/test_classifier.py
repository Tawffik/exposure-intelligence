"""Classifier unit tests against positive and negative fixtures."""

from ei.classifier import classify_observation
from ei.models import Classification, DiscoveryMode


def test_archive_zip_is_potentially_sensitive():
    c, reasons, conf, _, sens, fresh = classify_observation(
        url="https://t.example/backup.zip",
        status=200,
        content_type="application/zip",
        body="PK\x03\x04data",
        discovery_mode=DiscoveryMode.CURRENT_OBSERVATION.value,
    )
    assert c == Classification.POTENTIALLY_SENSITIVE.value
    assert conf >= 0.7
    assert sens in ("HIGH", "CRITICAL")
    assert fresh == "CURRENT"


def test_spa_shell_not_exposure():
    c, reasons, conf, _, sens, _ = classify_observation(
        url="https://t.example/",
        status=200,
        content_type="text/html",
        body='<div id="root"></div>You need to enable JavaScript',
    )
    assert c == Classification.SPA_SHELL.value
    assert sens == "NONE"


def test_auth_required_status():
    c, *_ = classify_observation(url="https://t.example/x", status=401, body="")
    assert c == Classification.AUTH_REQUIRED.value


def test_empty_body():
    c, *_ = classify_observation(url="https://t.example/e", status=200, body="")
    assert c == Classification.EMPTY_RESPONSE.value


def test_historical_404():
    c, reasons, _, _, _, fresh = classify_observation(
        url="https://t.example/old",
        status=404,
        body="gone",
        discovery_mode=DiscoveryMode.HISTORICAL.value,
    )
    assert c == Classification.HISTORICAL_ONLY.value
    assert fresh == "HISTORICAL"


def test_trace_page():
    c, reasons, _, _, sens, _ = classify_observation(
        url="https://t.example/trace.axd",
        status=200,
        content_type="text/html",
        body="Application Trace Request Details",
    )
    assert c == Classification.POTENTIALLY_SENSITIVE.value
    assert "diagnostic_trace_page" in reasons
    assert sens == "HIGH"


def test_ai_inference_not_observation():
    c, reasons, conf, _, _, _ = classify_observation(
        url="https://t.example/x",
        status=200,
        body="maybe sensitive",
        source_fidelity="AI_INFERENCE",
    )
    assert c == Classification.COPIED_RESEARCH.value
    assert conf < 0.5


def test_keyword_false_positive():
    c, reasons, _, _, _, _ = classify_observation(
        url="https://t.example/config.yml",
        status=200,
        content_type="text/html",
        body="<html><body>ok</body></html>",
    )
    assert c == Classification.KEYWORD_FALSE_POSITIVE.value


def test_secret_pattern_redaction_path():
    c, reasons, _, _, sens, _ = classify_observation(
        url="https://t.example/.env",
        status=200,
        content_type="text/plain",
        body="API_KEY=supersecretvalue12345\n",
    )
    assert c == Classification.POTENTIALLY_SENSITIVE.value
    assert any("secret_pattern" in r for r in reasons)
    assert sens == "HIGH"


def test_duplicate_flag():
    c, reasons, conf, _, _, _ = classify_observation(
        url="https://t.example/x", status=200, body="a", is_duplicate=True
    )
    assert c == Classification.DUPLICATE.value
    assert conf > 0.9


def test_waf_page():
    c, reasons, _, _, _, _ = classify_observation(
        url="https://t.example/",
        status=403,
        content_type="text/html",
        body="Attention Required! | Cloudflare",
    )
    # 403 takes precedence as AUTH_REQUIRED in current logic
    assert c in (Classification.AUTH_REQUIRED.value, Classification.GENERIC_ERROR.value)


def test_public_html():
    c, *_ = classify_observation(
        url="https://t.example/about",
        status=200,
        content_type="text/html",
        body="<html><body><h1>About</h1></body></html>",
    )
    assert c == Classification.INTENTIONALLY_PUBLIC.value