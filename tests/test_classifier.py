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
    # 403+WAF body -> GENERIC_ERROR; empty 403 may still be AUTH_REQUIRED
    assert c == Classification.GENERIC_ERROR.value
    assert "waf_or_block_page" in reasons


def test_public_html():
    c, *_ = classify_observation(
        url="https://t.example/about",
        status=200,
        content_type="text/html",
        body="<html><body><h1>About</h1></body></html>",
    )
    assert c == Classification.INTENTIONALLY_PUBLIC.value


def test_directory_listing_not_public_noise():
    """Regression: directory listings must not be INTENTIONALLY_PUBLIC / noise."""
    c, reasons, conf, _, sens, _ = classify_observation(
        url="https://t.example/files/",
        status=200,
        content_type="text/html",
        body='<title>Index of /files/</title><h1>Index of /files/</h1><a href="backup.zip">backup.zip</a>',
    )
    assert c == Classification.POTENTIALLY_SENSITIVE.value
    assert "directory_listing_fingerprint" in reasons
    assert c != Classification.INTENTIONALLY_PUBLIC.value
    assert sens in ("MEDIUM", "HIGH")
    assert conf >= 0.7


def test_source_map_with_sources_content():
    body = (
        '{"version":3,"file":"app.js","sources":["webpack:///src/app.js"],'
        '"mappings":"AAAA","sourcesContent":["const x=1"]}'
    )
    c, reasons, conf, _, sens, _ = classify_observation(
        url="https://t.example/static/app.js.map",
        status=200,
        content_type="application/json",
        body=body,
    )
    assert c == Classification.POTENTIALLY_SENSITIVE.value
    assert "source_map_with_sources_content" in reasons
    assert sens == "HIGH"
    assert conf >= 0.8


def test_source_map_without_sources_content_retained():
    body = '{"version":3,"file":"vendor.js","sources":["a.js"],"mappings":"AAAA"}'
    c, reasons, conf, _, sens, _ = classify_observation(
        url="https://t.example/static/vendor.js.map",
        status=200,
        content_type="application/json",
        body=body,
    )
    assert c == Classification.IMPACT_UNPROVEN.value
    assert "source_map_structure" in reasons
    assert sens == "MEDIUM"
    assert conf >= 0.6


def test_openapi_schema_is_lead_not_noise():
    body = '{"openapi":"3.0.0","info":{"title":"API"},"paths":{"/x":{"get":{}}}}'
    c, reasons, conf, _, sens, _ = classify_observation(
        url="https://t.example/openapi.json",
        status=200,
        content_type="application/json",
        body=body,
    )
    assert c == Classification.IMPACT_UNPROVEN.value
    assert "openapi_or_swagger_schema" in reasons
    assert sens == "MEDIUM"


def test_git_head_exposure():
    c, reasons, conf, _, sens, _ = classify_observation(
        url="https://t.example/.git/HEAD",
        status=200,
        content_type="text/plain",
        body="ref: refs/heads/main\n",
    )
    assert c == Classification.POTENTIALLY_SENSITIVE.value
    assert "git_metadata_exposure" in reasons
    assert sens == "HIGH"


def test_benign_json_still_unclassified():
    """Counterexample: ordinary JSON must not become source-map or OpenAPI."""
    c, reasons, _, _, _, _ = classify_observation(
        url="https://t.example/api/health",
        status=200,
        content_type="application/json",
        body='{"status":"ok","uptime":12}',
    )
    assert c == Classification.IMPACT_UNPROVEN.value
    assert "json_response_unclassified" in reasons
    assert "source_map_structure" not in reasons
    assert "openapi_or_swagger_schema" not in reasons

def test_403_cloudflare_is_not_auth_required():
    """403 + Cloudflare block page must not be labeled pure AUTH_REQUIRED."""
    from ei.classifier import classify_observation
    cls, reasons, conf, rat, sens, fr = classify_observation(
        url="https://example.com/admin",
        status=403,
        content_type="text/html",
        body="<html><title>Attention Required! | Cloudflare</title><p>Ray ID</p></html>",
        discovery_mode="FIXTURE",
    )
    assert cls == "GENERIC_ERROR"
    assert "waf_or_block_page" in reasons
    assert "http_auth_status" not in reasons or "waf_or_block_page" in reasons


def test_401_with_login_form_is_auth_required():
    from ei.classifier import classify_observation
    cls, reasons, conf, rat, sens, fr = classify_observation(
        url="https://example.com/login",
        status=401,
        content_type="text/html",
        body='<form action="/signin"><input name="password" type="password"></form>',
        discovery_mode="FIXTURE",
    )
    assert cls == "AUTH_REQUIRED"
    assert "login_form_markers" in reasons


def test_403_empty_body_auth_status_only():
    from ei.classifier import classify_observation
    cls, reasons, conf, rat, sens, fr = classify_observation(
        url="https://example.com/secret",
        status=403,
        content_type="text/plain",
        body="",
        discovery_mode="FIXTURE",
    )
    assert cls == "AUTH_REQUIRED"
    assert "empty_body" in reasons
