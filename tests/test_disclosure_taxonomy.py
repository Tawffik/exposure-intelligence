from ei.disclosure_taxonomy import classify_disclosure_signal
from ei.query_families import BOUNTY_QUERY_FAMILIES, select_query_terms, all_family_terms


def test_env_class():
    d = classify_disclosure_signal(url="https://github.com/x/y/blob/main/.env.production")
    assert d["disclosure_class"] == "ENV_CONFIG_EXPOSURE"
    assert d["typical_bounty_signal"] == "high"


def test_api_spec_class():
    d = classify_disclosure_signal(url="https://api.example.com/openapi.json")
    assert d["disclosure_class"] == "API_SPEC"


def test_source_map_not_sitemap():
    d = classify_disclosure_signal(url="https://cdn.example.com/static/app.js.map")
    assert d["disclosure_class"] == "SOURCE_MAP"


def test_families_cover_id_surface():
    keys = set(BOUNTY_QUERY_FAMILIES)
    assert {"env_config", "api_specs", "vcs_meta", "diagnostics", "backups_dumps", "source_maps_secrets"} <= keys
    terms = all_family_terms()
    assert any("openapi" in t for t in terms)
    assert any(".env" in t for t in terms)
    assert len(select_query_terms(limit=12)) >= 8
