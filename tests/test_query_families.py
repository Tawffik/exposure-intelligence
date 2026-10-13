from ei.query_families import (
    select_query_terms,
    org_matches_target,
    brand_tokens_from_host,
    DEFAULT_ACTIONS_TERMS,
)
from ei.providers.github_code_search import build_target_scoped_query_variants


def test_default_terms_cover_bounty_shapes():
    terms = select_query_terms(limit=12)
    assert any(".env" in t for t in terms)
    assert any("map" in t for t in terms)
    assert any("AKIA" in t or "sk_live" in t for t in terms)


def test_variants_are_simple_and_scoped():
    qs = build_target_scoped_query_variants("shopify.com", "", limit=8)
    assert len(qs) >= 4
    assert all(q.startswith("shopify.com ") for q in qs)
    assert not any(" OR " in q for q in qs)


def test_org_brand_match():
    assert org_matches_target("Shopify/hydrogen", "shopify.com") is True
    assert org_matches_target("random/demo", "shopify.com") is False
    assert "gitlab" in brand_tokens_from_host("gitlab.com")
