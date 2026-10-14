from ei.models import SECRET_PATTERNS
from ei.evidence_review import EXAMPLE_PATH_RE
from ei.query_families import BOUNTY_QUERY_FAMILIES


def test_github_pat_and_whsec_patterns():
    labels = {lab for _, lab in SECRET_PATTERNS}
    assert "github_fine_grained_pat" in labels
    assert "stripe_webhook_secret" in labels
    assert "npm_token" in labels


def test_env_audit_path_is_example_like():
    assert EXAMPLE_PATH_RE.search("https://github.com/a/b/.env.audit.md")


def test_hunter_family_has_github_pat():
    terms = " ".join(BOUNTY_QUERY_FAMILIES.get("hunter_github_dorks") or [])
    assert "github_pat_" in terms
    assert "whsec_" in terms
