from ei.optional_secret_verify import verify_github_repo


def test_skipped_by_policy_default():
    r = verify_github_repo(repo_full_name="acme/app", enable=False)
    assert r["status"] == "SKIPPED_BY_POLICY"
    assert r["finding_count"] == 0


def test_not_configured_when_enabled_without_binary(monkeypatch):
    monkeypatch.setattr("ei.optional_secret_verify.trufflehog_available", lambda: False)
    r = verify_github_repo(repo_full_name="acme/app", enable=True)
    assert r["status"] == "NOT_CONFIGURED"


def test_bad_repo_name():
    r = verify_github_repo(repo_full_name="noscale", enable=True)
    assert r["status"] == "ERROR"
