"""
Bounty-oriented passive query families.

Sources (hypothesis-backed, not guarantees of payout):
- Notion Information Disclosure Research Lab (backup, historical, source maps, diagnostics)
- Public writeups: .env/config exposure, source maps, wp-config, git metadata
- GitHub code-search dork practice: filename/extension/path qualifiers + host AND

Each family is a list of simple terms (no OR groups) for GitHub code search.
Callers AND the selected target host: "{host} {term}".
"""

from __future__ import annotations

from typing import Any

# Ordered by expected useful-lead density for info-disclosure programs
BOUNTY_QUERY_FAMILIES: dict[str, list[str]] = {
    # Notion H1.1 / Case A — deployment & config artifacts
    "env_config": [
        "filename:.env",
        "filename:.env.local",
        "filename:.env.production",
        "filename:.env.staging",
        "filename:.env.backup",
        "filename:.env.old",
        "filename:wp-config.php",
        "filename:appsettings.json",
        "filename:credentials",
        "filename:.git-credentials",
        "filename:.npmrc",
        "filename:.dockercfg",
    ],
    # Notion Case B/C style + build artifacts — source maps & secrets presence
    "source_maps_secrets": [
        "extension:map",
        "filename:sourcemap",
        "AKIA",
        "sk_live_",
        "ghp_",
        "BEGIN RSA PRIVATE KEY",
        "filename:id_rsa",
        "extension:pem",
    ],
    # Backups / dumps (Case A signals)
    "backups_dumps": [
        "filename:backup.zip",
        "filename:dump.sql",
        "filename:database.sql",
        "extension:sql",
        "filename:backup",
        "filename:web.config",
    ],
    # Diagnostics (Case E) — path names only; still leads
    "diagnostics": [
        "filename:trace.axd",
        "filename:phpinfo.php",
        "path:debug",
        "filename:server-status",
    ],
}

# Compact default set used when max_results is small (Actions budget)
DEFAULT_ACTIONS_TERMS: list[str] = [
    "filename:.env",
    "filename:.env.production",
    "filename:.env.local",
    "extension:map",
    "filename:wp-config.php",
    "filename:appsettings.json",
    "AKIA",
    "sk_live_",
    "filename:backup.zip",
    "extension:sql",
    "filename:id_rsa",
    "filename:.git-credentials",
]


def all_family_terms() -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for terms in BOUNTY_QUERY_FAMILIES.values():
        for t in terms:
            if t not in seen:
                seen.add(t)
                out.append(t)
    return out


def select_query_terms(
    *,
    base_terms: str = "",
    family: str = "default",
    limit: int = 8,
) -> list[str]:
    """
    Resolve terms for multi-query GitHub search.

    family:
      - default: DEFAULT_ACTIONS_TERMS
      - all: union of families
      - named key in BOUNTY_QUERY_FAMILIES
      - if base_terms has OR clauses, those win first
    """
    limit = max(1, min(int(limit), 20))
    terms: list[str] = []
    raw = (base_terms or "").strip()
    if raw and " OR " in raw.upper():
        parts = []
        for sep in (" OR ", " or "):
            if sep in raw:
                parts = [x.strip().strip("()") for x in raw.split(sep)]
                break
        terms = [p for p in parts if p]
    elif raw and not raw.lower().startswith("family:"):
        terms = [raw.strip().strip("()")]

    if not terms:
        fam = (family or "default").strip().lower()
        if fam == "all":
            terms = all_family_terms()
        elif fam in BOUNTY_QUERY_FAMILIES:
            terms = list(BOUNTY_QUERY_FAMILIES[fam])
        else:
            terms = list(DEFAULT_ACTIONS_TERMS)
    return terms[:limit]


def brand_tokens_from_host(host: str) -> list[str]:
    """Derive simple brand tokens from host for org/repo boosting."""
    h = (host or "").lower().rstrip(".")
    if not h or "." not in h:
        return []
    # shopify.com -> shopify; gitlab.com -> gitlab
    label = h.split(".")[0]
    # strip common prefix noise
    for prefix in ("www", "api", "app", "dev", "staging", "prod"):
        if label == prefix and len(h.split(".")) > 2:
            label = h.split(".")[1]
    tokens = [label]
    # hyphenated brands
    if "-" in label:
        tokens.extend(label.split("-"))
    return [t for t in tokens if len(t) >= 3]


def org_matches_target(repo_full_name: str, target_host: str) -> bool:
    """True if GitHub org/user likely matches the target brand."""
    repo = (repo_full_name or "").lower()
    if "/" not in repo:
        return False
    org = repo.split("/", 1)[0]
    for tok in brand_tokens_from_host(target_host):
        if tok == org or tok in org:
            return True
    return False


def families_metadata() -> dict[str, Any]:
    return {
        "families": {k: list(v) for k, v in BOUNTY_QUERY_FAMILIES.items()},
        "default_actions_terms": list(DEFAULT_ACTIONS_TERMS),
        "notes": [
            "Passive index leads only — not confirmed vulnerabilities.",
            "Query families prioritize high-frequency info-disclosure bounty signals.",
        ],
    }
