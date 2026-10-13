"""
Information-disclosure taxonomy for Exposure Intelligence.

Maps observation signals to bounty-oriented disclosure classes without
confirming vulnerability impact. Used for ranking rationale and queue
explanations. Sources: Notion Research Lab scenarios + public writeups.
"""

from __future__ import annotations

from typing import Any

# Class → human hypothesis (not a confirmed finding)
DISCLOSURE_CLASSES: dict[str, dict[str, str]] = {
    "ENV_CONFIG_EXPOSURE": {
        "label": "Environment / config artifact",
        "hypothesis": "Config or .env-style artifact may expose credentials or internal hosts.",
        "human_next": "Review redacted keys only; never reuse discovered credentials.",
        "typical_bounty_signal": "high",
    },
    "BACKUP_DUMP": {
        "label": "Backup or database dump artifact",
        "hypothesis": "Archive/SQL dump may contain source, PII, or credentials.",
        "human_next": "Confirm scope and sensitivity offline; do not download bulk PII casually.",
        "typical_bounty_signal": "high",
    },
    "SOURCE_MAP": {
        "label": "JavaScript source map",
        "hypothesis": "Source maps can reveal original source and sometimes embedded secrets.",
        "human_next": "Inspect map for secrets and internal endpoints; treat as lead only.",
        "typical_bounty_signal": "medium",
    },
    "API_SPEC": {
        "label": "OpenAPI / Swagger surface map",
        "hypothesis": "Specs map authenticated and hidden endpoints; not proof of access.",
        "human_next": "Extract unauthenticated routes as follow-up hypotheses under scope.",
        "typical_bounty_signal": "medium",
    },
    "VCS_METADATA": {
        "label": "VCS metadata (.git/.svn)",
        "hypothesis": "Exposed VCS metadata can enable source reconstruction.",
        "human_next": "Confirm reachability under authorization; do not dump entire repos blindly.",
        "typical_bounty_signal": "high",
    },
    "DIAGNOSTIC_SURFACE": {
        "label": "Debug / actuator / phpinfo surface",
        "hypothesis": "Diagnostics may leak env, paths, versions, or internal services.",
        "human_next": "Capture redacted evidence; avoid invasive probing.",
        "typical_bounty_signal": "medium",
    },
    "SECRET_LIKE_TOKEN": {
        "label": "Secret-like token pattern",
        "hypothesis": "Pattern resembles cloud/API credentials; validity and scope unknown.",
        "human_next": "Report pattern type only; never authenticate with discovered secrets.",
        "typical_bounty_signal": "high",
    },
    "HISTORICAL_INDEX": {
        "label": "Historical index hit",
        "hypothesis": "Archive/index evidence only; current reachability unverified.",
        "human_next": "Treat as hypothesis for authorized current-state check if policy allows.",
        "typical_bounty_signal": "low",
    },
    "GENERIC_PUBLIC": {
        "label": "Generic public page",
        "hypothesis": "Ordinary public content without strong disclosure signals.",
        "human_next": "Deprioritize unless relationship evidence is strong.",
        "typical_bounty_signal": "low",
    },
}


def classify_disclosure_signal(url: str = "", body: str = "", labels: list[str] | None = None) -> dict[str, Any]:
    """Heuristic disclosure class from URL/path/body snippet (no secret storage)."""
    u = (url or "").lower()
    b = (body or "")[:2000].lower()
    labs = {x.lower() for x in (labels or [])}

    def hit(*needles: str) -> bool:
        return any(n in u or n in b for n in needles)

    if hit("/.env", "filename:.env") or "env_config" in labs or hit(".env.production", ".env.local"):
        cls = "ENV_CONFIG_EXPOSURE"
    elif hit("backup.zip", "dump.sql", "database.sql", ".sql", "backup.tar"):
        cls = "BACKUP_DUMP"
    elif hit(".map", "sourcemap") and not hit("sitemap"):
        cls = "SOURCE_MAP"
    elif hit("openapi", "swagger", "api-docs", "redoc"):
        cls = "API_SPEC"
    elif hit(".git/", ".git/config", ".svn/"):
        cls = "VCS_METADATA"
    elif hit("phpinfo", "trace.axd", "actuator", "elmah", "server-status", "graphiql"):
        cls = "DIAGNOSTIC_SURFACE"
    elif hit("akia", "sk_live_", "ghp_", "begin rsa private", "aws_secret_access_key"):
        cls = "SECRET_LIKE_TOKEN"
    elif "historical" in labs or "cdx" in labs or "urlscan" in labs:
        cls = "HISTORICAL_INDEX"
    else:
        cls = "GENERIC_PUBLIC"

    meta = DISCLOSURE_CLASSES[cls]
    return {
        "disclosure_class": cls,
        "label": meta["label"],
        "impact_hypothesis": meta["hypothesis"],
        "suggested_next_step": meta["human_next"],
        "typical_bounty_signal": meta["typical_bounty_signal"],
    }
