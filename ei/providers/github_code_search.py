"""
GitHub Code Search — passive public index provider (shadow mode).

Maps GitHub code-search API records into EI observation records without
fetching target applications or validating impact.

Modes:
- Offline: normalize a recorded API JSON fixture (deterministic tests).
- Live (optional): GET api.github.com/search/code when a token is supplied
  and live mode is explicitly enabled. Never probes discovered hosts.

Live mode is for measuring provider connectivity only; results remain
PASSIVE_INDEX leads, not confirmed findings.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ei.models import DiscoveryMode, RunStatus, SourceFidelity, utc_now_iso


PROVIDER_NAME = "github_code_search"
CHECK_FAMILY = "public_code_index"
DEFAULT_API = "https://api.github.com/search/code"
USER_AGENT = "ExposureIntelligence/0.1.1 (passive-research; +https://github.com/Tawffik/exposure-intelligence)"


@dataclass
class ProviderCollectResult:
    """Outcome of a single provider collect call."""

    status: str
    records: list[dict[str, Any]] = field(default_factory=list)
    error_summary: str = ""
    coverage_notes: str = ""
    raw_total_count: Optional[int] = None
    incomplete_results: bool = False
    query: str = ""
    provider: str = PROVIDER_NAME


def _text_match_fragment(item: dict[str, Any]) -> str:
    """Join text-match fragments when present; never invent body content."""
    matches = item.get("text_matches") or []
    parts: list[str] = []
    for m in matches:
        frag = m.get("fragment") or m.get("text") or ""
        if frag:
            parts.append(str(frag))
    return "\n".join(parts)


def normalize_github_item(item: dict[str, Any], *, query: str = "") -> dict[str, Any]:
    """
    Convert one GitHub code-search item into an EI fixture-style observation record.

    Does not claim current accessibility on the owner's production host.
    The html_url is a public GitHub blob URL (PASSIVE_INDEX).
    """
    repo = item.get("repository") or {}
    full_name = repo.get("full_name") or ""
    path = item.get("path") or item.get("name") or ""
    html_url = item.get("html_url") or ""
    sha = item.get("sha") or ""
    body = _text_match_fragment(item)

    # Public GitHub blob is the observed artifact URL for this provider.
    discovered = html_url or (
        f"https://github.com/{full_name}/blob/{sha}/{path}" if full_name and path else path
    )

    content_type = "text/plain"
    lower_path = path.lower()
    if lower_path.endswith(".json") or lower_path.endswith(".map"):
        content_type = "application/json"
    elif lower_path.endswith((".html", ".htm")):
        content_type = "text/html"
    elif lower_path.endswith((".yml", ".yaml")):
        content_type = "text/yaml"

    return {
        "url": discovered,
        "status": 200 if html_url or path else None,
        "content_type": content_type,
        "body": body,
        "discovery_mode": DiscoveryMode.PASSIVE_INDEX.value,
        "source_fidelity": SourceFidelity.ORIGINAL.value,
        "provider": PROVIDER_NAME,
        "check_family": CHECK_FAMILY,
        "source_url": f"{DEFAULT_API}?q={urllib.parse.quote(query)}" if query else DEFAULT_API,
        "source_record_id": sha or item.get("url") or html_url,
        "scope_decision": "UNKNOWN",  # public index hit ≠ authorized target attribution
        "metadata": {
            "github_repo": full_name,
            "github_path": path,
            "github_score": item.get("score"),
            "github_repository_url": repo.get("html_url") or "",
            "query": query,
            "provider": PROVIDER_NAME,
        },
    }


def normalize_github_search_response(
    payload: dict[str, Any],
    *,
    query: str = "",
) -> ProviderCollectResult:
    """Normalize a full search/code JSON body into observation records + status."""
    if not isinstance(payload, dict):
        return ProviderCollectResult(
            status=RunStatus.ERROR.value,
            error_summary="GitHub search response is not a JSON object.",
            query=query,
        )

    # Explicit error envelope from API
    if "message" in payload and "items" not in payload:
        msg = str(payload.get("message") or "GitHub API error")
        lower = msg.lower()
        if "rate limit" in lower or "api rate limit" in lower:
            status = RunStatus.RATE_LIMITED.value
        else:
            status = RunStatus.ERROR.value
        return ProviderCollectResult(
            status=status,
            error_summary=msg,
            query=query,
            coverage_notes="API returned an error object without items.",
        )

    items = payload.get("items")
    if items is None:
        return ProviderCollectResult(
            status=RunStatus.ERROR.value,
            error_summary="GitHub search response missing 'items' field.",
            query=query,
        )

    incomplete = bool(payload.get("incomplete_results"))
    total = payload.get("total_count")
    records = [normalize_github_item(it, query=query) for it in items if isinstance(it, dict)]

    if incomplete:
        status = RunStatus.PARTIAL.value
        coverage = (
            f"GitHub reported incomplete_results=true; normalized {len(records)} item(s); "
            f"total_count={total}."
        )
    elif len(records) == 0:
        status = RunStatus.COMPLETED_ZERO.value
        coverage = f"Query completed with zero items; total_count={total}."
    else:
        status = RunStatus.COMPLETED_WITH_RESULTS.value
        coverage = f"Normalized {len(records)} item(s); total_count={total}."

    return ProviderCollectResult(
        status=status,
        records=records,
        coverage_notes=coverage,
        raw_total_count=total if isinstance(total, int) else None,
        incomplete_results=incomplete,
        query=query,
    )


def load_github_fixture(path: Path, *, query: str = "") -> ProviderCollectResult:
    """Load a recorded GitHub search/code response from disk."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "response" in data:
        query = data.get("query") or query
        data = data["response"]
    if not isinstance(data, dict):
        return ProviderCollectResult(
            status=RunStatus.ERROR.value,
            error_summary="Fixture must be a GitHub search JSON object.",
            query=query,
        )
    return normalize_github_search_response(data, query=query)


class GitHubCodeSearchProvider:
    """
    Minimal passive adapter.

    Offline path is the supported default. Live HTTP is opt-in and never
    follows results to third-party application hosts.
    """

    name = PROVIDER_NAME

    def __init__(
        self,
        *,
        token: Optional[str] = None,
        api_url: str = DEFAULT_API,
        timeout_sec: float = 20.0,
    ) -> None:
        self.token = token if token is not None else os.environ.get("GITHUB_TOKEN") or os.environ.get(
            "GH_TOKEN"
        )
        self.api_url = api_url
        self.timeout_sec = timeout_sec

    def validate_config(self, *, require_token: bool = False) -> ProviderCollectResult:
        if require_token and not self.token:
            return ProviderCollectResult(
                status=RunStatus.NOT_CONFIGURED.value,
                error_summary="GITHUB_TOKEN / GH_TOKEN not set; live GitHub search disabled.",
            )
        return ProviderCollectResult(
            status=RunStatus.COMPLETED_ZERO.value,
            coverage_notes="Config OK (token present)." if self.token else "Config OK (offline-only; no token).",
        )

    def collect_from_fixture(self, path: Path, *, query: str = "") -> ProviderCollectResult:
        return load_github_fixture(path, query=query)

    def collect_live(self, query: str, *, per_page: int = 10) -> ProviderCollectResult:
        """
        Optional live search. Requires token. Does not request target apps.

        Shadow mode policy: callers should not use results to drive active probes.
        """
        if not self.token:
            return ProviderCollectResult(
                status=RunStatus.NOT_CONFIGURED.value,
                error_summary="GITHUB_TOKEN / GH_TOKEN not set; cannot run live search.",
                query=query,
            )
        if not query.strip():
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary="Empty search query.",
                query=query,
            )

        params = urllib.parse.urlencode({"q": query, "per_page": max(1, min(per_page, 30))})
        url = f"{self.api_url}?{params}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github.text-match+json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                payload = json.loads(body)
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            if e.code == 403 and "rate limit" in err_body.lower():
                return ProviderCollectResult(
                    status=RunStatus.RATE_LIMITED.value,
                    error_summary=f"HTTP 403 rate limited: {err_body[:200]}",
                    query=query,
                )
            if e.code in (401, 403):
                return ProviderCollectResult(
                    status=RunStatus.ERROR.value,
                    error_summary=f"HTTP {e.code}: {err_body[:200] or e.reason}",
                    query=query,
                )
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary=f"HTTP {e.code}: {err_body[:200] or e.reason}",
                query=query,
            )
        except urllib.error.URLError as e:
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary=f"Network error: {e.reason}",
                query=query,
            )
        except json.JSONDecodeError as e:
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary=f"Invalid JSON from GitHub: {e}",
                query=query,
            )

        return normalize_github_search_response(payload, query=query)
