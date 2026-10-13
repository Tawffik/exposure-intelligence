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
import time
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ei.models import DiscoveryMode, RunStatus, SourceFidelity, utc_now_iso
from ei.providers.base import ProviderCollectResult
from ei.query_families import select_query_terms, org_matches_target


PROVIDER_NAME = "github_code_search"
CHECK_FAMILY = "public_code_index"
DEFAULT_API = "https://api.github.com/search/code"
USER_AGENT = "ExposureIntelligence/0.1.1 (passive-research; +https://github.com/Tawffik/exposure-intelligence)"




def append_hunter_noise_filters(query: str) -> str:
    """Reduce classic false-positive buckets used by strong GitHub hunters.

    Inspired by public GitHub-recon writeups (e.g. Orwa Atyat): exclude obvious
    non-production hosts and consumer-mail noise from code search when possible.
    Does not claim the remaining hits are in-scope or exploitable.
    """
    q = (query or "").strip()
    if not q:
        return q
    # Keep filters short — GitHub rejects overly long queries
    for token in ("NOT localhost", "NOT 127.0.0.1"):
        if token.lower() not in q.lower():
            q = f"{q} {token}"
    return q


def build_target_scoped_query(target_host: str, base_terms: str = "") -> str:
    """
    Build a GitHub code-search query that includes the target host.

    GitHub code search rejects some parenthesized OR groups (HTTP 422).
    Prefer a simple AND form: <host> <shape-term>

    For multi-shape research, callers may invoke collect_live multiple times
    via build_target_scoped_query_variants().
    """
    host = (target_host or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("target_host required for scoped query")
    for ch in "(){}[]\"\"'":
        host = host.replace(ch, "")
    if not host or "." not in host:
        raise ValueError("target_host must be a multi-label domain after sanitization")

    base = (base_terms or "").strip()
    # If operator supplied a complex OR expression, use the first filename/extension term only
    # to keep a single valid query; variants() expands the rest.
    if not base:
        base = "filename:.env"
    elif " OR " in base.upper():
        # take first clause only for the primary query
        first = base.split(" OR ")[0].split(" or ")[0].strip().strip("()")
        base = first or "filename:.env"
    # Remove outer parens that break the parser when combined with host
    base = base.strip()
    if base.startswith("(") and base.endswith(")"):
        base = base[1:-1].strip()
    return append_hunter_noise_filters(f"{host} {base}")


def build_target_scoped_query_variants(target_host: str, base_terms: str = "", *, limit: int = 4) -> list[str]:
    """Return up to `limit` simple host+term queries (no OR groups)."""
    host = (target_host or "").strip().lower().rstrip(".")
    for ch in "(){}[]\"\"'":
        host = host.replace(ch, "")
    raw = (base_terms or "").strip()
    if host and raw.lower().startswith(host.lower()):
        raw = raw[len(host):].strip()
    terms = select_query_terms(base_terms=raw, family="default", limit=max(1, limit))
    queries = []
    for term in terms:
        queries.append(append_hunter_noise_filters(f"{host} {term}"))
    return queries


def _dns_token_present(text: str, host: str) -> bool:
    """True if host appears as a DNS-boundary token (not inside notexample.com)."""
    if not text or not host:
        return False
    hay = text.lower()
    needle = host.lower()
    start = 0
    while True:
        i = hay.find(needle, start)
        if i < 0:
            return False
        before = hay[i - 1] if i > 0 else ""
        after = hay[i + len(needle)] if i + len(needle) < len(hay) else ""
        # Boundary: not extending a larger domain/label
        if before and (before.isalnum() or before in "-_."):
            start = i + 1
            continue
        if after and (after.isalnum() or after in "-_"):
            # allow after '.' only if next part is not continuing same token wrongly —
            # e.g. example.com.attacker is a different host; treat as non-match for exact host
            if after == ".":
                start = i + 1
                continue
            start = i + 1
            continue
        return True


def _path_segments(path: str) -> list[str]:
    return [s for s in (path or "").replace("\\", "/").lower().split("/") if s]


def classify_index_relationship(
    *,
    target_host: str,
    item_path: str = "",
    repo_full_name: str = "",
    body_snippet: str = "",
    html_url: str = "",
) -> dict:
    """
    Classify how a public-index hit relates to the selected target.

    A textual substring is recorded separately from relationship.
    GitHub blob URLs are source artifact locations, not the target application.
    Never returns VERIFIED_DISCLOSURE — index evidence alone is insufficient.
    DIRECT_TARGET_REFERENCE requires a DNS-boundary host token in the *path*
    (as a full path segment or filename stem), not merely body text or a
    substring inside another domain (notexample.com).
    """
    host = (target_host or "").strip().lower().rstrip(".")
    path = (item_path or "").strip()
    repo = (repo_full_name or "").strip()
    body = (body_snippet or "").strip()
    # Do NOT treat github html_url as evidence of target relationship —
    # it always contains github.com, and may embed the query host in odd ways.
    if not host:
        return {
            "relationship": "UNATTRIBUTED",
            "rationale": "No target host provided.",
            "textual_match": False,
            "textual_match_fields": [],
        }

    fields: list[str] = []
    if _dns_token_present(path, host):
        fields.append("path")
    if _dns_token_present(repo, host):
        fields.append("repo")
    if _dns_token_present(body, host):
        fields.append("body")
    textual = bool(fields)

    # DIRECT: host is an exact path segment (e.g. configs/example.com/secrets.env)
    # or the filename is exactly the host / host with a single extension.
    segments = _path_segments(path)
    direct = False
    if host in segments:
        direct = True
        reason = f"Path contains exact segment '{host}'."
    else:
        fname = segments[-1] if segments else ""
        # example.com, example.com.env, example.com.backup
        if fname == host or fname.startswith(host + "."):
            # reject notexample.com when host is example.com — already boundary-safe via startswith only if fname starts with host+'.'
            # but notexample.com.startswith('example.com.') is False; good
            # example.com.attacker.test as filename is still a path claim about that name
            direct = True
            reason = f"Filename '{fname}' is host-prefixed."

    if direct:
        return {
            "relationship": "DIRECT_TARGET_REFERENCE",
            "rationale": reason + " Index-only evidence; not verified production exposure.",
            "textual_match": True,
            "textual_match_fields": fields or ["path"],
        }

    if "path" in fields or "repo" in fields:
        return {
            "relationship": "RELATED_CANDIDATE",
            "rationale": (
                f"DNS-boundary token for '{host}' found in {','.join(fields)} but not as an "
                "exact path segment/filename. Plausible, unproven relationship."
            ),
            "textual_match": True,
            "textual_match_fields": fields,
        }

    if "body" in fields:
        return {
            "relationship": "INDEX_ONLY",
            "rationale": (
                f"Host '{host}' appears only in snippet text. Public-index hit; "
                "not a defensible target finding."
            ),
            "textual_match": True,
            "textual_match_fields": fields,
        }

    # Apex weak match (example.com vs www.example.com path) — RELATED if apex in path with boundary
    labels = host.split(".")
    apex = ".".join(labels[-2:]) if len(labels) >= 2 else host
    if apex != host and (_dns_token_present(path, apex) or _dns_token_present(repo, apex)):
        return {
            "relationship": "RELATED_CANDIDATE",
            "rationale": f"Apex '{apex}' present with DNS boundaries; exact host '{host}' not established.",
            "textual_match": True,
            "textual_match_fields": ["apex"],
        }

    return {
        "relationship": "INDEX_ONLY",
        "rationale": (
            "Public index hit without a DNS-boundary reference to the selected target "
            "in path, repo name, or body. Do not treat as a target finding."
        ),
        "textual_match": textual,
        "textual_match_fields": fields,
    }



def _text_match_fragment(item: dict[str, Any]) -> str:
    """Join text-match fragments when present; never invent body content."""
    matches = item.get("text_matches") or []
    parts: list[str] = []
    for m in matches:
        frag = m.get("fragment") or m.get("text") or ""
        if frag:
            parts.append(str(frag))
    return "\n".join(parts)


def normalize_github_item(
    item: dict[str, Any],
    *,
    query: str = "",
    target_host: str = "",
) -> dict[str, Any]:
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
    rel = classify_index_relationship(
        target_host=target_host,
        item_path=path,
        repo_full_name=full_name,
        body_snippet=body,
        html_url=html_url,
    )

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
            "target_relationship": rel["relationship"],
            "target_relationship_rationale": rel["rationale"],
            "textual_match": rel.get("textual_match", False),
            "textual_match_fields": rel.get("textual_match_fields") or [],
            "selected_target_host": target_host,
            "org_brand_match": org_matches_target(full_name, target_host),
        },
    }


def normalize_github_search_response(
    payload: dict[str, Any],
    *,
    query: str = "",
    target_host: str = "",
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
    records = [normalize_github_item(it, query=query, target_host=target_host) for it in items if isinstance(it, dict)]

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


def load_github_fixture(path: Path, *, query: str = "", target_host: str = "") -> ProviderCollectResult:
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
    return normalize_github_search_response(data, query=query, target_host=target_host)


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

    def collect_from_fixture(self, path: Path, *, query: str = "", target_host: str = "") -> ProviderCollectResult:
        return load_github_fixture(path, query=query, target_host=target_host)

    def collect_live(self, query: str, *, per_page: int = 10, target_host: str = "") -> ProviderCollectResult:
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

        per_page = max(1, min(int(per_page), 30))
        params = urllib.parse.urlencode({"q": query, "per_page": per_page})
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
            if e.code == 429:
                # Secondary rate limit — stop multi-query early as RATE_LIMITED
                return ProviderCollectResult(
                    status=RunStatus.RATE_LIMITED.value,
                    error_summary=f"HTTP 429: {err_body[:200]}",
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

        return normalize_github_search_response(payload, query=query, target_host=target_host)

    def collect_live_multi(
        self,
        queries: list[str],
        *,
        per_page: int = 10,
        max_total: int = 10,
        target_host: str = "",
    ) -> ProviderCollectResult:
        """
        Run several simple queries; merge unique records up to max_total.
        Stops early on RATE_LIMITED / NOT_CONFIGURED. Never probes app hosts.
        """
        if not self.token:
            return ProviderCollectResult(
                status=RunStatus.NOT_CONFIGURED.value,
                error_summary="GITHUB_TOKEN / GH_TOKEN not set; cannot run live search.",
                query="; ".join(queries),
            )
        merged: list[dict] = []
        seen: set[str] = set()
        notes: list[str] = []
        last_status = RunStatus.COMPLETED_ZERO.value
        errors: list[str] = []
        n_q = max(len(queries), 1)
        # Reserve slots across queries so org: does not monopolize max_total
        per_query_cap = max(2, min(per_page, max(2, max_total // min(n_q, 4))))
        for q in queries:
            if len(merged) >= max_total:
                break
            remaining = max_total - len(merged)
            # Soft preference: leave room for later host-scoped families
            take = min(per_page, remaining, per_query_cap)
            if q.startswith("org:") and remaining > per_query_cap:
                take = min(take, 3)
            r = self.collect_live(q, per_page=take, target_host=target_host)
            time.sleep(2.0)  # soft pacing against secondary rate limits
            notes.append(f"{q!r}->{r.status}/{len(r.records)}")
            if r.status == RunStatus.NOT_CONFIGURED.value:
                return r
            if r.status == RunStatus.RATE_LIMITED.value:
                if merged:
                    return ProviderCollectResult(
                        status=RunStatus.PARTIAL.value,
                        records=merged,
                        error_summary=r.error_summary,
                        coverage_notes="Rate limited after partial collection. " + "; ".join(notes),
                        query="; ".join(queries),
                        incomplete_results=True,
                    )
                return r
            if r.status == RunStatus.ERROR.value:
                errors.append(r.error_summary)
                last_status = RunStatus.ERROR.value
                continue
            for rec in r.records:
                key = rec.get("url") or rec.get("source_record_id") or ""
                if key in seen:
                    continue
                seen.add(key)
                merged.append(rec)
                if len(merged) >= max_total:
                    break
            if r.status == RunStatus.COMPLETED_WITH_RESULTS.value:
                last_status = RunStatus.COMPLETED_WITH_RESULTS.value
            elif r.status == RunStatus.PARTIAL.value:
                last_status = RunStatus.PARTIAL.value
            elif last_status != RunStatus.COMPLETED_WITH_RESULTS.value and r.status == RunStatus.COMPLETED_ZERO.value:
                last_status = RunStatus.COMPLETED_ZERO.value
        if not merged and last_status == RunStatus.ERROR.value:
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary="; ".join(errors)[:500],
                coverage_notes="; ".join(notes),
                query="; ".join(queries),
            )
        if not merged:
            return ProviderCollectResult(
                status=RunStatus.COMPLETED_ZERO.value,
                coverage_notes="; ".join(notes),
                query="; ".join(queries),
            )
        # Preserve successful records even if later queries failed.
        # ERROR with any records must surface as PARTIAL, never drop evidence.
        if errors:
            status = RunStatus.PARTIAL.value
            err = "; ".join(errors)[:500]
            coverage = (
                "; ".join(notes)
                + f"; merged={len(merged)}; query_errors={len(errors)}"
            )
        elif last_status == RunStatus.PARTIAL.value:
            status = RunStatus.PARTIAL.value
            err = ""
            coverage = "; ".join(notes) + f"; merged={len(merged)}"
        else:
            status = RunStatus.COMPLETED_WITH_RESULTS.value
            err = ""
            coverage = "; ".join(notes) + f"; merged={len(merged)}"
        return ProviderCollectResult(
            status=status,
            records=merged[:max_total],
            error_summary=err,
            coverage_notes=coverage,
            query="; ".join(queries),
            incomplete_results=bool(errors) or len(merged) >= max_total,
            actual_queries=list(queries),
        )

