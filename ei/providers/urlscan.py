"""
URLScan.io — passive public-index search provider.

Searches existing public scan records only. Does NOT submit new scans.
Results are PASSIVE_INDEX / HISTORICAL leads, never verified disclosures.

API (public search, no key required for basic q=):
  GET https://urlscan.io/api/v1/search/?q=domain:<host>&size=N

Offline: normalize a recorded JSON fixture for deterministic tests.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional

from ei.models import DiscoveryMode, RunStatus, SourceFidelity, utc_now_iso
from ei.host_relationship import classify_url_host_relationship, to_provider_relationship
from ei.providers.base import ProviderCollectResult

PROVIDER_NAME = "urlscan"
CHECK_FAMILY = "public_scan_index"
DEFAULT_API = "https://urlscan.io/api/v1/search/"
USER_AGENT = "ExposureIntelligence/0.2.0 (passive-research; +https://github.com/Tawffik/exposure-intelligence)"


def build_urlscan_query(target_host: str) -> str:
    host = (target_host or "").strip().lower().rstrip(".")
    for ch in "(){}[]\"'":
        host = host.replace(ch, "")
    if not host or "." not in host:
        raise ValueError("target_host must be a multi-label domain")
    return f"domain:{host}"


def normalize_urlscan_item(
    item: dict[str, Any],
    *,
    query: str = "",
    target_host: str = "",
) -> dict[str, Any]:
    """Map one URLScan result object into an EI observation-shaped record."""
    page = item.get("page") or {}
    task = item.get("task") or {}
    stats = item.get("stats") or {}
    url = (
        page.get("url")
        or task.get("url")
        or item.get("result")
        or ""
    )
    if isinstance(url, str) and url and not url.startswith("http"):
        # result field may be an API path
        url = page.get("url") or task.get("url") or url
    domain = page.get("domain") or task.get("domain") or ""
    scan_id = item.get("_id") or task.get("uuid") or ""
    result_api = item.get("result") or (
        f"https://urlscan.io/api/v1/result/{scan_id}/" if scan_id else ""
    )
    screenshot = item.get("screenshot") or ""
    observed = task.get("time") or item.get("indexedAt") or utc_now_iso()
    server = page.get("server") or ""
    status_code = page.get("status")
    title = page.get("title") or ""
    tls = page.get("tlsIssuer") or page.get("tlsValidDays") or ""

    # Relationship: DNS-boundary hostname only (not path/query substring)
    rel_detail = classify_url_host_relationship(
        target_host=target_host, url=url or "", provider_domain=domain or ""
    )
    relationship = to_provider_relationship(rel_detail)
    rationale = (
        "Public URLScan index record; not current-state verification. "
        + (rel_detail.get("rationale") or "")
    )

    preview = f"title={title[:80]} server={server} status={status_code}"
    meta = {
        "provider": PROVIDER_NAME,
        "check_family": CHECK_FAMILY,
        "scan_id": scan_id,
        "urlscan_result_api": result_api,
        "screenshot": screenshot,
        "page_domain": domain,
        "page_server": server,
        "page_status": status_code,
        "page_title": title[:200],
        "tls_hint": str(tls)[:120] if tls else "",
        "task_time": task.get("time"),
        "indexed_at": item.get("indexedAt"),
        "stats": {
            "uniqIPs": stats.get("uniqIPs"),
            "dataLength": stats.get("dataLength"),
            "requests": stats.get("requests"),
        },
        "search_query": query,
        "selected_target_host": target_host,
        "target_relationship": relationship,
        "target_relationship_rationale": rationale,
        "host_relationship_detail": rel_detail.get("relationship"),
        "parsed_hostname": rel_detail.get("hostname") or "",
        "textual_match": bool(rel_detail.get("textual_match")),
        "textual_match_fields": list(rel_detail.get("textual_match_fields") or []),
        "source_artifact_url": result_api or url,
    }
    return {
        "url": url or result_api or f"urlscan://{scan_id}",
        "observed_at": observed,
        "discovery_mode": DiscoveryMode.PASSIVE_INDEX.value,
        "source_fidelity": SourceFidelity.SUMMARY.value,
        "http_status": int(status_code) if isinstance(status_code, int) else None,
        "content_type": "",
        "body_preview_redacted": preview[:500],
        "body_truncated": True,
        "provider": PROVIDER_NAME,
        "check_family": CHECK_FAMILY,
        "scope_decision": "PUBLIC_INDEX",
        "metadata": meta,
        "labels": ["urlscan", "passive_index"],
    }


def normalize_urlscan_search_response(
    payload: dict[str, Any],
    *,
    query: str = "",
    target_host: str = "",
    limit: int = 30,
) -> list[dict[str, Any]]:
    results = payload.get("results") or []
    out: list[dict[str, Any]] = []
    for item in results[: max(1, limit)]:
        if not isinstance(item, dict):
            continue
        out.append(normalize_urlscan_item(item, query=query, target_host=target_host))
    return out


class URLScanProvider:
    def __init__(
        self,
        *,
        api_url: str = DEFAULT_API,
        api_key: Optional[str] = None,
        timeout: float = 25.0,
    ) -> None:
        self.api_url = api_url
        self.api_key = api_key if api_key is not None else (
            os.environ.get("URLSCAN_API_KEY") or os.environ.get("URLSCAN_KEY") or ""
        )
        self.timeout = timeout

    def collect_from_fixture(
        self,
        path: Path,
        *,
        target_host: str = "",
        limit: int = 30,
    ) -> ProviderCollectResult:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary=f"Fixture read failed: {e}",
                provider=PROVIDER_NAME,
            )
        if not isinstance(payload, dict):
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary="Fixture must be a JSON object with results[].",
                provider=PROVIDER_NAME,
            )
        query = payload.get("_ei_query") or (
            build_urlscan_query(target_host) if target_host else ""
        )
        records = normalize_urlscan_search_response(
            payload, query=query, target_host=target_host, limit=limit
        )
        total = payload.get("total")
        status = (
            RunStatus.COMPLETED_WITH_RESULTS.value
            if records
            else RunStatus.COMPLETED_ZERO.value
        )
        return ProviderCollectResult(
            status=status,
            records=records,
            coverage_notes=f"Fixture {Path(path).name}; total={total}; returned={len(records)}",
            raw_total_count=int(total) if isinstance(total, int) else len(records),
            query=query,
            provider=PROVIDER_NAME,
            actual_queries=[query] if query else [],
        )

    def collect_live(
        self,
        target_host: str,
        *,
        size: int = 10,
    ) -> ProviderCollectResult:
        try:
            query = build_urlscan_query(target_host)
        except ValueError as e:
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary=str(e),
                provider=PROVIDER_NAME,
            )
        size = max(1, min(int(size), 100))
        params = urllib.parse.urlencode({"q": query, "size": str(size)})
        url = f"{self.api_url}?{params}"
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        }
        if self.api_key:
            headers["API-Key"] = self.api_key
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                status_code = getattr(resp, "status", 200)
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                pass
            if e.code == 429:
                return ProviderCollectResult(
                    status=RunStatus.RATE_LIMITED.value,
                    error_summary=f"HTTP 429 rate limited. {err_body}",
                    query=query,
                    provider=PROVIDER_NAME,
                    actual_queries=[query],
                )
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary=f"HTTP {e.code}: {err_body}",
                query=query,
                provider=PROVIDER_NAME,
                actual_queries=[query],
            )
        except urllib.error.URLError as e:
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary=f"Network error: {e}",
                query=query,
                provider=PROVIDER_NAME,
                actual_queries=[query],
            )
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary=f"Invalid JSON: {e}",
                query=query,
                provider=PROVIDER_NAME,
                actual_queries=[query],
            )
        if not isinstance(payload, dict):
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary="Unexpected payload type",
                query=query,
                provider=PROVIDER_NAME,
                actual_queries=[query],
            )
        records = normalize_urlscan_search_response(
            payload, query=query, target_host=target_host, limit=size
        )
        total = payload.get("total")
        incomplete = isinstance(total, int) and total > len(records)
        status = (
            RunStatus.COMPLETED_WITH_RESULTS.value
            if records
            else RunStatus.COMPLETED_ZERO.value
        )
        if incomplete and records:
            status = RunStatus.PARTIAL.value
        return ProviderCollectResult(
            status=status,
            records=records,
            coverage_notes=(
                f"Live URLScan search q={query!r} size={size} "
                f"http={status_code} total={total} returned={len(records)}. "
                "Search of existing public scans only; no scan submission."
            ),
            raw_total_count=int(total) if isinstance(total, int) else len(records),
            incomplete_results=incomplete,
            query=query,
            provider=PROVIDER_NAME,
            actual_queries=[query],
        )
