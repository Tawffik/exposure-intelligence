"""
Internet Archive CDX — passive historical URL index provider.

Queries the public CDX API for archived URL observations.
Results are HISTORICAL leads, never current-state verification.

API:
  GET https://web.archive.org/cdx/search/cdx?url=<pattern>&output=json&limit=N&fl=...

Offline: normalize a recorded JSON fixture (array-of-arrays or list of objects).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional

from ei.models import DiscoveryMode, RunStatus, SourceFidelity, utc_now_iso
from ei.host_relationship import classify_url_host_relationship, to_provider_relationship
from ei.providers.base import ProviderCollectResult

PROVIDER_NAME = "internet_archive_cdx"
CHECK_FAMILY = "historical_url_index"
DEFAULT_API = "https://web.archive.org/cdx/search/cdx"
USER_AGENT = "ExposureIntelligence/0.2.0 (passive-research; +https://github.com/Tawffik/exposure-intelligence)"


def _is_junk_url(url: str) -> bool:
    """Drop clearly malformed/noisy archive originals."""
    u = url or ""
    if not u.startswith(("http://", "https://")):
        return True
    bad_tokens = (
        "%0a",
        "%0d",
        "%22",
        "%27",
        "!!!!!",
        "!==",
        "/%22",
        "${",
        "$ci_",
        "prgnam",
        "committish",
        "downloadedversion",
        "wallhack",
        "aimbot",
        "fortnitespoofer",
        "cheat-undetected",
    )
    low = u.lower()
    if any(b in low for b in bad_tokens):
        return True
    if "\n" in u or "\r" in u:
        return True
    from urllib.parse import urlparse
    try:
        path = urlparse(u).path or ""
    except Exception:
        return True
    if path in {"", "/", ":80/", ":443/"}:
        return True
    if len(path) <= 1 and ":" in (urlparse(u).netloc or ""):
        return True
    return False


DEFAULT_FL = "timestamp,original,statuscode,mimetype,digest,length"


def build_cdx_url_pattern(target_host: str) -> str:
    host = (target_host or "").strip().lower().rstrip(".")
    for ch in "(){}[]\"'":
        host = host.replace(ch, "")
    if not host or "." not in host:
        raise ValueError("target_host must be a multi-label domain")
    return f"{host}/*"


def _row_to_dict(headers: list[str], row: list[Any]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for i, h in enumerate(headers):
        if i < len(row):
            d[h] = row[i]
    return d


def normalize_cdx_row(
    row: dict[str, Any],
    *,
    query: str = "",
    target_host: str = "",
) -> dict[str, Any]:
    original = row.get("original") or row.get("url") or ""
    ts = str(row.get("timestamp") or "")
    status = row.get("statuscode") or row.get("status") or ""
    mime = row.get("mimetype") or row.get("mime") or ""
    digest = row.get("digest") or ""
    length = row.get("length") or ""
    try:
        status_int = int(status) if str(status).isdigit() else None
    except ValueError:
        status_int = None

    wayback = ""
    if ts and original:
        wayback = f"https://web.archive.org/web/{ts}/{original}"

    rel_detail = classify_url_host_relationship(
        target_host=target_host, url=original or "", provider_domain=""
    )
    relationship = to_provider_relationship(rel_detail)
    rationale = (
        "Historical CDX index row; not proof of current exposure. "
        + (rel_detail.get("rationale") or "")
    )

    # Sensitive-looking path heuristics (filename only — never treat as confirmed)
    path_lower = (original or "").lower()
    labels = ["cdx", "historical"]
    sens_hint = False
    for token in (
        "/.env",
        ".env.",
        ".env/",
        "backup.zip",
        "backup.sql",
        "dump.sql",
        "database.sql",
        ".git/",
        "wp-config",
        "web.config",
        "appsettings.json",
        "id_rsa",
        "phpinfo.php",
        "trace.axd",
        ".pem",
        ".map",
    ):
        if token in path_lower:
            labels.append("path_sensitive_hint")
            sens_hint = True
            break

    meta = {
        "provider": PROVIDER_NAME,
        "check_family": CHECK_FAMILY,
        "cdx_timestamp": ts,
        "cdx_digest": digest,
        "cdx_length": length,
        "cdx_mimetype": mime,
        "wayback_url": wayback,
        "search_query": query,
        "selected_target_host": target_host,
        "target_relationship": relationship,
        "target_relationship_rationale": rationale,
        "host_relationship_detail": rel_detail.get("relationship"),
        "parsed_hostname": rel_detail.get("hostname") or "",
        "provider_domain_conflict": bool(rel_detail.get("provider_domain_conflict")),
        "provider_domain_fallback": bool(rel_detail.get("provider_domain_fallback")),
        "textual_match": bool(rel_detail.get("textual_match")),
        "textual_match_fields": list(rel_detail.get("textual_match_fields") or []),
        "path_sensitive_hint": sens_hint,
        "source_artifact_url": wayback or original,
        "freshness": "HISTORICAL",
    }
    observed = utc_now_iso()
    if len(ts) >= 14 and ts.isdigit():
        # 20240101120000 → rough ISO date for sorting only
        observed = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}T{ts[8:10]}:{ts[10:12]}:{ts[12:14]}Z"

    return {
        "url": original or wayback,
        "observed_at": observed,
        "discovery_mode": DiscoveryMode.HISTORICAL.value,
        "source_fidelity": SourceFidelity.MIRROR.value,
        "http_status": status_int,
        "content_type": mime,
        "body_preview_redacted": f"cdx status={status} mime={mime} length={length} ts={ts}"[:500],
        "body_truncated": True,
        "provider": PROVIDER_NAME,
        "check_family": CHECK_FAMILY,
        "scope_decision": "PUBLIC_INDEX",
        "metadata": meta,
        "labels": labels,
        "classification_hint": "HISTORICAL_ONLY" if not sens_hint else "IMPACT_UNPROVEN",
    }


def normalize_cdx_payload(
    payload: Any,
    *,
    query: str = "",
    target_host: str = "",
    limit: int = 30,
) -> list[dict[str, Any]]:
    """
    Accept:
    - list of dicts
    - CDX JSON array-of-arrays (first row headers)
    - object with key 'rows' or 'results'
    """
    rows: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        if "results" in payload and isinstance(payload["results"], list):
            for r in payload["results"]:
                if isinstance(r, dict):
                    rows.append(r)
        elif "rows" in payload and isinstance(payload["rows"], list):
            for r in payload["rows"]:
                if isinstance(r, dict):
                    rows.append(r)
        else:
            return []
    elif isinstance(payload, list):
        if not payload:
            return []
        if isinstance(payload[0], dict):
            rows = [r for r in payload if isinstance(r, dict)]
        elif isinstance(payload[0], list):
            headers = [str(h) for h in payload[0]]
            for row in payload[1:]:
                if isinstance(row, list):
                    rows.append(_row_to_dict(headers, row))
        else:
            return []
    else:
        return []

    out: list[dict[str, Any]] = []
    for row in rows:
        if len(out) >= max(1, limit):
            break
        rec = normalize_cdx_row(row, query=query, target_host=target_host)
        if _is_junk_url(rec.get("url") or ""):
            continue
        out.append(rec)
    return out


class CDXProvider:
    def __init__(
        self,
        *,
        api_url: str = DEFAULT_API,
        timeout: float = 12.0,
    ) -> None:
        self.api_url = api_url
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
        query = ""
        if isinstance(payload, dict):
            query = payload.get("_ei_query") or ""
        if not query and target_host:
            try:
                query = build_cdx_url_pattern(target_host)
            except ValueError:
                query = target_host
        records = normalize_cdx_payload(
            payload, query=query, target_host=target_host, limit=limit
        )
        status = (
            RunStatus.COMPLETED_WITH_RESULTS.value
            if records
            else RunStatus.COMPLETED_ZERO.value
        )
        return ProviderCollectResult(
            status=status,
            records=records,
            coverage_notes=f"Fixture {Path(path).name}; returned={len(records)}",
            raw_total_count=len(records),
            query=query,
            provider=PROVIDER_NAME,
            actual_queries=[query] if query else [],
        )

    def collect_live(
        self,
        target_host: str,
        *,
        limit: int = 10,
        match_type: str = "domain",
        filter_statuscode: str = "",
    ) -> ProviderCollectResult:
        try:
            pattern = build_cdx_url_pattern(target_host)
        except ValueError as e:
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary=str(e),
                provider=PROVIDER_NAME,
            )
        limit = max(1, min(int(limit), 100))
        params: dict[str, str] = {
            "url": pattern,
            "output": "json",
            "limit": str(limit),
            "fl": DEFAULT_FL,
            "collapse": "urlkey",
        }
        if match_type:
            params["matchType"] = match_type
        if filter_statuscode:
            params["filter"] = f"statuscode:{filter_statuscode}"
        # Prefer URL patterns that historically correlate with disclosure leads
        params["filter"] = params.get("filter") or ""
        # CDX supports multiple filter params via repeated keys — use urllib list later if needed.
        # Single regex filter on original path:
        if not filter_statuscode:
            params["filter"] = r"original:.*(\.env|backup\.|dump\.sql|wp-config|\.git/|\.map|openapi|swagger)"|map|bak|tar\.gz|pem)([?#]|$))"
        qs = urllib.parse.urlencode(params)
        url = f"{self.api_url}?{qs}"
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                pass
            if e.code in (429, 503):
                return ProviderCollectResult(
                    status=RunStatus.RATE_LIMITED.value,
                    error_summary=f"HTTP {e.code}: {err_body}",
                    query=pattern,
                    provider=PROVIDER_NAME,
                    actual_queries=[url],
                )
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary=f"HTTP {e.code}: {err_body}",
                query=pattern,
                provider=PROVIDER_NAME,
                actual_queries=[url],
            )
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary=f"Network error: {e}",
                query=pattern,
                provider=PROVIDER_NAME,
                actual_queries=[url],
            )
        try:
            text = body.decode("utf-8")
            payload = json.loads(text) if text.strip() else []
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return ProviderCollectResult(
                status=RunStatus.ERROR.value,
                error_summary=f"Invalid JSON: {e}",
                query=pattern,
                provider=PROVIDER_NAME,
                actual_queries=[url],
            )
        records = normalize_cdx_payload(
            payload, query=pattern, target_host=target_host, limit=limit
        )
        status = (
            RunStatus.COMPLETED_WITH_RESULTS.value
            if records
            else RunStatus.COMPLETED_ZERO.value
        )
        return ProviderCollectResult(
            status=status,
            records=records,
            coverage_notes=(
                f"Live CDX url={pattern!r} limit={limit} returned={len(records)}. "
                "Historical index only; not current-state verification."
            ),
            raw_total_count=len(records),
            query=pattern,
            provider=PROVIDER_NAME,
            actual_queries=[url],
        )
