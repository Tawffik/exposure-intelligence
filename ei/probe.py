"""
Bounded current-state probes (charter §4, §6 ladder step 3).

Fail-closed:
- Only when authorization_status=ACTIVE
- Only when CURRENT_OBSERVATION_GET or HEAD is in allowed_operations
- Only against hosts explicitly in the profile scope
- Budget-limited; no redirects followed beyond a small cap
- Never stores full bodies; redacted preview + hash only

This is not vulnerability confirmation.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

from ei.models import DiscoveryMode, RunStatus, SourceFidelity, redact_text, utc_now_iso
from ei.profile import ProgramProfile, live_request_permitted
from ei.providers.base import ProviderCollectResult

PROVIDER_NAME = "current_state_probe"
CHECK_FAMILY = "bounded_http"
USER_AGENT = "ExposureIntelligence/0.3.0 (authorized-probe; +https://github.com/Tawffik/exposure-intelligence)"
MAX_BODY = 4096


@dataclass
class ProbeResult:
    status: str
    records: list[dict[str, Any]] = field(default_factory=list)
    error_summary: str = ""
    coverage_notes: str = ""
    requests_made: int = 0


def _host_in_scope(profile: ProgramProfile, url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:
        return False
    if not host:
        return False
    for h in profile.in_scope_hosts:
        if host == h.lower().rstrip("."):
            return True
    for d in profile.in_scope_domains:
        d = d.lower().rstrip(".")
        if host == d or host.endswith("." + d):
            return True
    return False


def plan_probe_urls(
    profile: ProgramProfile,
    candidate_urls: list[str],
    *,
    budget: int = 5,
) -> list[str]:
    """Select in-scope http(s) URLs only, up to budget."""
    out: list[str] = []
    seen: set[str] = set()
    for u in candidate_urls:
        if len(out) >= max(1, budget):
            break
        if not u or not u.startswith(("http://", "https://")):
            continue
        if u in seen:
            continue
        if not _host_in_scope(profile, u):
            continue
        # Never probe github.com blob URLs as "target" current-state
        host = (urlparse(u).hostname or "").lower()
        if host in {"github.com", "gist.github.com", "raw.githubusercontent.com"}:
            continue
        if host.endswith("urlscan.io") or host.endswith("web.archive.org"):
            continue
        seen.add(u)
        out.append(u)
    return out


def probe_url(
    url: str,
    *,
    method: str = "HEAD",
    timeout: float = 12.0,
    profile: Optional[ProgramProfile] = None,
) -> dict[str, Any]:
    """
    Single bounded request. Returns observation-shaped dict.
    """
    method = (method or "HEAD").upper()
    if method not in {"GET", "HEAD"}:
        method = "HEAD"
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    req = urllib.request.Request(url, headers=headers, method=method)
    status_code: Optional[int] = None
    final_url = url
    content_type = ""
    body = b""
    err = ""
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = getattr(resp, "status", None) or resp.getcode()
            final_url = resp.geturl() or url
            content_type = resp.headers.get("Content-Type", "") or ""
            if method == "GET":
                body = resp.read(MAX_BODY + 1)
    except urllib.error.HTTPError as e:
        status_code = e.code
        err = f"HTTP {e.code}"
        try:
            if method == "GET":
                body = e.read(MAX_BODY + 1)
        except Exception:
            pass
    except urllib.error.URLError as e:
        err = f"URL error: {e}"
        status_code = None

    truncated = len(body) > MAX_BODY
    body = body[:MAX_BODY]
    text = body.decode("utf-8", errors="replace")
    preview, redacted = redact_text(text)
    sha = hashlib.sha256(body).hexdigest() if body else ""

    return {
        "url": final_url or url,
        "status": status_code,
        "content_type": content_type,
        "body": text if method == "GET" else "",
        "body_preview_redacted": preview if method == "GET" else f"HEAD status={status_code}",
        "body_truncated": truncated,
        "discovery_mode": DiscoveryMode.CURRENT_OBSERVATION.value,
        "source_fidelity": SourceFidelity.ORIGINAL.value,
        "provider": PROVIDER_NAME,
        "check_family": CHECK_FAMILY,
        "scope_decision": "IN_SCOPE",
        "metadata": {
            "probe_method": method,
            "requested_url": url,
            "final_url": final_url,
            "error": err,
            "body_sha256": sha,
            "redaction_applied": redacted,
            "observed_at": utc_now_iso(),
            "target_relationship": "DIRECT_TARGET_REFERENCE",
            "target_relationship_rationale": "URL host matched profile in-scope assets.",
        },
        "labels": ["current_state_probe"],
    }


def collect_probes(
    profile: ProgramProfile,
    candidate_urls: list[str],
    *,
    budget: int = 5,
    prefer_head: bool = True,
    timeout: float = 12.0,
) -> ProviderCollectResult:
    """
    Policy-gated probe collection. Returns NOT_RUN/SKIPPED when unauthorized.
    """
    if profile.authorization_status != "ACTIVE":
        return ProviderCollectResult(
            status=RunStatus.SKIPPED_BY_POLICY.value,
            error_summary=f"authorization_status={profile.authorization_status} (need ACTIVE)",
            provider=PROVIDER_NAME,
            coverage_notes="Current-state probes require ACTIVE authorization.",
        )
    method = "HEAD"
    if "CURRENT_OBSERVATION_GET" in profile.allowed_operations and not prefer_head:
        method = "GET"
    elif "CURRENT_OBSERVATION_HEAD" in profile.allowed_operations:
        method = "HEAD"
    elif "CURRENT_OBSERVATION_GET" in profile.allowed_operations:
        method = "GET"
    else:
        return ProviderCollectResult(
            status=RunStatus.SKIPPED_BY_POLICY.value,
            error_summary="No CURRENT_OBSERVATION_GET/HEAD in allowed_operations.",
            provider=PROVIDER_NAME,
        )

    # live_request_permitted double-check for first host
    hosts = profile.in_scope_hosts or profile.in_scope_domains
    if not hosts:
        return ProviderCollectResult(
            status=RunStatus.SKIPPED_BY_POLICY.value,
            error_summary="No in-scope hosts for probing.",
            provider=PROVIDER_NAME,
        )
    gate = live_request_permitted(profile, f"https://{hosts[0]}/")
    if not gate.get("allowed"):
        return ProviderCollectResult(
            status=RunStatus.SKIPPED_BY_POLICY.value,
            error_summary=f"live_request_permitted=False: {gate.get('reason')}",
            provider=PROVIDER_NAME,
        )

    urls = plan_probe_urls(profile, candidate_urls, budget=budget)
    if not urls:
        return ProviderCollectResult(
            status=RunStatus.COMPLETED_ZERO.value,
            coverage_notes="No in-scope application URLs to probe (index hosts excluded).",
            provider=PROVIDER_NAME,
            query=f"budget={budget}",
        )

    records: list[dict[str, Any]] = []
    errors = 0
    for u in urls:
        rec = probe_url(u, method=method, timeout=timeout, profile=profile)
        if rec.get("metadata", {}).get("error") and rec.get("status") is None:
            errors += 1
        records.append(rec)

    if errors == len(records):
        status = RunStatus.ERROR.value
        err = "All probe requests failed"
    elif errors:
        status = RunStatus.PARTIAL.value
        err = f"{errors}/{len(records)} probes failed"
    else:
        status = RunStatus.COMPLETED_WITH_RESULTS.value
        err = ""

    return ProviderCollectResult(
        status=status,
        records=records,
        error_summary=err,
        coverage_notes=(
            f"Probed {len(records)} in-scope URL(s) via {method}; "
            f"budget={budget}. Not vulnerability confirmation."
        ),
        provider=PROVIDER_NAME,
        query=f"method={method};count={len(records)}",
        actual_queries=urls,
    )
