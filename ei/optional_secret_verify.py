"""Optional external secret verification (TruffleHog-shaped).

Honest statuses:
  NOT_CONFIGURED — binary not on PATH
  SKIPPED_BY_POLICY — caller did not enable verification
  ERROR — tool failed
  COMPLETED_WITH_RESULTS / COMPLETED_ZERO — tool ran

Never stores raw secret values. Off by default for EI CI.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any


def trufflehog_available() -> bool:
    return shutil.which("trufflehog") is not None


def verify_github_repo(
    *,
    repo_full_name: str,
    enable: bool = False,
    only_verified: bool = True,
    timeout_sec: int = 120,
) -> dict[str, Any]:
    """Run TruffleHog against a public GitHub repo if configured."""
    out: dict[str, Any] = {
        "tool": "trufflehog",
        "repo": repo_full_name,
        "status": "SKIPPED_BY_POLICY",
        "finding_count": 0,
        "detector_names": [],
        "error_summary": None,
        "note": "Optional; not part of default EI passive path.",
    }
    if not enable:
        return out
    if not repo_full_name or "/" not in repo_full_name:
        out["status"] = "ERROR"
        out["error_summary"] = "repo_full_name must look like org/name"
        return out
    if not trufflehog_available():
        out["status"] = "NOT_CONFIGURED"
        out["error_summary"] = "trufflehog binary not found on PATH"
        return out

    url = f"https://github.com/{repo_full_name}"
    cmd = ["trufflehog", "git", url, "--json", "--no-update"]
    if only_verified:
        cmd.append("--only-verified")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        out["status"] = "ERROR"
        out["error_summary"] = f"timeout after {timeout_sec}s"
        return out
    except OSError as e:
        out["status"] = "ERROR"
        out["error_summary"] = str(e)[:200]
        return out

    detectors: list[str] = []
    count = 0
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        count += 1
        det = obj.get("DetectorName") or obj.get("detector_name") or obj.get("Detector") or ""
        if det and str(det) not in detectors:
            detectors.append(str(det)[:80])
    out["finding_count"] = count
    out["detector_names"] = detectors[:20]
    if proc.returncode not in (0, 1):
        out["status"] = "ERROR"
        out["error_summary"] = (proc.stderr or "")[:300] or f"exit {proc.returncode}"
    elif count:
        out["status"] = "COMPLETED_WITH_RESULTS"
    else:
        out["status"] = "COMPLETED_ZERO"
    return out
