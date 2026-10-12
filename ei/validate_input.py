"""Safe target/hostname validation for CLI and Actions inputs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# DNS label: letters/digits/hyphen, not starting/ending with hyphen
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.I)
_DISALLOWED = set(";|&$<>`\\\"'\n\r\t\x00")


@dataclass
class TargetValidation:
    ok: bool
    host: str = ""
    errors: list[str] = field(default_factory=list)


def sanitize_target_input(raw: str) -> TargetValidation:
    """
    Accept a bare hostname/domain or URL; return normalized hostname only.
    Reject empty, shell metacharacters, and malformed DNS.
    """
    s = (raw or "").strip()
    if not s:
        return TargetValidation(ok=False, errors=["target is required"])
    if any(c in _DISALLOWED for c in s):
        return TargetValidation(ok=False, errors=["target contains disallowed characters"])
    if any(c.isspace() for c in s):
        return TargetValidation(ok=False, errors=["target must not contain whitespace"])
    if "$(" in s or "${" in s:
        return TargetValidation(ok=False, errors=["target contains disallowed characters"])

    host = s
    if "://" in s:
        parsed = urlparse(s)
        host = parsed.hostname or ""
        if not host:
            return TargetValidation(ok=False, errors=["could not parse hostname from URL"])
    else:
        host = s.split("/")[0].split("?")[0].split("#")[0]
        if ":" in host and not host.startswith("["):
            host = host.rsplit(":", 1)[0]

    host = host.strip(".").lower()
    if not host:
        return TargetValidation(ok=False, errors=["empty hostname"])
    if len(host) > 253:
        return TargetValidation(ok=False, errors=["hostname too long"])
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return TargetValidation(ok=False, errors=["localhost/loopback targets are not allowed"])

    labels = host.split(".")
    if len(labels) < 2:
        return TargetValidation(
            ok=False,
            errors=["target must be a domain with at least two labels (e.g. example.com)"],
        )
    for lab in labels:
        if not lab or not _LABEL.match(lab):
            return TargetValidation(ok=False, errors=[f"invalid DNS label: {lab!r}"])

    return TargetValidation(ok=True, host=host, errors=[])


def validate_budget(
    value: str | int,
    *,
    name: str,
    minimum: int,
    maximum: int,
    default: int,
) -> tuple[int, list[str]]:
    errors: list[str] = []
    if value is None or value == "":
        return default, errors
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default, [f"{name} must be an integer"]
    if n < minimum or n > maximum:
        return default, [f"{name} must be between {minimum} and {maximum}"]
    return n, errors
