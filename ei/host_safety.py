"""Conservative local / private / special-use host classification.

Policy (explicit — do not rely on a single ipaddress property alone):
- IPv4 loopback 127.0.0.0/8
- IPv4 private RFC1918: 10/8, 172.16/12, 192.168/16
- IPv4 unspecified 0.0.0.0
- IPv6 loopback ::1
- IPv6 unique-local fc00::/7
- IPv6 link-local fe80::/10
- IPv6 unspecified ::
- IPv4-mapped IPv6 forms of the above
- Hostname localhost and labels ending in .localhost (RFC 6761)

Public hosts (including documentation TEST-NET ranges) are never classified
as private by substring tricks such as matching "10." in a path or query.

No DNS resolution, no network I/O.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_LOCALHOST_LABEL_RE = re.compile(r"(?i)^(.+\.)?localhost$")


def _hostname_from_url_or_host(value: str) -> str | None:
    """Extract hostname from a URL or bare host string. No network."""
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    # Bare host / host:port without scheme
    if "://" not in raw:
        # Bracketed IPv6 with optional port: [fe80::1]:8080
        if raw.startswith("["):
            end = raw.find("]")
            if end > 1:
                return raw[1:end].strip() or None
        # host:port (avoid splitting IPv6 without brackets)
        if raw.count(":") == 1:
            host, _, _port = raw.partition(":")
            return host.strip() or None
        return raw.split("/")[0].strip() or None

    try:
        parsed = urlparse(raw)
    except Exception:
        return None
    host = parsed.hostname  # strips brackets and userinfo; handles ports
    if host is None:
        return None
    return host.strip() or None


def _ip_is_local_or_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Explicit policy over ipaddress categories."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _ip_is_local_or_private(ip.ipv4_mapped)

    if isinstance(ip, ipaddress.IPv4Address):
        if ip.is_loopback:  # 127.0.0.0/8
            return True
        if ip.is_unspecified:  # 0.0.0.0
            return True
        # RFC1918 only (not all is_private, which may include other specials)
        return (
            ip in ipaddress.ip_network("10.0.0.0/8")
            or ip in ipaddress.ip_network("172.16.0.0/12")
            or ip in ipaddress.ip_network("192.168.0.0/16")
        )

    # IPv6
    if ip.is_loopback or ip.is_unspecified:
        return True
    if ip in ipaddress.ip_network("fc00::/7"):  # unique local
        return True
    if ip in ipaddress.ip_network("fe80::/10"):  # link-local
        return True
    return False


def is_private_or_local_host(url_or_host: str) -> bool:
    """True if the authority is loopback, RFC1918, ULA, link-local, or localhost.

    Malformed inputs return False (do not invent safety from garbage — callers
    still apply LOW_PRIORITY / attribution gates).
    """
    host = _hostname_from_url_or_host(url_or_host)
    if not host:
        return False

    if _LOCALHOST_LABEL_RE.match(host):
        return True

    # Strip zone id if present (fe80::1%eth0) — rare in URLs
    if "%" in host:
        host = host.split("%", 1)[0]

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Non-IP hostname that is not localhost → not local by this policy
        return False

    return _ip_is_local_or_private(ip)


def local_or_private_next_step_message() -> str:
    return (
        "Likely local-only or private-network credentials — do not report without "
        "production host evidence under program scope."
    )
