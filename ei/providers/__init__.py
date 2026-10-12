"""Passive provider adapters. Each normalizes source records into EI observations."""

from ei.providers.cdx import CDXProvider, normalize_cdx_payload
from ei.providers.github_code_search import (
    GitHubCodeSearchProvider,
    normalize_github_search_response,
)
from ei.providers.urlscan import URLScanProvider, normalize_urlscan_search_response

__all__ = [
    "GitHubCodeSearchProvider",
    "normalize_github_search_response",
    "URLScanProvider",
    "normalize_urlscan_search_response",
    "CDXProvider",
    "normalize_cdx_payload",
]
