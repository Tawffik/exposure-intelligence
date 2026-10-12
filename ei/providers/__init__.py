"""Passive provider adapters. Each normalizes source records into EI observations."""

from ei.providers.github_code_search import (
    GitHubCodeSearchProvider,
    normalize_github_search_response,
)

__all__ = [
    "GitHubCodeSearchProvider",
    "normalize_github_search_response",
]