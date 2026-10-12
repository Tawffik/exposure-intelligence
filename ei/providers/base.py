"""Shared provider collect result contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


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
    provider: str = ""
    actual_queries: list[str] = field(default_factory=list)
