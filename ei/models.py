"""Core data contracts for observations, candidates, and run state."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone


class RunStatus(str, Enum):
    """Honest execution states. Failures must never look like clean zeros."""

    NOT_CONFIGURED = "NOT_CONFIGURED"
    NOT_RUN = "NOT_RUN"
    SKIPPED_BY_POLICY = "SKIPPED_BY_POLICY"
    ERROR = "ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    PARTIAL = "PARTIAL"
    COMPLETED_ZERO = "COMPLETED_ZERO"
    COMPLETED_WITH_RESULTS = "COMPLETED_WITH_RESULTS"


class SourceFidelity(str, Enum):
    ORIGINAL = "ORIGINAL"
    EXTRACTED = "EXTRACTED"
    SUMMARY = "SUMMARY"
    AI_INFERENCE = "AI_INFERENCE"
    MIRROR = "MIRROR"
    INDEPENDENTLY_REPRODUCED = "INDEPENDENTLY_REPRODUCED"


class DiscoveryMode(str, Enum):
    PASSIVE_INDEX = "PASSIVE_INDEX"
    HISTORICAL = "HISTORICAL"
    CURRENT_OBSERVATION = "CURRENT_OBSERVATION"
    FIXTURE = "FIXTURE"


class Classification(str, Enum):
    POTENTIALLY_SENSITIVE = "POTENTIALLY_SENSITIVE"
    INTENTIONALLY_PUBLIC = "INTENTIONALLY_PUBLIC"
    GENERIC_ERROR = "GENERIC_ERROR"
    SPA_SHELL = "SPA_SHELL"
    EMPTY_RESPONSE = "EMPTY_RESPONSE"
    HISTORICAL_ONLY = "HISTORICAL_ONLY"
    UNREACHABLE = "UNREACHABLE"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    DUPLICATE = "DUPLICATE"
    IMPACT_UNPROVEN = "IMPACT_UNPROVEN"
    COPIED_RESEARCH = "COPIED_RESEARCH"
    KEYWORD_FALSE_POSITIVE = "KEYWORD_FALSE_POSITIVE"
    UNKNOWN = "UNKNOWN"


class SensitivityClass(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class Freshness(str, Enum):
    CURRENT = "CURRENT"
    HISTORICAL = "HISTORICAL"
    UNKNOWN = "UNKNOWN"


# Content availability semantics (provider observation contract)
CONTENT_PRESENT = "PRESENT"
CONTENT_ABSENT_FROM_SOURCE = "ABSENT_FROM_SOURCE"  # source metadata had no body field
CONTENT_NOT_FETCHED = "NOT_FETCHED"  # index-only; body never retrieved
CONTENT_INACCESSIBLE = "INACCESSIBLE"  # auth/network prevented fetch
CONTENT_CONFIRMED_EMPTY = "CONFIRMED_EMPTY"  # fetched and empty
CONTENT_UNAVAILABLE = "UNAVAILABLE"  # unknown / provider error

SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*['\"]?[^\s'\"]{8,}"), "credential_pattern"),
    (re.compile(r"(?i)AKIA[0-9A-Z]{16}"), "aws_access_key_id"),
    (re.compile(r"(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private_key_pem"),
    (re.compile(r"(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}"), "github_token"),
    (re.compile(r"(?i)github_pat_[A-Za-z0-9_]{20,}"), "github_fine_grained_pat"),
    (re.compile(r"(?i)sk_live_[0-9a-zA-Z]{20,}"), "stripe_live_key"),
    (re.compile(r"(?i)sk_test_[0-9a-zA-Z]{20,}"), "stripe_test_key"),
    (re.compile(r"(?i)whsec_[A-Za-z0-9_]{20,}"), "stripe_webhook_secret"),
    (re.compile(r"(?i)xox[baprs]-"), "slack_token"),
    (re.compile(r"(?i)mongodb(\+srv)?://[^\s'\"]+"), "mongodb_uri"),
    (re.compile(r"(?i)glpat-[A-Za-z0-9_\-]{20,}"), "gitlab_pat"),
    (re.compile(r"(?i)AIza[0-9A-Za-z\-_]{35}"), "google_api_key"),
    (re.compile(r"(?i)SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"), "sendgrid_key"),
    (re.compile(r"(?i)eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "jwt_like"),
    (re.compile(r"(?i)shpat_[a-f0-9]{32}"), "shopify_access_token"),
    (re.compile(r"(?i)shpca_[a-f0-9]{32}"), "shopify_custom_app_token"),
    (re.compile(r"(?i)npm_[A-Za-z0-9]{30,}"), "npm_token"),
]



def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def content_hash(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()


def redact_text(text: str, max_len: int = 512) -> tuple[str, bool]:
    """Redact likely secrets and truncate. Returns (redacted, was_redacted)."""
    if not text:
        return "", False
    redacted = text
    changed = False
    for pattern, _name in SECRET_PATTERNS:
        if pattern.search(redacted):
            redacted = pattern.sub("[REDACTED]", redacted)
            changed = True
    truncated = False
    if len(redacted) > max_len:
        redacted = redacted[:max_len] + "…[truncated]"
        truncated = True
    return redacted, changed or truncated


@dataclass
class Observation:
    """Normalized observation with provenance. Raw secrets are never stored."""

    schema_version: str = "1.0"
    observation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    run_id: str = ""
    target_id: str = ""
    provider: str = "fixture"
    check_family: str = "generic"
    observed_at: str = field(default_factory=utc_now_iso)
    source_url: str = ""
    source_record_id: str = ""
    discovered_url: str = ""
    discovery_mode: str = DiscoveryMode.FIXTURE.value
    source_fidelity: str = SourceFidelity.ORIGINAL.value
    http_status: Optional[int] = None
    content_type: str = ""
    body_byte_count: int = 0
    body_sha256: str = ""
    preview_redacted: str = ""
    body_truncated: bool = False
    redaction_applied: bool = False
    classification: str = Classification.UNKNOWN.value
    classification_reason_codes: list[str] = field(default_factory=list)
    confidence: float = 0.0
    confidence_rationale: str = ""
    sensitivity: str = SensitivityClass.UNKNOWN.value
    freshness: str = Freshness.UNKNOWN.value
    scope_decision: str = "UNKNOWN"
    error_code: str = ""
    error_summary: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Observation":
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


@dataclass
class Candidate:
    """Ranked exposure candidate derived from one or more observations."""

    candidate_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    stable_key: str = ""
    target_id: str = ""
    primary_url: str = ""
    classification: str = Classification.UNKNOWN.value
    sensitivity: str = SensitivityClass.UNKNOWN.value
    freshness: str = Freshness.UNKNOWN.value
    confidence: float = 0.0
    confidence_rationale: str = ""
    impact_hypothesis: str = ""
    impact_confirmed: bool = False
    novelty_score: float = 0.0
    rank_score: float = 0.0
    rank_explanation: list[str] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)
    duplicate_of: str = ""
    review_status: str = "PENDING"
    source_fidelity: str = SourceFidelity.ORIGINAL.value
    evidence_summary: str = ""
    classification_reason_codes: list[str] = field(default_factory=list)
    target_relationship: str = ""
    scope_decision: str = ""
    discovery_mode: str = ""
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProviderRunSummary:
    provider: str
    status: str
    started_at: str = ""
    ended_at: str = ""
    records_received: int = 0
    records_normalized: int = 0
    candidates_emitted: int = 0
    duplicates: int = 0
    error_summary: str = ""
    coverage_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunReport:
    run_id: str
    started_at: str
    ended_at: str = ""
    status: str = RunStatus.NOT_RUN.value
    target_ids: list[str] = field(default_factory=list)
    provider_summaries: list[ProviderRunSummary] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "status": self.status,
            "target_ids": self.target_ids,
            "provider_summaries": [p.to_dict() for p in self.provider_summaries],
            "observations": [o.to_dict() for o in self.observations],
            "candidates": [c.to_dict() for c in self.candidates],
            "metrics": self.metrics,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def stable_candidate_key(url: str, body_sha: str = "") -> str:
    raw = f"{url.strip().lower()}|{body_sha}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]