"""SQLite persistence for runs, observations, and candidates."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Optional

from ei.models import Candidate, Observation, RunReport, utc_now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    started_at TEXT,
    ended_at TEXT,
    status TEXT,
    profile_version TEXT,
    metrics_json TEXT,
    provider_summaries_json TEXT,
    report_json TEXT
);

CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    target_id TEXT,
    provider TEXT,
    discovered_url TEXT,
    body_sha256 TEXT,
    stable_key TEXT,
    classification TEXT,
    sensitivity TEXT,
    freshness TEXT,
    source_fidelity TEXT,
    discovery_mode TEXT,
    observed_at TEXT,
    payload_json TEXT,
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS candidates (
    candidate_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    target_id TEXT,
    stable_key TEXT,
    primary_url TEXT,
    classification TEXT,
    sensitivity TEXT,
    confidence REAL,
    rank_score REAL,
    review_status TEXT,
    first_seen_run_id TEXT,
    last_seen_run_id TEXT,
    change_type TEXT,
    payload_json TEXT,
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_obs_target ON observations(target_id);
CREATE INDEX IF NOT EXISTS idx_obs_key ON observations(stable_key);
CREATE INDEX IF NOT EXISTS idx_cand_target ON candidates(target_id);
CREATE INDEX IF NOT EXISTS idx_cand_key ON candidates(stable_key);
CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target_id, started_at);
"""


class ResearchStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def save_run(self, report: RunReport, *, profile_version: str = "") -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO runs(
                run_id, target_id, started_at, ended_at, status,
                profile_version, metrics_json, provider_summaries_json, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.run_id,
                report.target_ids[0] if report.target_ids else "",
                report.started_at,
                report.ended_at,
                report.status,
                profile_version,
                json.dumps(report.metrics),
                json.dumps([p.to_dict() for p in report.provider_summaries]),
                report.to_json(),
            ),
        )
        for obs in report.observations:
            from ei.models import stable_candidate_key

            key = stable_candidate_key(obs.discovered_url, obs.body_sha256)
            self._conn.execute(
                """
                INSERT OR REPLACE INTO observations(
                    observation_id, run_id, target_id, provider, discovered_url,
                    body_sha256, stable_key, classification, sensitivity, freshness,
                    source_fidelity, discovery_mode, observed_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    obs.observation_id,
                    report.run_id,
                    obs.target_id,
                    obs.provider,
                    obs.discovered_url,
                    obs.body_sha256,
                    key,
                    obs.classification,
                    obs.sensitivity,
                    obs.freshness,
                    obs.source_fidelity,
                    obs.discovery_mode,
                    obs.observed_at,
                    json.dumps(obs.to_dict()),
                ),
            )
        for cand in report.candidates:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO candidates(
                    candidate_id, run_id, target_id, stable_key, primary_url,
                    classification, sensitivity, confidence, rank_score, review_status,
                    first_seen_run_id, last_seen_run_id, change_type, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cand.candidate_id,
                    report.run_id,
                    cand.target_id,
                    cand.stable_key,
                    cand.primary_url,
                    cand.classification,
                    cand.sensitivity,
                    cand.confidence,
                    cand.rank_score,
                    cand.review_status,
                    report.run_id,
                    report.run_id,
                    getattr(cand, "change_type", "") if hasattr(cand, "change_type") else "",
                    json.dumps(cand.to_dict()),
                ),
            )
        self._conn.commit()

    def list_runs(self, target_id: str, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT run_id, target_id, started_at, ended_at, status, metrics_json
            FROM runs WHERE target_id = ? ORDER BY started_at DESC LIMIT ?
            """,
            (target_id, limit),
        ).fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "run_id": r["run_id"],
                    "target_id": r["target_id"],
                    "started_at": r["started_at"],
                    "ended_at": r["ended_at"],
                    "status": r["status"],
                    "metrics": json.loads(r["metrics_json"] or "{}"),
                }
            )
        return out

    def previous_run_id(self, target_id: str, current_run_id: str) -> Optional[str]:
        rows = self._conn.execute(
            """
            SELECT run_id FROM runs
            WHERE target_id = ? AND run_id != ?
            ORDER BY started_at DESC LIMIT 1
            """,
            (target_id, current_run_id),
        ).fetchall()
        return rows[0]["run_id"] if rows else None

    def candidate_keys_for_run(self, run_id: str) -> set[str]:
        rows = self._conn.execute(
            "SELECT stable_key, primary_url FROM candidates WHERE run_id = ?",
            (run_id,),
        ).fetchall()
        keys = set()
        for r in rows:
            if r["stable_key"]:
                keys.add(r["stable_key"])
            if r["primary_url"]:
                keys.add("url:" + r["primary_url"].lower())
        return keys

    def observation_keys_for_run(self, run_id: str) -> set[str]:
        rows = self._conn.execute(
            "SELECT stable_key FROM observations WHERE run_id = ?",
            (run_id,),
        ).fetchall()
        return {r["stable_key"] for r in rows if r["stable_key"]}

    def load_run_report(self, run_id: str) -> Optional[dict[str, Any]]:
        row = self._conn.execute(
            "SELECT report_json FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if not row:
            return None
        return json.loads(row["report_json"])

    def queue_for_target(self, target_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """Latest candidates per primary_url for a target, ordered by rank."""
        rows = self._conn.execute(
            """
            SELECT c.* FROM candidates c
            INNER JOIN (
                SELECT primary_url, MAX(run_id) AS max_run
                FROM candidates WHERE target_id = ?
                GROUP BY primary_url
            ) t ON c.primary_url = t.primary_url AND c.run_id = t.max_run
            WHERE c.target_id = ?
            ORDER BY c.rank_score DESC
            LIMIT ?
            """,
            (target_id, target_id, limit),
        ).fetchall()
        return [json.loads(r["payload_json"]) for r in rows]
