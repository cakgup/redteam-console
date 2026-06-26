from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class JobStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                  id TEXT PRIMARY KEY,
                  scope_type TEXT NOT NULL,
                  scope_label TEXT NOT NULL,
                  target TEXT NOT NULL,
                  note TEXT NOT NULL,
                  status TEXT NOT NULL,
                  progress INTEGER NOT NULL DEFAULT 0,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  module_ids TEXT NOT NULL,
                  logs TEXT NOT NULL,
                  severity_summary TEXT NOT NULL DEFAULT '{}',
                  evidence TEXT NOT NULL DEFAULT '[]',
                  module_runs TEXT NOT NULL DEFAULT '[]',
                  runtime_meta TEXT NOT NULL DEFAULT '{}'
                )
                """
            )

            existing_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
            }

            migrations = {
                "progress": "ALTER TABLE jobs ADD COLUMN progress INTEGER NOT NULL DEFAULT 0",
                "severity_summary": "ALTER TABLE jobs ADD COLUMN severity_summary TEXT NOT NULL DEFAULT '{}'",
                "evidence": "ALTER TABLE jobs ADD COLUMN evidence TEXT NOT NULL DEFAULT '[]'",
                "module_runs": "ALTER TABLE jobs ADD COLUMN module_runs TEXT NOT NULL DEFAULT '[]'",
                "runtime_meta": "ALTER TABLE jobs ADD COLUMN runtime_meta TEXT NOT NULL DEFAULT '{}'",
            }

            for column, statement in migrations.items():
                if column not in existing_columns:
                    connection.execute(statement)

            connection.commit()

    def create_job(self, payload: dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                  id, scope_type, scope_label, target, note, status, progress,
                  created_at, updated_at, module_ids, logs, severity_summary, evidence, module_runs, runtime_meta
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["id"],
                    payload["scope_type"],
                    payload["scope_label"],
                    payload["target"],
                    payload["note"],
                    payload["status"],
                    payload["progress"],
                    payload["created_at"],
                    payload["updated_at"],
                    json.dumps(payload["module_ids"]),
                    json.dumps(payload["logs"]),
                    json.dumps(payload["severity_summary"]),
                    json.dumps(payload["evidence"]),
                    json.dumps(payload["module_runs"]),
                    json.dumps(payload.get("runtime_meta", {})),
                ),
            )
            connection.commit()

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM jobs
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [self._deserialize(row) for row in rows]

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
        return self._deserialize(row) if row else None

    def update_job(
        self,
        job_id: str,
        *,
        status: str | None = None,
        progress: int | None = None,
        logs: list[dict[str, Any]] | None = None,
        severity_summary: dict[str, int] | None = None,
        evidence: list[dict[str, Any]] | None = None,
        module_runs: list[dict[str, Any]] | None = None,
        runtime_meta: dict[str, Any] | None = None,
        updated_at: str,
    ) -> None:
        current = self.get_job(job_id)
        if not current:
            return

        next_status = status or current["status"]
        next_progress = current["progress"] if progress is None else progress
        next_logs = logs if logs is not None else current["logs"]
        next_severity = severity_summary if severity_summary is not None else current["severity_summary"]
        next_evidence = evidence if evidence is not None else current["evidence"]
        next_module_runs = module_runs if module_runs is not None else current["module_runs"]
        next_runtime_meta = runtime_meta if runtime_meta is not None else current.get("runtime_meta", {})

        with self._connect() as connection:
            connection.execute(
                """
                UPDATE jobs
                SET status = ?, progress = ?, updated_at = ?, logs = ?, severity_summary = ?, evidence = ?, module_runs = ?, runtime_meta = ?
                WHERE id = ?
                """,
                (
                    next_status,
                    next_progress,
                    updated_at,
                    json.dumps(next_logs),
                    json.dumps(next_severity),
                    json.dumps(next_evidence),
                    json.dumps(next_module_runs),
                    json.dumps(next_runtime_meta),
                    job_id,
                ),
            )
            connection.commit()

    def delete_job(self, job_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
            connection.commit()
        return int(cursor.rowcount or 0) > 0

    def delete_all_jobs(self) -> int:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM jobs")
            connection.commit()
        return int(cursor.rowcount or 0)

    def _deserialize(self, row: sqlite3.Row) -> dict[str, Any]:
        logs = self._normalize_logs(json.loads(row["logs"]))
        severity_summary = self._ensure_dict(json.loads(row["severity_summary"]))
        evidence = self._ensure_list(json.loads(row["evidence"]))
        module_runs = self._ensure_list(json.loads(row["module_runs"]))
        runtime_meta = self._ensure_dict_generic(json.loads(row["runtime_meta"])) if "runtime_meta" in row.keys() else {}

        return {
            "id": row["id"],
            "scope_type": row["scope_type"],
            "scope_label": row["scope_label"],
            "target": row["target"],
            "note": row["note"],
            "status": row["status"],
            "progress": int(row["progress"] or 0),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "module_ids": self._ensure_list(json.loads(row["module_ids"])),
            "logs": logs,
            "severity_summary": severity_summary,
            "evidence": evidence,
            "module_runs": module_runs,
            "runtime_meta": runtime_meta,
        }

    def _normalize_logs(self, logs: Any) -> list[dict[str, Any]]:
        if not isinstance(logs, list):
            return []

        normalized: list[dict[str, Any]] = []
        for entry in logs:
            if isinstance(entry, dict):
                normalized.append(
                    {
                        "timestamp": str(entry.get("timestamp") or ""),
                        "severity": str(entry.get("severity") or "info"),
                        "message": str(entry.get("message") or ""),
                    }
                )
            else:
                normalized.append(
                    {
                        "timestamp": "",
                        "severity": "info",
                        "message": str(entry),
                    }
                )
        return normalized

    def _ensure_dict(self, value: Any) -> dict[str, int]:
        if not isinstance(value, dict):
            return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        base = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for key in base:
            try:
                base[key] = int(value.get(key, 0))
            except (TypeError, ValueError):
                base[key] = 0
        return base

    def _ensure_list(self, value: Any) -> list[Any]:
        return value if isinstance(value, list) else []

    def _ensure_dict_generic(self, value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}
