"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import time


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[tuple[str, str], dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Start an audit record and retain its monotonic start time."""
        key = (user_id, request_id or user_id)
        entry = {
            "request_id": request_id,
            "user_id": user_id,
            "input": text,
            "started_at": utc_now_iso(),
            "output": None,
            "blocked": None,
            "layer": None,
            "latency_ms": None,
            "_started_monotonic": time.perf_counter(),
        }
        self._open[key] = entry
        self.logs.append(entry)

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete the matching interaction with output and latency."""
        key = (user_id, request_id or user_id)
        entry = self._open.pop(key, None)
        if entry is None:
            entry = {
                "request_id": request_id,
                "user_id": user_id,
                "input": None,
                "started_at": utc_now_iso(),
            }
            self.logs.append(entry)

        started = entry.pop("_started_monotonic", time.perf_counter())
        entry.update(
            {
                "output": text,
                "blocked": blocked,
                "layer": layer,
                "completed_at": utc_now_iso(),
                "latency_ms": round((time.perf_counter() - started) * 1000, 3),
            }
        )

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        serializable_logs = [
            {key: value for key, value in entry.items() if not key.startswith("_")}
            for entry in self.logs
        ]
        path.write_text(
            json.dumps(serializable_logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
