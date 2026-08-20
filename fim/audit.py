"""Append-only audit logging for file integrity monitoring operations.

Security note: Threading.Lock protects against concurrent threads within
a single process. Multiple simultaneous CLI invocations could interleave
JSON Lines in the same audit log file.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fim.models import ChangeType, ScanResult

__all__ = ["AuditLogger"]


class AuditLogger:
    """Thread-safe append-only audit logger using JSON Lines format."""

    def __init__(self, log_path: str | Path) -> None:
        self._log_path = Path(log_path)
        self._lock = threading.Lock()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _write(self, entry: dict) -> None:
        with self._lock:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")

    def log_baseline_created(
        self,
        baseline_path: str,
        scan_path: str,
        file_count: int,
        algorithm: str,
        signed: bool,
    ) -> None:
        self._write(
            {
                "timestamp": self._now(),
                "event": "baseline_created",
                "baseline_path": baseline_path,
                "scan_path": scan_path,
                "file_count": file_count,
                "algorithm": algorithm,
                "signed": signed,
            }
        )

    def log_scan_started(
        self,
        scan_path: str,
        baseline_path: Optional[str],
    ) -> None:
        self._write(
            {
                "timestamp": self._now(),
                "event": "scan_started",
                "scan_path": scan_path,
                "baseline_path": baseline_path,
            }
        )

    def log_scan_completed(self, result: ScanResult) -> None:
        summary = {
            "added": 0,
            "deleted": 0,
            "modified": 0,
            "moved": 0,
            "permission_changed": 0,
        }
        for change in result.changes:
            if change.change_type == ChangeType.ADDED:
                summary["added"] += 1
            elif change.change_type == ChangeType.DELETED:
                summary["deleted"] += 1
            elif change.change_type == ChangeType.MODIFIED:
                summary["modified"] += 1
            elif change.change_type == ChangeType.MOVED:
                summary["moved"] += 1
            elif change.change_type == ChangeType.PERMISSION_CHANGED:
                summary["permission_changed"] += 1

        self._write(
            {
                "timestamp": self._now(),
                "event": "scan_completed",
                "scan_path": result.scan_path,
                "baseline_path": result.baseline_path,
                "files_scanned": result.files_scanned,
                "changes_total": len(result.changes),
                "changes_summary": summary,
            }
        )