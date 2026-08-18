"""Data models for the file integrity monitor."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

__all__ = ["ChangeType", "FileRecord", "Change", "ScanResult"]


class ChangeType(enum.Enum):
    ADDED = "added"
    DELETED = "deleted"
    MODIFIED = "modified"
    MOVED = "moved"
    PERMISSION_CHANGED = "permission_changed"


@dataclass(frozen=True, slots=True)
class FileRecord:
    path: str
    hash: str
    size: int
    permissions: int
    mtime: float
    algorithm: str

    @property
    def path_obj(self) -> Path:
        return Path(self.path)


@dataclass(frozen=True, slots=True)
class Change:
    change_type: ChangeType
    record: Optional[FileRecord]
    previous_record: Optional[FileRecord]
    diff_preview: Optional[str] = None


@dataclass(frozen=True, slots=True)
class ScanResult:
    baseline_path: Optional[str]
    scan_path: str
    changes: list[Change]
    timestamp: str
    files_scanned: int
