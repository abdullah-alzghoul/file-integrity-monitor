"""Core scanning and change detection engine."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fim.audit import AuditLogger
from fim.hasher import hash_directory
from fim.models import Change, ChangeType, FileRecord, ScanResult
from fim.rules import RuleSet
from fim.storage import load_baseline, save_baseline

__all__ = ["create_baseline", "scan_directory"]


def create_baseline(
    scan_path: str,
    baseline_path: str,
    rules: RuleSet,
    algorithm: str,
    threads: int,
    key: Optional[str],
    audit_logger: Optional[AuditLogger],
) -> None:
    """Create a new baseline by hashing all files under scan_path."""
    path = Path(scan_path)
    if not path.exists():
        raise FileNotFoundError(f"scan path does not exist: {scan_path}")
    if not path.is_dir():
        raise NotADirectoryError(f"scan path is not a directory: {scan_path}")

    records = hash_directory(scan_path, rules, algorithm, threads)
    save_baseline(baseline_path, records, algorithm, key)
    if audit_logger:
        audit_logger.log_baseline_created(
            baseline_path=baseline_path,
            scan_path=scan_path,
            file_count=len(records),
            algorithm=algorithm,
            signed=key is not None,
        )


def scan_directory(
    scan_path: str,
    baseline_path: str,
    rules: RuleSet,
    algorithm: str,
    threads: int,
    key: Optional[str],
    audit_logger: Optional[AuditLogger],
) -> ScanResult:
    """Scan scan_path and compare against baseline. Return ScanResult."""
    path = Path(scan_path)
    if not path.exists():
        raise FileNotFoundError(f"scan path does not exist: {scan_path}")
    if not path.is_dir():
        raise NotADirectoryError(f"scan path is not a directory: {scan_path}")

    if audit_logger:
        audit_logger.log_scan_started(scan_path, baseline_path)

    baseline_records, baseline_algorithm = load_baseline(baseline_path, key)
    current_records = hash_directory(scan_path, rules, algorithm, threads)

    changes = _detect_changes(baseline_records, current_records)

    result = ScanResult(
        baseline_path=baseline_path,
        scan_path=scan_path,
        changes=changes,
        timestamp=datetime.now(timezone.utc).isoformat(),
        files_scanned=len(current_records),
    )

    if audit_logger:
        audit_logger.log_scan_completed(result)

    return result


def _detect_changes(
    baseline: list[FileRecord],
    current: list[FileRecord],
) -> list[Change]:
    """Compare baseline and current records to produce a list of changes."""
    baseline_by_path = {r.path: r for r in baseline}
    current_by_path = {r.path: r for r in current}

    baseline_by_hash: dict[str, list[FileRecord]] = defaultdict(list)
    for r in baseline:
        baseline_by_hash[r.hash].append(r)

    current_by_hash: dict[str, list[FileRecord]] = defaultdict(list)
    for r in current:
        current_by_hash[r.hash].append(r)

    changes: list[Change] = []
    moved_baseline_paths: set[str] = set()
    moved_current_paths: set[str] = set()

    # Detect moved files
    for hash_val, baseline_records in baseline_by_hash.items():
        if hash_val not in current_by_hash:
            continue
        current_records_with_hash = current_by_hash[hash_val]

        unmatched_baseline = [
            r for r in baseline_records
            if r.path not in current_by_path
        ]
        unmatched_current = [
            r for r in current_records_with_hash
            if r.path not in baseline_by_path
        ]

        pairs = min(len(unmatched_baseline), len(unmatched_current))
        for i in range(pairs):
            changes.append(
                Change(
                    change_type=ChangeType.MOVED,
                    record=unmatched_current[i],
                    previous_record=unmatched_baseline[i],
                )
            )
            moved_baseline_paths.add(unmatched_baseline[i].path)
            moved_current_paths.add(unmatched_current[i].path)

    # Detect added files
    for path, record in current_by_path.items():
        if path not in baseline_by_path and path not in moved_current_paths:
            changes.append(
                Change(
                    change_type=ChangeType.ADDED,
                    record=record,
                    previous_record=None,
                )
            )

    # Detect deleted files
    for path, record in baseline_by_path.items():
        if path not in current_by_path and path not in moved_baseline_paths:
            changes.append(
                Change(
                    change_type=ChangeType.DELETED,
                    record=None,
                    previous_record=record,
                )
            )

    # Detect modified and permission-changed files
    for path in set(baseline_by_path.keys()) & set(current_by_path.keys()):
        baseline_record = baseline_by_path[path]
        current_record = current_by_path[path]

        if baseline_record.hash != current_record.hash:
            changes.append(
                Change(
                    change_type=ChangeType.MODIFIED,
                    record=current_record,
                    previous_record=baseline_record,
                )
            )
        elif baseline_record.permissions != current_record.permissions:
            changes.append(
                Change(
                    change_type=ChangeType.PERMISSION_CHANGED,
                    record=current_record,
                    previous_record=baseline_record,
                )
            )

    return changes