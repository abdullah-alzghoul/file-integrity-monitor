"""Cryptographic hashing for file integrity monitoring.

Security note: No maximum file size limit is enforced. Hashing very large
files will consume CPU and time proportionally.
"""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

from fim.models import FileRecord
from fim.rules import RuleSet

__all__ = ["hash_file", "hash_directory"]


def hash_file(path: str | Path, algorithm: str = "sha256") -> str:
    """Return the hex digest of a file using the specified algorithm."""
    if algorithm not in {"sha256", "sha512"}:
        raise ValueError(f"unsupported algorithm: {algorithm}")

    hasher = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _hash_single(path: Path, algorithm: str) -> Optional[FileRecord]:
    """Hash a single file and return its FileRecord, or None if unreadable."""
    try:
        stat = path.stat()
        file_hash = hash_file(path, algorithm)
        return FileRecord(
            path=str(path),
            hash=file_hash,
            size=stat.st_size,
            permissions=stat.st_mode,
            mtime=stat.st_mtime,
            algorithm=algorithm,
        )
    except (OSError, PermissionError):
        return None


def hash_directory(
    root: str | Path,
    rules: RuleSet,
    algorithm: str = "sha256",
    threads: int = 4,
) -> list[FileRecord]:
    """Recursively hash all files under root, respecting exclusion rules."""
    root_path = Path(root).resolve()
    root_str = str(root_path)
    files_to_hash: list[Path] = []

    for dirpath, dirnames, filenames in os.walk(root_str):
        rel_dir = Path(dirpath).relative_to(root_path)

        dirnames[:] = [
            d for d in dirnames
            if not rules.is_ignored(rel_dir / d)
        ]

        for filename in filenames:
            file_path = Path(dirpath) / filename
            if file_path.is_symlink():
                continue
            rel_path = rel_dir / filename
            if not rules.is_ignored(rel_path):
                files_to_hash.append(file_path)

    results: list[FileRecord] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(_hash_single, fp, algorithm)
            for fp in files_to_hash
        ]
        for future in futures:
            record = future.result()
            if record is not None:
                results.append(record)

    return results