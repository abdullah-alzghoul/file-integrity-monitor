"""Unified diff preview generation for modified files."""

from __future__ import annotations

import difflib
from pathlib import Path

__all__ = ["generate_diff_preview"]


MAX_DIFF_LINES = 50


def _is_binary(path: str | Path) -> bool:
    """Heuristic: read first 8KB and check for null bytes."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(8192)
            return b"\x00" in chunk
    except (OSError, PermissionError):
        return True


def generate_diff_preview(
    old_path: str | Path,
    new_path: str | Path,
    max_lines: int = MAX_DIFF_LINES,
) -> str | None:
    """Return a unified diff preview between old_path and new_path.

    Returns None if either file is binary, unreadable, or does not exist.
    """
    if _is_binary(old_path) or _is_binary(new_path):
        return None

    try:
        with open(old_path, "r", encoding="utf-8", errors="replace") as f:
            old_lines = f.read().splitlines()
        with open(new_path, "r", encoding="utf-8", errors="replace") as f:
            new_lines = f.read().splitlines()
    except (OSError, PermissionError):
        return None

    diff = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=str(old_path),
            tofile=str(new_path),
            lineterm="",
        )
    )

    if len(diff) > max_lines:
        diff = diff[:max_lines]
        diff.append(f"... ({len(diff)} lines truncated)")

    return "\n".join(diff) if diff else None