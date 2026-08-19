"""Pattern-based file filtering for the file integrity monitor."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path

__all__ = ["RuleSet", "load_rules"]


class RuleSet:
    """A collection of include/exclude patterns."""

    def __init__(self, excludes: list[str]) -> None:
        self.excludes = excludes

    def is_ignored(self, path: str | Path) -> bool:
        """Return True if the given path matches any exclude pattern."""
        rel_path = str(path).replace(os.sep, "/")
        name = Path(rel_path).name

        for pattern in self.excludes:
            if pattern.endswith("/"):
                if rel_path.startswith(pattern.rstrip("/") + "/"):
                    return True
                if rel_path == pattern.rstrip("/"):
                    return True
            if fnmatch.fnmatch(rel_path, pattern):
                return True
            if fnmatch.fnmatch(name, pattern):
                return True
        return False


def load_rules(path: str | Path | None) -> RuleSet:
    """Load exclude patterns from a file, one per line.

    Blank lines and lines starting with '#' are ignored.
    """
    if path is None:
        return RuleSet([])

    rules_path = Path(path)
    if not rules_path.exists():
        return RuleSet([])

    excludes: list[str] = []
    with open(rules_path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            excludes.append(stripped)
    return RuleSet(excludes)