"""Configuration management for the file integrity monitor."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["Config", "load_config"]


@dataclass(frozen=True)
class Config:
    scan_path: str
    baseline_path: str | None
    output_path: str | None
    format: str
    algorithm: str
    threads: int
    key: str | None
    rules_path: str | None
    audit_log: str
    config_path: str | None
    exclude: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.threads < 1:
            raise ValueError("threads must be >= 1")
        if self.algorithm not in {"sha256", "sha512"}:
            raise ValueError(f"unsupported algorithm: {self.algorithm}")
        if self.format not in {"console", "json", "csv", "html"}:
            raise ValueError(f"unsupported format: {self.format}")
        if not isinstance(self.exclude, list) or not all(isinstance(x, str) for x in self.exclude):  # pragma: no cover
            raise ValueError("exclude must be a list of strings")


def load_config(
    *,
    scan_path: str = ".",
    baseline_path: str | None = None,
    output_path: str | None = None,
    format: str = "console",
    algorithm: str = "sha256",
    threads: int = 4,
    key: str | None = None,
    rules_path: str | None = None,
    audit_log: str = "fim-audit.log",
    config_path: str | None = None,
    **overrides,
) -> Config:
    """Load configuration from CLI args, environment variables, and JSON config file.

    Precedence (highest to lowest): CLI args > environment variables > config file > defaults.
    """
    merged = {
        "scan_path": scan_path,
        "baseline_path": baseline_path,
        "output_path": output_path,
        "format": format,
        "algorithm": algorithm,
        "threads": threads,
        "key": key,
        "rules_path": rules_path,
        "audit_log": audit_log,
        "config_path": config_path,
        "exclude": [],
    }

    file_config = {}
    if config_path:
        path = Path(config_path)
        if path.exists():
            with open(path, encoding="utf-8") as f:
                file_config = json.load(f)

    env_keys = {
        "baseline_path": "FIM_BASELINE",
        "output_path": "FIM_OUTPUT",
        "format": "FIM_FORMAT",
        "algorithm": "FIM_ALGORITHM",
        "threads": "FIM_THREADS",
        "key": "FIM_KEY",
        "rules_path": "FIM_RULES",
        "audit_log": "FIM_AUDIT_LOG",
        "config_path": "FIM_CONFIG",
    }

    for cfg_key, env_name in env_keys.items():
        if cfg_key in file_config:
            merged[cfg_key] = file_config[cfg_key]
        env_val = os.getenv(env_name)
        if env_val is not None and env_val != "":
            merged[cfg_key] = env_val

    for key, value in overrides.items():
        if value is not None:
            merged[key] = value

    # Resolve @file syntax for key
    key_value = merged.get("key")
    if isinstance(key_value, str) and key_value.startswith("@"):
        key_file = key_value[1:]
        with open(key_file, encoding="utf-8") as f:
            merged["key"] = f.read().strip()

    # Inline exclude patterns from config file (no env var support)
    if "exclude" in file_config:
        val = file_config["exclude"]
        if isinstance(val, list) and all(isinstance(x, str) for x in val):
            merged["exclude"] = val
        else:
            raise ValueError("config 'exclude' must be a list of strings")

    merged["threads"] = int(merged["threads"])

    return Config(**merged)
