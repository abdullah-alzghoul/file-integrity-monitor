"""Configuration management for the file integrity monitor."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

__all__ = ["Config", "load_config"]


@dataclass(frozen=True, slots=True)
class Config:
    scan_path: str
    baseline_path: Optional[str]
    output_path: Optional[str]
    format: str
    algorithm: str
    threads: int
    key: Optional[str]
    rules_path: Optional[str]
    audit_log: str
    config_path: Optional[str]

    def __post_init__(self):
        if self.threads < 1:
            raise ValueError("threads must be >= 1")
        if self.algorithm not in {"sha256", "sha512"}:
            raise ValueError(f"unsupported algorithm: {self.algorithm}")
        if self.format not in {"console", "json", "csv", "html"}:
            raise ValueError(f"unsupported format: {self.format}")


def load_config(
    *,
    scan_path: str = ".",
    baseline_path: Optional[str] = None,
    output_path: Optional[str] = None,
    format: str = "console",
    algorithm: str = "sha256",
    threads: int = 4,
    key: Optional[str] = None,
    rules_path: Optional[str] = None,
    audit_log: str = "fim-audit.log",
    config_path: Optional[str] = None,
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
    }

    file_config = {}
    if config_path:
        path = Path(config_path)
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
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
        with open(key_file, "r", encoding="utf-8") as f:
            merged["key"] = f.read().strip()

    merged["threads"] = int(merged["threads"])

    return Config(**merged)
