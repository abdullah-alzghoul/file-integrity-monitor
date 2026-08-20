"""Baseline storage: JSON read/write with optional HMAC signing.

Security note: A signed baseline prevents tampering of content, but an
attacker with filesystem access could perform a rollback attack by
replacing the baseline with an older signed version. The audit log
provides a partial mitigation by recording baseline creation events.
"""

from __future__ import annotations

import json
from pathlib import Path

from fim.crypto import sign, verify
from fim.models import FileRecord

__all__ = ["save_baseline", "load_baseline"]


BASELINE_VERSION = 1


def _canonical_payload(records: list[FileRecord], algorithm: str) -> str:
    """Return a canonical JSON string for signing.

    Sorts records by path to ensure deterministic output.
    """
    data = {
        "version": BASELINE_VERSION,
        "algorithm": algorithm,
        "records": [
            {
                "path": r.path,
                "hash": r.hash,
                "size": r.size,
                "permissions": r.permissions,
                "mtime": r.mtime,
                "algorithm": r.algorithm,
            }
            for r in sorted(records, key=lambda r: r.path)
        ],
    }
    return json.dumps(data, separators=(",", ":"), sort_keys=True)


def save_baseline(
    path: str | Path,
    records: list[FileRecord],
    algorithm: str,
    key: str | None = None,
) -> None:
    """Write baseline to path as JSON. Signs with HMAC if key is provided."""
    payload = _canonical_payload(records, algorithm)
    baseline = {
        "version": BASELINE_VERSION,
        "algorithm": algorithm,
        "records": json.loads(payload)["records"],
    }
    if key is not None:
        baseline["signature"] = sign(payload, key, algorithm=algorithm)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)


def load_baseline(
    path: str | Path,
    key: str | None = None,
) -> tuple[list[FileRecord], str]:
    """Load baseline from path. Verifies HMAC if signature is present.

    Returns (records, algorithm).
    Raises ValueError if signature verification fails or baseline is malformed.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("baseline must be a JSON object")

    version = data.get("version")
    if version != BASELINE_VERSION:
        raise ValueError(f"unsupported baseline version: {version}")

    algorithm = data.get("algorithm", "sha256")
    records_data = data.get("records", [])
    if not isinstance(records_data, list):
        raise ValueError("baseline records must be a list")

    records = [
        FileRecord(
            path=r["path"],
            hash=r["hash"],
            size=r["size"],
            permissions=r["permissions"],
            mtime=r["mtime"],
            algorithm=r.get("algorithm", algorithm),  # pragma: no cover (backward compatibility)
        )
        for r in records_data
    ]

    signature = data.get("signature")
    if signature is not None:
        if key is None:
            raise ValueError("baseline is signed but no key was provided")
        payload = _canonical_payload(records, algorithm)
        if not verify(payload, signature, key, algorithm=algorithm):
            raise ValueError("baseline signature verification failed")

    return records, algorithm
