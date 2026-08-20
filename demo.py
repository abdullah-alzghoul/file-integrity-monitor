"""Demonstration script for the File Integrity Monitor.

Creates a temporary directory, generates a baseline, simulates changes,
and runs a scan with console output.
"""

import os
import shutil
import tempfile
from pathlib import Path

from fim.cli import run


def main() -> None:
    temp_dir = tempfile.mkdtemp()
    scan_dir = os.path.join(temp_dir, "demo")
    os.makedirs(scan_dir)
    baseline_path = os.path.join(temp_dir, "baseline.json")

    try:
        # Create initial files
        (Path(scan_dir) / "config.ini").write_text("setting=value\n")
        (Path(scan_dir) / "data.txt").write_text("original data\n")

        print("=" * 60)
        print("Step 1: Creating baseline")
        print("=" * 60)
        rc = run(["baseline", scan_dir, "-o", baseline_path])
        print(f"Baseline creation exit code: {rc}")
        print()

        # Simulate changes
        (Path(scan_dir) / "data.txt").write_text("modified data\n")
        (Path(scan_dir) / "new_file.txt").write_text("new content\n")
        os.remove(Path(scan_dir) / "config.ini")

        print("=" * 60)
        print("Step 2: Scanning for changes")
        print("=" * 60)
        rc = run(["scan", scan_dir, "-b", baseline_path])
        print(f"Scan exit code: {rc}")
        print()

    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    main()