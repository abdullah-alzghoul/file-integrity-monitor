"""Tests for fim.audit — append-only audit logging."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from fim.audit import AuditLogger
from fim.models import Change, ChangeType, FileRecord, ScanResult


class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False)
        self.temp_file.close()
        self.logger = AuditLogger(self.temp_file.name)

    def tearDown(self):
        os.unlink(self.temp_file.name)

    def _read_lines(self):
        with open(self.temp_file.name, "r") as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_log_baseline_created(self):
        self.logger.log_baseline_created(
            baseline_path="baseline.json",
            scan_path=".",
            file_count=10,
            algorithm="sha256",
            signed=True,
        )
        lines = self._read_lines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["event"], "baseline_created")
        self.assertEqual(lines[0]["file_count"], 10)
        self.assertTrue(lines[0]["signed"])
        self.assertIn("timestamp", lines[0])

    def test_log_scan_started(self):
        self.logger.log_scan_started(scan_path=".", baseline_path="baseline.json")
        lines = self._read_lines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["event"], "scan_started")
        self.assertEqual(lines[0]["baseline_path"], "baseline.json")

    def test_log_scan_completed_no_changes(self):
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[],
            timestamp="2026-01-01T00:00:00",
            files_scanned=5,
        )
        self.logger.log_scan_completed(result)
        lines = self._read_lines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["event"], "scan_completed")
        self.assertEqual(lines[0]["changes_total"], 0)
        self.assertEqual(lines[0]["changes_summary"]["added"], 0)

    def test_log_scan_completed_with_changes(self):
        record = FileRecord(
            path="test.txt",
            hash="abc",
            size=1,
            permissions=0o644,
            mtime=1.0,
            algorithm="sha256",
        )
        changes = [
            Change(ChangeType.ADDED, record, None),
            Change(ChangeType.DELETED, None, record),
            Change(ChangeType.MODIFIED, record, record),
            Change(ChangeType.MOVED, record, record),
            Change(ChangeType.PERMISSION_CHANGED, record, record),
        ]
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=changes,
            timestamp="2026-01-01T00:00:00",
            files_scanned=5,
        )
        self.logger.log_scan_completed(result)
        lines = self._read_lines()
        self.assertEqual(len(lines), 1)
        summary = lines[0]["changes_summary"]
        self.assertEqual(summary["added"], 1)
        self.assertEqual(summary["deleted"], 1)
        self.assertEqual(summary["modified"], 1)
        self.assertEqual(summary["moved"], 1)
        self.assertEqual(summary["permission_changed"], 1)

    def test_multiple_entries_append(self):
        self.logger.log_scan_started(".", None)
        self.logger.log_baseline_created("b.json", ".", 1, "sha256", False)
        lines = self._read_lines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["event"], "scan_started")
        self.assertEqual(lines[1]["event"], "baseline_created")

    def test_file_created_if_missing(self):
        new_path = os.path.join(tempfile.gettempdir(), "fim_audit_test.log")
        if os.path.exists(new_path):
            os.unlink(new_path)
        logger = AuditLogger(new_path)
        logger.log_scan_started(".", None)
        self.assertTrue(os.path.exists(new_path))
        os.unlink(new_path)


if __name__ == "__main__":
    unittest.main()