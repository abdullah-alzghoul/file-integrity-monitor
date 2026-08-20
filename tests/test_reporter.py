"""Tests for fim.reporter — output formatting for console, JSON, CSV, and HTML."""

import csv
import io
import json
import os
import tempfile
import unittest

from fim.models import Change, ChangeType, FileRecord, ScanResult
from fim.reporter import report


class TestConsoleReport(unittest.TestCase):
    def test_console_diff_preview_truncation(self):
        long_diff = "\n".join([f"line{i}" for i in range(10)])
        record = FileRecord(
            path="test.txt",
            hash="a" * 64,
            size=100,
            permissions=0o644,
            mtime=1.0,
            algorithm="sha256",
        )
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[
                Change(ChangeType.MODIFIED, record, record, diff_preview=long_diff),
            ],
            timestamp="2026-01-01T00:00:00",
            files_scanned=1,
        )
        output = report(result, "console")
        self.assertIn("Diff preview:", output)
        self.assertIn("...", output)

    def test_console_moved_and_permission_changed(self):
        record = FileRecord(
            path="test.txt",
            hash="a" * 64,
            size=1024,
            permissions=0o644,
            mtime=1.0,
            algorithm="sha256",
        )
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[
                Change(ChangeType.MOVED, record, record),
                Change(ChangeType.PERMISSION_CHANGED, record, record),
            ],
            timestamp="2026-01-01T00:00:00",
            files_scanned=2,
        )
        output = report(result, "console")
        self.assertIn("[MOVED]", output)
        self.assertIn("[PERMISSION_CHANGED]", output)
        self.assertIn("Permissions:", output)

    def test_no_changes(self):
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[],
            timestamp="2026-01-01T00:00:00",
            files_scanned=5,
        )
        output = report(result, "console")
        self.assertIn("No changes detected", output)
        self.assertIn("Files Scanned: 5", output)

    def test_with_changes(self):
        record = FileRecord(
            path="test.txt",
            hash="a" * 64,
            size=1024,
            permissions=0o644,
            mtime=1.0,
            algorithm="sha256",
        )
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[
                Change(ChangeType.ADDED, record, None),
                Change(ChangeType.DELETED, None, record),
                Change(ChangeType.MODIFIED, record, record),
            ],
            timestamp="2026-01-01T00:00:00",
            files_scanned=3,
        )
        output = report(result, "console")
        self.assertIn("[ADDED]", output)
        self.assertIn("[DELETED]", output)
        self.assertIn("[MODIFIED]", output)
        self.assertIn("1.0 KB", output)


class TestJsonReport(unittest.TestCase):
    def test_valid_json(self):
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[],
            timestamp="2026-01-01T00:00:00",
            files_scanned=0,
        )
        output = report(result, "json")
        data = json.loads(output)
        self.assertEqual(data["scan_path"], ".")
        self.assertEqual(data["files_scanned"], 0)

    def test_enum_serialization(self):
        record = FileRecord("test.txt", "hash", 1, 0o644, 1.0, "sha256")
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[Change(ChangeType.ADDED, record, None)],
            timestamp="2026-01-01T00:00:00",
            files_scanned=1,
        )
        output = report(result, "json")
        data = json.loads(output)
        self.assertEqual(data["changes"][0]["change_type"], "added")


class TestCsvReport(unittest.TestCase):
    def test_csv_output(self):
        record = FileRecord("test.txt", "hash", 100, 0o644, 1.0, "sha256")
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[Change(ChangeType.ADDED, record, None)],
            timestamp="2026-01-01T00:00:00",
            files_scanned=1,
        )
        output = report(result, "csv")
        reader = csv.DictReader(io.StringIO(output))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["change_type"], "added")
        self.assertEqual(rows[0]["path"], "test.txt")

    def test_no_changes(self):
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[],
            timestamp="2026-01-01T00:00:00",
            files_scanned=0,
        )
        output = report(result, "csv")
        reader = csv.DictReader(io.StringIO(output))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["change_type"], "none")


class TestHtmlReport(unittest.TestCase):
    def test_html_moved_and_permission_changed(self):
        record = FileRecord("test.txt", "hash", 100, 0o644, 1.0, "sha256")
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[
                Change(ChangeType.MOVED, record, record),
                Change(ChangeType.PERMISSION_CHANGED, record, record),
            ],
            timestamp="2026-01-01T00:00:00",
            files_scanned=2,
        )
        output = report(result, "html")
        self.assertIn("MOVED", output)
        self.assertIn("PERMISSION_CHANGED", output)
        self.assertIn("Permissions:", output)

    def test_html_escapes_single_quotes(self):
        record = FileRecord("file's.txt", "hash", 100, 0o644, 1.0, "sha256")
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[Change(ChangeType.ADDED, record, None)],
            timestamp="2026-01-01T00:00:00",
            files_scanned=1,
        )
        output = report(result, "html")
        self.assertIn("file&#x27;s.txt", output)
        self.assertNotIn("file's.txt", output)

    def test_html_structure(self):
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[],
            timestamp="2026-01-01T00:00:00",
            files_scanned=0,
        )
        output = report(result, "html")
        self.assertIn("<!DOCTYPE html>", output)
        self.assertIn("File Integrity Monitor Report", output)
        self.assertIn("No changes detected", output)

    def test_html_with_changes(self):
        record = FileRecord("test.txt", "hash", 100, 0o644, 1.0, "sha256")
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[Change(ChangeType.ADDED, record, None)],
            timestamp="2026-01-01T00:00:00",
            files_scanned=1,
        )
        output = report(result, "html")
        self.assertIn("ADDED", output)
        self.assertIn("test.txt", output)


class TestReportOutputPath(unittest.TestCase):
    def test_write_to_file(self):
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[],
            timestamp="2026-01-01T00:00:00",
            files_scanned=0,
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            path = f.name

        try:
            report(result, "console", output_path=path)
            with open(path) as f:
                content = f.read()
            self.assertIn("No changes detected", content)
        finally:
            os.unlink(path)

    def test_unsupported_format(self):
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[],
            timestamp="2026-01-01T00:00:00",
            files_scanned=0,
        )
        with self.assertRaises(ValueError) as ctx:
            report(result, "xml")
        self.assertIn("xml", str(ctx.exception))

class TestCsvSanitization(unittest.TestCase):
    def test_formula_prefix_blocked(self):
        record = FileRecord(
            path="=cmd|' /C calc'!A0",
            hash="hash",
            size=1,
            permissions=0o644,
            mtime=1.0,
            algorithm="sha256",
        )
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[Change(ChangeType.ADDED, record, None)],
            timestamp="2026-01-01T00:00:00",
            files_scanned=1,
        )
        output = report(result, "csv")
        self.assertIn("\t=cmd", output)
        self.assertNotIn("\n=cmd", output)

    def test_plus_prefix_blocked(self):
        record = FileRecord(
            path="+1+1",
            hash="hash",
            size=1,
            permissions=0o644,
            mtime=1.0,
            algorithm="sha256",
        )
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[Change(ChangeType.ADDED, record, None)],
            timestamp="2026-01-01T00:00:00",
            files_scanned=1,
        )
        output = report(result, "csv")
        self.assertIn("\t+1+1", output)

    def test_normal_path_unchanged(self):
        record = FileRecord(
            path="normal.txt",
            hash="hash",
            size=1,
            permissions=0o644,
            mtime=1.0,
            algorithm="sha256",
        )
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[Change(ChangeType.ADDED, record, None)],
            timestamp="2026-01-01T00:00:00",
            files_scanned=1,
        )
        output = report(result, "csv")
        self.assertIn("normal.txt", output)
        self.assertNotIn("\tnormal.txt", output)


class TestUtilityFunctions(unittest.TestCase):
    def test_to_dict_with_path(self):
        from pathlib import Path

        from fim.reporter import _to_dict
        result = _to_dict(Path("test.txt"))
        self.assertEqual(result, "test.txt")

    def test_format_size_mb(self):
        from fim.reporter import _format_size
        self.assertIn("MB", _format_size(1024 * 1024))

    def test_truncate_hash_short(self):
        from fim.reporter import _truncate_hash
        self.assertEqual(_truncate_hash("abc", length=10), "abc")


if __name__ == "__main__":
    unittest.main()
