"""Tests for fim.reporter."""

import csv
import io
import json
import os
import tempfile
import unittest

from fim.models import Change, ChangeType, FileRecord, ScanResult
from fim.reporter import report


class TestConsoleReport(unittest.TestCase):
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
            with open(path, "r") as f:
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


if __name__ == "__main__":
    unittest.main()