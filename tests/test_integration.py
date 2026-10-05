"""End-to-end integration tests for the file integrity monitor CLI."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from fim.cli import run
from tests._util import rmtree_force


class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.scan_dir = os.path.join(self.temp_dir, "scan")
        os.makedirs(self.scan_dir)
        self.baseline_path = os.path.join(self.temp_dir, "baseline.json")

    def tearDown(self):
        rmtree_force(self.temp_dir)

    def test_full_workflow_no_changes(self):
        (Path(self.scan_dir) / "file.txt").write_text("content")
        rc = run(["baseline", self.scan_dir, "-o", self.baseline_path])
        self.assertEqual(rc, 0)

        rc = run(["scan", self.scan_dir, "-b", self.baseline_path])
        self.assertEqual(rc, 0)

    def test_full_workflow_with_changes_json_report(self):
        (Path(self.scan_dir) / "file.txt").write_text("content")
        rc = run(["baseline", self.scan_dir, "-o", self.baseline_path])
        self.assertEqual(rc, 0)

        (Path(self.scan_dir) / "new.txt").write_text("new")
        report_path = os.path.join(self.temp_dir, "report.json")
        rc = run(["scan", self.scan_dir, "-b", self.baseline_path, "-f", "json", "-o", report_path])
        self.assertEqual(rc, 1)

        with open(report_path) as f:
            data = json.load(f)
        self.assertEqual(data["scan_path"], self.scan_dir)
        self.assertEqual(len(data["changes"]), 1)
        self.assertEqual(data["changes"][0]["change_type"], "added")

    def test_full_workflow_with_signed_baseline(self):
        (Path(self.scan_dir) / "file.txt").write_text("content")
        key_path = os.path.join(self.temp_dir, "key.txt")
        with open(key_path, "w") as f:
            f.write("integration_secret")

        rc = run(["baseline", self.scan_dir, "-o", self.baseline_path, "--key-file", key_path])
        self.assertEqual(rc, 0)

        (Path(self.scan_dir) / "file.txt").write_text("modified")
        rc = run(["scan", self.scan_dir, "-b", self.baseline_path, "--key-file", key_path])
        self.assertEqual(rc, 1)

    def test_full_workflow_csv_report(self):
        (Path(self.scan_dir) / "file.txt").write_text("content")
        rc = run(["baseline", self.scan_dir, "-o", self.baseline_path])
        self.assertEqual(rc, 0)

        report_path = os.path.join(self.temp_dir, "report.csv")
        rc = run(["scan", self.scan_dir, "-b", self.baseline_path, "-f", "csv", "-o", report_path])
        self.assertEqual(rc, 0)

        with open(report_path) as f:
            content = f.read()
        self.assertIn("timestamp", content)
        self.assertIn("scan_path", content)

    def test_full_workflow_html_report(self):
        (Path(self.scan_dir) / "file.txt").write_text("content")
        rc = run(["baseline", self.scan_dir, "-o", self.baseline_path])
        self.assertEqual(rc, 0)

        report_path = os.path.join(self.temp_dir, "report.html")
        rc = run(["scan", self.scan_dir, "-b", self.baseline_path, "-f", "html", "-o", report_path])
        self.assertEqual(rc, 0)

        with open(report_path) as f:
            content = f.read()
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("File Integrity Monitor Report", content)


if __name__ == "__main__":
    unittest.main()
