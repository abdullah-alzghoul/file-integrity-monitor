"""Tests for fim.cli."""

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from fim.cli import run


class TestBaselineCommand(unittest.TestCase):
    def test_baseline_with_inline_exclude_from_config(self):
        (Path(self.scan_dir) / "keep.txt").write_text("keep")
        (Path(self.scan_dir) / "ignore.tmp").write_text("ignore")
        config_path = os.path.join(self.temp_dir, "config.json")
        with open(config_path, "w") as f:
            json.dump({"exclude": ["*.tmp"]}, f)
        rc = run(["baseline", self.scan_dir, "-o", self.baseline_path, "--config", config_path])
        self.assertEqual(rc, 0)
        with open(self.baseline_path, "r") as f:
            data = json.load(f)
        paths = {r["path"] for r in data["records"]}
        basenames = {os.path.basename(p) for p in paths}
        self.assertIn("keep.txt", basenames)
        self.assertNotIn("ignore.tmp", basenames)
        
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.scan_dir = os.path.join(self.temp_dir, "scan")
        os.makedirs(self.scan_dir)
        self.baseline_path = os.path.join(self.temp_dir, "baseline.json")

    def tearDown(self):
        def _onexc(func, path, exc_info):
            os.chmod(path, stat.S_IWRITE)
            func(path)
        shutil.rmtree(self.temp_dir, onexc=_onexc)

    def test_baseline_creates_file(self):
        (Path(self.scan_dir) / "file.txt").write_text("content")
        rc = run(["baseline", self.scan_dir, "-o", self.baseline_path])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(self.baseline_path))

    def test_baseline_missing_scan_path(self):
        rc = run(["baseline", "does_not_exist", "-o", self.baseline_path])
        self.assertEqual(rc, 2)

    def test_baseline_with_key(self):
        (Path(self.scan_dir) / "file.txt").write_text("content")
        rc = run(["baseline", self.scan_dir, "-o", self.baseline_path, "-k", "secret"])
        self.assertEqual(rc, 0)
        with open(self.baseline_path, "r") as f:
            data = json.load(f)
        self.assertIn("signature", data)

    def test_baseline_with_rules(self):
        (Path(self.scan_dir) / "keep.txt").write_text("keep")
        (Path(self.scan_dir) / "ignore.tmp").write_text("ignore")
        rules_path = os.path.join(self.temp_dir, "rules.txt")
        with open(rules_path, "w") as f:
            f.write("*.tmp\n")
        rc = run(["baseline", self.scan_dir, "-o", self.baseline_path, "-r", rules_path])
        self.assertEqual(rc, 0)
        with open(self.baseline_path, "r") as f:
            data = json.load(f)
        paths = {r["path"] for r in data["records"]}
        basenames = {os.path.basename(p) for p in paths}
        self.assertIn("keep.txt", basenames)
        self.assertNotIn("ignore.tmp", basenames)


    def test_baseline_with_key_file(self):
        (Path(self.scan_dir) / "file.txt").write_text("content")
        key_path = os.path.join(self.temp_dir, "key.txt")
        with open(key_path, "w") as f:
            f.write("mysecretkey")
        rc = run(["baseline", self.scan_dir, "-o", self.baseline_path, "--key-file", key_path])
        self.assertEqual(rc, 0)
        with open(self.baseline_path, "r") as f:
            data = json.load(f)
        self.assertIn("signature", data)


class TestScanCommand(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.scan_dir = os.path.join(self.temp_dir, "scan")
        os.makedirs(self.scan_dir)
        self.baseline_path = os.path.join(self.temp_dir, "baseline.json")

    def tearDown(self):
        def _onexc(func, path, exc_info):
            os.chmod(path, stat.S_IWRITE)
            func(path)
        shutil.rmtree(self.temp_dir, onexc=_onexc)

    def _create_baseline(self):
        (Path(self.scan_dir) / "file.txt").write_text("content")
        run(["baseline", self.scan_dir, "-o", self.baseline_path])

    def test_scan_no_changes(self):
        self._create_baseline()
        rc = run(["scan", self.scan_dir, "-b", self.baseline_path])
        self.assertEqual(rc, 0)

    def test_scan_with_changes(self):
        self._create_baseline()
        (Path(self.scan_dir) / "new.txt").write_text("new")
        rc = run(["scan", self.scan_dir, "-b", self.baseline_path])
        self.assertEqual(rc, 1)

    def test_scan_json_output(self):
        self._create_baseline()
        report_path = os.path.join(self.temp_dir, "report.json")
        rc = run(["scan", self.scan_dir, "-b", self.baseline_path, "-f", "json", "-o", report_path])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(report_path))
        with open(report_path, "r") as f:
            data = json.load(f)
        self.assertEqual(data["scan_path"], self.scan_dir)

    def test_scan_signed_baseline_wrong_key(self):
        (Path(self.scan_dir) / "file.txt").write_text("content")
        run(["baseline", self.scan_dir, "-o", self.baseline_path, "-k", "secret"])
        rc = run(["scan", self.scan_dir, "-b", self.baseline_path, "-k", "wrong"])
        self.assertEqual(rc, 2)

    def test_scan_missing_baseline(self):
        rc = run(["scan", self.scan_dir, "-b", "does_not_exist.json"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()