"""Tests for fim.monitor — core scanning and change detection engine."""

import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from fim.models import ChangeType
from fim.monitor import create_baseline, scan_directory
from fim.rules import RuleSet


class TestCreateBaseline(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.baseline_path = os.path.join(self.temp_dir, "baseline.json")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_create_baseline_success(self):
        scan_dir = os.path.join(self.temp_dir, "scan")
        os.makedirs(scan_dir)
        (Path(scan_dir) / "file.txt").write_text("content")

        create_baseline(
            scan_path=scan_dir,
            baseline_path=self.baseline_path,
            rules=RuleSet([]),
            algorithm="sha256",
            threads=1,
            key=None,
            audit_logger=None,
        )
        self.assertTrue(os.path.exists(self.baseline_path))

    def test_create_baseline_nonexistent_path(self):
        with self.assertRaises(FileNotFoundError):
            create_baseline(
                scan_path="does_not_exist",
                baseline_path=self.baseline_path,
                rules=RuleSet([]),
                algorithm="sha256",
                threads=1,
                key=None,
                audit_logger=None,
            )

    def test_create_baseline_not_a_directory(self):
        file_path = os.path.join(self.temp_dir, "notadir")
        with open(file_path, "w") as f:
            f.write("x")
        with self.assertRaises(NotADirectoryError):
            create_baseline(
                scan_path=file_path,
                baseline_path=self.baseline_path,
                rules=RuleSet([]),
                algorithm="sha256",
                threads=1,
                key=None,
                audit_logger=None,
            )


class TestScanDirectory(unittest.TestCase):
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
        create_baseline(
            scan_path=self.scan_dir,
            baseline_path=self.baseline_path,
            rules=RuleSet([]),
            algorithm="sha256",
            threads=1,
            key=None,
            audit_logger=None,
        )

    def test_no_changes(self):
        (Path(self.scan_dir) / "file.txt").write_text("content")
        self._create_baseline()

        audit_path = os.path.join(self.temp_dir, "audit.log")
        from fim.audit import AuditLogger
        audit = AuditLogger(audit_path)

        result = scan_directory(
            scan_path=self.scan_dir,
            baseline_path=self.baseline_path,
            rules=RuleSet([]),
            algorithm="sha256",
            threads=1,
            key=None,
            audit_logger=audit,
        )
        self.assertEqual(len(result.changes), 0)
        self.assertEqual(result.files_scanned, 1)
        self.assertTrue(os.path.exists(audit_path))

    def test_file_added(self):
        self._create_baseline()
        (Path(self.scan_dir) / "new.txt").write_text("new content")

        result = scan_directory(
            scan_path=self.scan_dir,
            baseline_path=self.baseline_path,
            rules=RuleSet([]),
            algorithm="sha256",
            threads=1,
            key=None,
            audit_logger=None,
        )
        self.assertEqual(len(result.changes), 1)
        self.assertEqual(result.changes[0].change_type, ChangeType.ADDED)

    def test_file_deleted(self):
        (Path(self.scan_dir) / "old.txt").write_text("content")
        self._create_baseline()

        os.unlink(Path(self.scan_dir) / "old.txt")

        result = scan_directory(
            scan_path=self.scan_dir,
            baseline_path=self.baseline_path,
            rules=RuleSet([]),
            algorithm="sha256",
            threads=1,
            key=None,
            audit_logger=None,
        )
        self.assertEqual(len(result.changes), 1)
        self.assertEqual(result.changes[0].change_type, ChangeType.DELETED)

    def test_file_modified(self):
        file_path = Path(self.scan_dir) / "file.txt"
        file_path.write_text("original")
        self._create_baseline()

        file_path.write_text("modified")

        result = scan_directory(
            scan_path=self.scan_dir,
            baseline_path=self.baseline_path,
            rules=RuleSet([]),
            algorithm="sha256",
            threads=1,
            key=None,
            audit_logger=None,
        )
        self.assertEqual(len(result.changes), 1)
        self.assertEqual(result.changes[0].change_type, ChangeType.MODIFIED)

    def test_file_moved(self):
        old_path = Path(self.scan_dir) / "old.txt"
        old_path.write_text("content")
        self._create_baseline()

        new_path = Path(self.scan_dir) / "new.txt"
        old_path.rename(new_path)

        result = scan_directory(
            scan_path=self.scan_dir,
            baseline_path=self.baseline_path,
            rules=RuleSet([]),
            algorithm="sha256",
            threads=1,
            key=None,
            audit_logger=None,
        )
        self.assertEqual(len(result.changes), 1)
        self.assertEqual(result.changes[0].change_type, ChangeType.MOVED)

    def test_permission_changed(self):
        file_path = Path(self.scan_dir) / "file.txt"
        file_path.write_text("content")
        self._create_baseline()

        os.chmod(file_path, 0o444)

        result = scan_directory(
            scan_path=self.scan_dir,
            baseline_path=self.baseline_path,
            rules=RuleSet([]),
            algorithm="sha256",
            threads=1,
            key=None,
            audit_logger=None,
        )
        perm_changes = [
            c for c in result.changes
            if c.change_type == ChangeType.PERMISSION_CHANGED
        ]
        self.assertEqual(len(perm_changes), 1)

    def test_respects_rules(self):
        (Path(self.scan_dir) / "keep.txt").write_text("keep")
        (Path(self.scan_dir) / "ignore.tmp").write_text("ignore")
        self._create_baseline()

        result = scan_directory(
            scan_path=self.scan_dir,
            baseline_path=self.baseline_path,
            rules=RuleSet(["*.tmp"]),
            algorithm="sha256",
            threads=1,
            key=None,
            audit_logger=None,
        )
        deleted = [c for c in result.changes if c.change_type == ChangeType.DELETED]
        self.assertEqual(len(deleted), 1)

    def test_multiple_changes(self):
        (Path(self.scan_dir) / "keep.txt").write_text("keep")
        (Path(self.scan_dir) / "modify.txt").write_text("original")
        (Path(self.scan_dir) / "delete.txt").write_text("delete")
        self._create_baseline()

        (Path(self.scan_dir) / "modify.txt").write_text("modified")
        os.unlink(Path(self.scan_dir) / "delete.txt")
        (Path(self.scan_dir) / "add.txt").write_text("added")

        result = scan_directory(
            scan_path=self.scan_dir,
            baseline_path=self.baseline_path,
            rules=RuleSet([]),
            algorithm="sha256",
            threads=1,
            key=None,
            audit_logger=None,
        )
        types = {c.change_type for c in result.changes}
        self.assertIn(ChangeType.MODIFIED, types)
        self.assertIn(ChangeType.DELETED, types)
        self.assertIn(ChangeType.ADDED, types)

    def test_scan_nonexistent_path(self):
        (Path(self.scan_dir) / "file.txt").write_text("content")
        self._create_baseline()

        with self.assertRaises(FileNotFoundError):
            scan_directory(
                scan_path="does_not_exist",
                baseline_path=self.baseline_path,
                rules=RuleSet([]),
                algorithm="sha256",
                threads=1,
                key=None,
                audit_logger=None,
            )


if __name__ == "__main__":
    unittest.main()
