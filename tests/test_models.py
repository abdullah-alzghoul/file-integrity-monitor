"""Tests for fim.models — core data model classes."""

import unittest

from fim.models import Change, ChangeType, FileRecord, ScanResult


class TestChangeType(unittest.TestCase):
    def test_members(self):
        self.assertEqual(ChangeType.ADDED.value, "added")
        self.assertEqual(ChangeType.DELETED.value, "deleted")
        self.assertEqual(ChangeType.MODIFIED.value, "modified")
        self.assertEqual(ChangeType.MOVED.value, "moved")
        self.assertEqual(ChangeType.PERMISSION_CHANGED.value, "permission_changed")


class TestFileRecord(unittest.TestCase):
    def test_creation(self):
        record = FileRecord(
            path="test.txt",
            hash="abc123",
            size=100,
            permissions=0o644,
            mtime=1234567890.0,
            algorithm="sha256",
        )
        self.assertEqual(record.path, "test.txt")
        self.assertEqual(record.hash, "abc123")
        self.assertEqual(record.size, 100)

    def test_frozen(self):
        record = FileRecord(
            path="test.txt",
            hash="abc123",
            size=100,
            permissions=0o644,
            mtime=1234567890.0,
            algorithm="sha256",
        )
        with self.assertRaises(AttributeError):
            record.hash = "changed"

    def test_path_obj(self):
        record = FileRecord(
            path="test.txt",
            hash="abc123",
            size=100,
            permissions=0o644,
            mtime=1234567890.0,
            algorithm="sha256",
        )
        self.assertEqual(record.path_obj.name, "test.txt")


class TestChange(unittest.TestCase):
    def test_defaults(self):
        change = Change(
            change_type=ChangeType.MODIFIED,
            record=None,
            previous_record=None,
        )
        self.assertIsNone(change.diff_preview)

    def test_with_diff(self):
        record = FileRecord(
            path="test.txt",
            hash="abc123",
            size=100,
            permissions=0o644,
            mtime=1234567890.0,
            algorithm="sha256",
        )
        change = Change(
            change_type=ChangeType.MODIFIED,
            record=record,
            previous_record=record,
            diff_preview="--- a/test.txt\n+++ b/test.txt",
        )
        self.assertIn("a/test.txt", change.diff_preview)


class TestScanResult(unittest.TestCase):
    def test_creation(self):
        result = ScanResult(
            baseline_path="baseline.json",
            scan_path=".",
            changes=[],
            timestamp="2026-01-01T00:00:00",
            files_scanned=10,
        )
        self.assertEqual(result.files_scanned, 10)
        self.assertEqual(len(result.changes), 0)


if __name__ == "__main__":
    unittest.main()
