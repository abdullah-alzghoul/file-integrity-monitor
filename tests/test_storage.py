"""Tests for fim.storage."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from fim.models import FileRecord
from fim.storage import save_baseline, load_baseline, BASELINE_VERSION


class TestSaveBaseline(unittest.TestCase):
    def test_save_unsigned(self):
        record = FileRecord(
            path="test.txt",
            hash="abc123",
            size=100,
            permissions=0o644,
            mtime=1234567890.0,
            algorithm="sha256",
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name

        try:
            save_baseline(path, [record], "sha256")
            with open(path, "r") as f:
                data = json.load(f)
            self.assertEqual(data["version"], BASELINE_VERSION)
            self.assertEqual(data["algorithm"], "sha256")
            self.assertEqual(len(data["records"]), 1)
            self.assertNotIn("signature", data)
        finally:
            os.unlink(path)

    def test_save_signed(self):
        record = FileRecord(
            path="test.txt",
            hash="abc123",
            size=100,
            permissions=0o644,
            mtime=1234567890.0,
            algorithm="sha256",
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name

        try:
            save_baseline(path, [record], "sha256", key="secret")
            with open(path, "r") as f:
                data = json.load(f)
            self.assertIn("signature", data)
            self.assertEqual(len(data["signature"]), 64)
        finally:
            os.unlink(path)

    def test_save_multiple_records_sorted(self):
        r1 = FileRecord("b.txt", "hash1", 1, 0o644, 1.0, "sha256")
        r2 = FileRecord("a.txt", "hash2", 2, 0o644, 2.0, "sha256")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name

        try:
            save_baseline(path, [r1, r2], "sha256")
            with open(path, "r") as f:
                data = json.load(f)
            paths = [r["path"] for r in data["records"]]
            self.assertEqual(paths, ["a.txt", "b.txt"])
        finally:
            os.unlink(path)


class TestLoadBaseline(unittest.TestCase):
    def test_load_unsigned(self):
        record = FileRecord(
            path="test.txt",
            hash="abc123",
            size=100,
            permissions=0o644,
            mtime=1234567890.0,
            algorithm="sha256",
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        save_baseline(path, [record], "sha256")

        try:
            records, algorithm = load_baseline(path)
            self.assertEqual(algorithm, "sha256")
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].path, "test.txt")
        finally:
            os.unlink(path)

    def test_load_signed_with_key(self):
        record = FileRecord(
            path="test.txt",
            hash="abc123",
            size=100,
            permissions=0o644,
            mtime=1234567890.0,
            algorithm="sha256",
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        save_baseline(path, [record], "sha256", key="secret")

        try:
            records, algorithm = load_baseline(path, key="secret")
            self.assertEqual(len(records), 1)
        finally:
            os.unlink(path)

    def test_load_signed_without_key(self):
        record = FileRecord(
            path="test.txt",
            hash="abc123",
            size=100,
            permissions=0o644,
            mtime=1234567890.0,
            algorithm="sha256",
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        save_baseline(path, [record], "sha256", key="secret")

        try:
            with self.assertRaises(ValueError) as ctx:
                load_baseline(path)
            self.assertIn("signed but no key", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_load_signed_wrong_key(self):
        record = FileRecord(
            path="test.txt",
            hash="abc123",
            size=100,
            permissions=0o644,
            mtime=1234567890.0,
            algorithm="sha256",
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        save_baseline(path, [record], "sha256", key="secret")

        try:
            with self.assertRaises(ValueError) as ctx:
                load_baseline(path, key="wrong")
            self.assertIn("signature verification failed", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_load_malformed_not_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("[1, 2, 3]")
            path = f.name

        try:
            with self.assertRaises(ValueError) as ctx:
                load_baseline(path)
            self.assertIn("JSON object", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_load_wrong_version(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"version": 99, "algorithm": "sha256", "records": []}, f)
            path = f.name

        try:
            with self.assertRaises(ValueError) as ctx:
                load_baseline(path)
            self.assertIn("unsupported baseline version", str(ctx.exception))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()