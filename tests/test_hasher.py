"""Tests for fim.hasher — cryptographic file hashing."""

import hashlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from fim.hasher import hash_file, hash_directory
from fim.rules import RuleSet


class TestHashFile(unittest.TestCase):
    def test_sha256(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("hello world")
            path = f.name

        try:
            expected = hashlib.sha256(b"hello world").hexdigest()
            result = hash_file(path, "sha256")
            self.assertEqual(result, expected)
        finally:
            os.unlink(path)

    def test_sha512(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("hello world")
            path = f.name

        try:
            expected = hashlib.sha512(b"hello world").hexdigest()
            result = hash_file(path, "sha512")
            self.assertEqual(result, expected)
        finally:
            os.unlink(path)

    def test_unsupported_algorithm(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name

        try:
            with self.assertRaises(ValueError) as ctx:
                hash_file(path, "md5")
            self.assertIn("md5", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_binary_file(self):
        data = bytes(range(256))
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(data)
            path = f.name

        try:
            expected = hashlib.sha256(data).hexdigest()
            result = hash_file(path, "sha256")
            self.assertEqual(result, expected)
        finally:
            os.unlink(path)


class TestHashDirectory(unittest.TestCase):
    def test_skips_unreadable_file(self):
        import sys
        if sys.platform == "win32":
            self.skipTest("Windows ACLs do not support owner-read denial via chmod")
        path = Path(self.temp_dir) / "secret.txt"
        path.write_text("secret")
        os.chmod(path, 0o000)
        try:
            result = hash_directory(self.temp_dir, RuleSet([]), threads=1)
            self.assertEqual(len(result), 0)
        finally:
            os.chmod(path, 0o644)

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_empty_directory(self):
        result = hash_directory(self.temp_dir, RuleSet([]))
        self.assertEqual(len(result), 0)

    def test_hashes_files(self):
        path1 = Path(self.temp_dir) / "file1.txt"
        path1.write_text("content1")
        path2 = Path(self.temp_dir) / "file2.txt"
        path2.write_text("content2")

        result = hash_directory(self.temp_dir, RuleSet([]), threads=1)
        self.assertEqual(len(result), 2)

        paths = {r.path for r in result}
        self.assertIn(str(path1), paths)
        self.assertIn(str(path2), paths)

    def test_respects_excludes(self):
        path1 = Path(self.temp_dir) / "keep.txt"
        path1.write_text("keep")
        path2 = Path(self.temp_dir) / "ignore.tmp"
        path2.write_text("ignore")

        result = hash_directory(self.temp_dir, RuleSet(["*.tmp"]), threads=1)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].path, str(path1))

    def test_excludes_directories(self):
        subdir = Path(self.temp_dir) / "skipme"
        subdir.mkdir()
        (subdir / "file.txt").write_text("hidden")

        result = hash_directory(self.temp_dir, RuleSet(["skipme/"]), threads=1)
        self.assertEqual(len(result), 0)

    def test_returns_file_records(self):
        path = Path(self.temp_dir) / "test.txt"
        path.write_text("data")

        result = hash_directory(self.temp_dir, RuleSet([]), threads=1)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].size, 4)
        self.assertEqual(result[0].algorithm, "sha256")

    def test_skips_symlinks(self):
        target = Path(self.temp_dir) / "target.txt"
        target.write_text("real content")
        link = Path(self.temp_dir) / "link.txt"

        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlinks not supported on this platform")

        result = hash_directory(self.temp_dir, RuleSet([]), threads=1)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].path, str(target))


if __name__ == "__main__":
    unittest.main()