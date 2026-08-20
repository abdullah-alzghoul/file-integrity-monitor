"""Tests for fim.diff."""

import os
import tempfile
import unittest
from pathlib import Path

from fim.diff import generate_diff_preview, _is_binary


class TestIsBinary(unittest.TestCase):
    def test_unreadable_file(self):
        import sys
        if sys.platform == "win32":
            self.skipTest("Windows ACLs do not support owner-read denial via chmod")
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("content")
            path = f.name
        os.chmod(path, 0o000)
        try:
            self.assertTrue(_is_binary(path))
        finally:
            os.chmod(path, 0o644)
            os.unlink(path)

    def test_text_file(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("hello world")
            path = f.name
        try:
            self.assertFalse(_is_binary(path))
        finally:
            os.unlink(path)

    def test_binary_file(self):
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"\x00\x01\x02\x03")
            path = f.name
        try:
            self.assertTrue(_is_binary(path))
        finally:
            os.unlink(path)

    def test_missing_file(self):
        self.assertTrue(_is_binary("does_not_exist.txt"))


class TestGenerateDiffPreview(unittest.TestCase):
    def test_text_diff(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("line1\nline2\nline3\n")
            old = f.name
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("line1\nline2 modified\nline3\n")
            new = f.name

        try:
            diff = generate_diff_preview(old, new)
            self.assertIsNotNone(diff)
            self.assertIn("line2 modified", diff)
            self.assertIn("---", diff)
            self.assertIn("+++", diff)
        finally:
            os.unlink(old)
            os.unlink(new)

    def test_identical_files(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("same content")
            old = new = f.name

        try:
            diff = generate_diff_preview(old, new)
            self.assertIsNone(diff)
        finally:
            os.unlink(old)

    def test_binary_files(self):
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"\x00\x01\x02")
            old = f.name
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"\x00\x01\x03")
            new = f.name

        try:
            diff = generate_diff_preview(old, new)
            self.assertIsNone(diff)
        finally:
            os.unlink(old)
            os.unlink(new)

    def test_truncation(self):
        lines_old = [f"line{i}" for i in range(100)]
        lines_new = [f"line{i} modified" for i in range(100)]

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("\n".join(lines_old))
            old = f.name
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("\n".join(lines_new))
            new = f.name

        try:
            diff = generate_diff_preview(old, new, max_lines=10)
            self.assertIsNotNone(diff)
            self.assertIn("truncated", diff)
        finally:
            os.unlink(old)
            os.unlink(new)

    def test_missing_file(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("content")
            path = f.name
        try:
            diff = generate_diff_preview(path, "does_not_exist.txt")
            self.assertIsNone(diff)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()