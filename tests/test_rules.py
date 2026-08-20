"""Tests for fim.rules — pattern-based file filtering."""

import tempfile
import unittest
from pathlib import Path

from fim.rules import RuleSet, load_rules


class TestRuleSet(unittest.TestCase):
    def test_directory_exact_match_no_trailing_slash(self):
        rs = RuleSet([".git/"])
        self.assertTrue(rs.is_ignored(".git"))

    def test_no_rules_allows_all(self):
        rs = RuleSet([])
        self.assertFalse(rs.is_ignored("anything.txt"))
        self.assertFalse(rs.is_ignored("deep/nested/file.py"))

    def test_exact_match(self):
        rs = RuleSet(["*.tmp"])
        self.assertTrue(rs.is_ignored("file.tmp"))
        self.assertTrue(rs.is_ignored("deep/file.tmp"))
        self.assertFalse(rs.is_ignored("file.txt"))

    def test_directory_pattern(self):
        rs = RuleSet([".git/"])
        self.assertTrue(rs.is_ignored(".git/config"))
        self.assertTrue(rs.is_ignored(".git/"))
        self.assertFalse(rs.is_ignored(".gitignore"))

    def test_multiple_patterns(self):
        rs = RuleSet(["*.log", "*.tmp", "node_modules/"])
        self.assertTrue(rs.is_ignored("debug.log"))
        self.assertTrue(rs.is_ignored("temp.tmp"))
        self.assertTrue(rs.is_ignored("node_modules/package.json"))
        self.assertFalse(rs.is_ignored("main.py"))

    def test_wildcard_middle(self):
        rs = RuleSet(["test_*.py"])
        self.assertTrue(rs.is_ignored("test_foo.py"))
        self.assertFalse(rs.is_ignored("foo_test.py"))


class TestLoadRules(unittest.TestCase):
    def test_load_from_file(self):
        content = "*.pyc\n__pycache__/\n# comment\n\n*.log"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            path = f.name

        try:
            rs = load_rules(path)
            self.assertTrue(rs.is_ignored("foo.pyc"))
            self.assertTrue(rs.is_ignored("__pycache__/foo.py"))
            self.assertTrue(rs.is_ignored("debug.log"))
            self.assertFalse(rs.is_ignored("comment"))
        finally:
            Path(path).unlink()

    def test_none_returns_empty(self):
        rs = load_rules(None)
        self.assertFalse(rs.is_ignored("anything"))

    def test_missing_file_returns_empty(self):
        rs = load_rules("does_not_exist.txt")
        self.assertFalse(rs.is_ignored("anything"))


if __name__ == "__main__":
    unittest.main()