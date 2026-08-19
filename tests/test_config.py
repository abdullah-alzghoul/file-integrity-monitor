"""Tests for fim.config."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from fim.config import Config, load_config


class TestConfigValidation(unittest.TestCase):
    def test_default_values(self):
        cfg = load_config()
        self.assertEqual(cfg.scan_path, ".")
        self.assertEqual(cfg.algorithm, "sha256")
        self.assertEqual(cfg.threads, 4)
        self.assertEqual(cfg.format, "console")
        self.assertIsNone(cfg.baseline_path)
        self.assertIsNone(cfg.key)

    def test_threads_must_be_positive(self):
        with self.assertRaises(ValueError) as ctx:
            load_config(threads=0)
        self.assertIn("threads", str(ctx.exception).lower())

    def test_threads_negative(self):
        with self.assertRaises(ValueError):
            load_config(threads=-1)

    def test_algorithm_must_be_supported(self):
        with self.assertRaises(ValueError) as ctx:
            load_config(algorithm="md5")
        self.assertIn("md5", str(ctx.exception))

    def test_format_must_be_supported(self):
        with self.assertRaises(ValueError) as ctx:
            load_config(format="xml")
        self.assertIn("xml", str(ctx.exception))


class TestConfigFileLoading(unittest.TestCase):
    def test_load_from_json_file(self):
        data = {"algorithm": "sha512", "threads": 8, "format": "json"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name

        try:
            cfg = load_config(config_path=path)
            self.assertEqual(cfg.algorithm, "sha512")
            self.assertEqual(cfg.threads, 8)
            self.assertEqual(cfg.format, "json")
        finally:
            os.unlink(path)

    def test_missing_file_uses_defaults(self):
        cfg = load_config(config_path="does_not_exist.json")
        self.assertEqual(cfg.algorithm, "sha256")


class TestEnvironmentVariables(unittest.TestCase):
    @patch.dict(os.environ, {"FIM_ALGORITHM": "sha512", "FIM_THREADS": "2"})
    def test_env_overrides_defaults(self):
        cfg = load_config()
        self.assertEqual(cfg.algorithm, "sha512")
        self.assertEqual(cfg.threads, 2)

    @patch.dict(os.environ, {"FIM_ALGORITHM": "sha512"})
    def test_env_overrides_file(self):
        data = {"algorithm": "sha256"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name

        try:
            cfg = load_config(config_path=path)
            self.assertEqual(cfg.algorithm, "sha512")
        finally:
            os.unlink(path)

    @patch.dict(os.environ, {"FIM_THREADS": "invalid"})
    def test_env_invalid_threads_raises(self):
        with self.assertRaises(ValueError):
            load_config()


if __name__ == "__main__":
    unittest.main()
