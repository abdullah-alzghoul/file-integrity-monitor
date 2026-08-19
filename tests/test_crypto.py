"""Tests for fim.crypto."""

import unittest

from fim.crypto import sign, verify


class TestSign(unittest.TestCase):
    def test_sign_consistent(self):
        sig1 = sign("hello", "secret")
        sig2 = sign("hello", "secret")
        self.assertEqual(sig1, sig2)

    def test_sign_different_data(self):
        sig1 = sign("hello", "secret")
        sig2 = sign("world", "secret")
        self.assertNotEqual(sig1, sig2)

    def test_sign_different_key(self):
        sig1 = sign("hello", "secret1")
        sig2 = sign("hello", "secret2")
        self.assertNotEqual(sig1, sig2)

    def test_sha512(self):
        sig = sign("data", "key", algorithm="sha512")
        self.assertEqual(len(sig), 128)

    def test_unsupported_algorithm(self):
        with self.assertRaises(ValueError) as ctx:
            sign("data", "key", algorithm="md5")
        self.assertIn("md5", str(ctx.exception))


class TestVerify(unittest.TestCase):
    def test_verify_valid(self):
        sig = sign("hello", "secret")
        self.assertTrue(verify("hello", sig, "secret"))

    def test_verify_invalid_signature(self):
        sig = sign("hello", "secret")
        self.assertFalse(verify("hello", sig + "x", "secret"))

    def test_verify_wrong_key(self):
        sig = sign("hello", "secret")
        self.assertFalse(verify("hello", sig, "wrong"))

    def test_verify_wrong_data(self):
        sig = sign("hello", "secret")
        self.assertFalse(verify("world", sig, "secret"))

    def test_verify_sha512(self):
        sig = sign("data", "key", algorithm="sha512")
        self.assertTrue(verify("data", sig, "key", algorithm="sha512"))


if __name__ == "__main__":
    unittest.main()