"""Cryptographic utilities for baseline signing and verification."""

from __future__ import annotations

import hashlib
import hmac

__all__ = ["sign", "verify"]


def sign(data: str, key: str, algorithm: str = "sha256") -> str:
    """Return HMAC hex digest of data using key.

    The key is used directly as the HMAC secret. For production use,
    derive the key from a password via a KDF (e.g., PBKDF2).
    """
    if algorithm == "sha256":
        hash_cls = hashlib.sha256
    elif algorithm == "sha512":
        hash_cls = hashlib.sha512
    else:
        raise ValueError(f"unsupported algorithm: {algorithm}")

    return hmac.new(
        key.encode("utf-8"),
        data.encode("utf-8"),
        hash_cls,
    ).hexdigest()


def verify(data: str, signature: str, key: str, algorithm: str = "sha256") -> bool:
    """Verify HMAC signature of data using key.

    Uses constant-time comparison to prevent timing attacks.
    """
    expected = sign(data, key, algorithm)
    return hmac.compare_digest(expected, signature)