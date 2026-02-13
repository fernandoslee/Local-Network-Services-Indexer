"""Shared authentication utilities."""

import hmac

import bcrypt

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against a hash. Handles both bcrypt and legacy plaintext."""
    if hashed.startswith("$2b$") or hashed.startswith("$2a$"):
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    # Legacy plaintext — constant-time comparison
    return hmac.compare_digest(plain, hashed)
