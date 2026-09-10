"""Unit tests for the authentication module."""

from __future__ import annotations

import pytest
import jwt

from bastion.auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_totp_secret,
    get_totp_uri,
    hash_password,
    verify_password,
    verify_totp,
)
from bastion.config import get_settings


class TestPasswordHashing:
    """Tests for bcrypt password hashing."""

    def test_hash_is_not_plaintext(self):
        """Hashed password must not equal the plaintext."""
        hashed = hash_password("correct-horse-battery-staple")
        assert hashed != "correct-horse-battery-staple"

    def test_correct_password_verifies(self):
        """Correct password must verify successfully."""
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("correct-horse-battery-staple", hashed) is True

    def test_wrong_password_fails(self):
        """Incorrect password must not verify."""
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("wrong-password", hashed) is False

    def test_hashes_are_unique(self):
        """Two hashes of the same password must differ (different salts)."""
        h1 = hash_password("same-password")
        h2 = hash_password("same-password")
        assert h1 != h2


class TestJWT:
    """Tests for JWT token issuance and validation."""

    def test_access_token_contains_expected_claims(self):
        """Access token must contain sub, username, role, and type claims."""
        token = create_access_token("user-id-123", "alice", "user")
        payload = decode_token(token)
        assert payload["sub"] == "user-id-123"
        assert payload["username"] == "alice"
        assert payload["role"] == "user"
        assert payload["type"] == "access"

    def test_refresh_token_type_is_refresh(self):
        """Refresh token must have type 'refresh'."""
        token = create_refresh_token("user-id-123")
        payload = decode_token(token)
        assert payload["type"] == "refresh"
        assert payload["sub"] == "user-id-123"

    def test_tampered_token_raises(self):
        """A tampered token must raise jwt.PyJWTError on decode."""
        token = create_access_token("user-id-123", "alice", "user")
        tampered = token[:-4] + "XXXX"
        with pytest.raises(jwt.PyJWTError):
            decode_token(tampered)

    def test_token_signed_with_secret_key(self):
        """Token must be verifiable with the configured secret key."""
        settings = get_settings()
        token = create_access_token("user-id-123", "alice", "user")
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        assert payload["sub"] == "user-id-123"


class TestTOTP:
    """Tests for TOTP secret generation and verification."""

    def test_secret_is_base32(self):
        """Generated TOTP secret must be a valid base32 string."""
        import base64

        secret = generate_totp_secret()
        # Should not raise
        base64.b32decode(secret)

    def test_totp_uri_contains_issuer(self):
        """TOTP URI must contain the configured issuer name."""
        settings = get_settings()
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, "alice")
        assert settings.totp_issuer in uri
        assert "alice" in uri

    def test_valid_totp_code_verifies(self):
        """A freshly generated TOTP code must verify successfully."""
        import pyotp

        secret = generate_totp_secret()
        code = pyotp.TOTP(secret).now()
        assert verify_totp(secret, code) is True

    def test_wrong_totp_code_fails(self):
        """An incorrect TOTP code must not verify."""
        secret = generate_totp_secret()
        assert verify_totp(secret, "000000") is False
