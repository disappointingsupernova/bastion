"""Unit tests for the encryption module."""

from __future__ import annotations

import pytest

from bastion.crypto.encryption import decrypt_secret, encrypt_secret, get_fernet

SECRET_KEY = "test-secret-key-not-for-production-use-only-32chars"


class TestFernetEncryption:
    """Tests for Fernet-based secret encryption at rest."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypting and decrypting a secret must return the original value."""
        plaintext = "super-secret-totp-key"
        token = encrypt_secret(plaintext, SECRET_KEY)
        assert decrypt_secret(token, SECRET_KEY) == plaintext

    def test_encrypted_value_differs_from_plaintext(self):
        """The encrypted token must not equal the plaintext."""
        plaintext = "super-secret-totp-key"
        token = encrypt_secret(plaintext, SECRET_KEY)
        assert token != plaintext

    def test_different_keys_produce_different_tokens(self):
        """Encrypting with different keys must produce different tokens."""
        plaintext = "same-secret"
        t1 = encrypt_secret(plaintext, SECRET_KEY)
        t2 = encrypt_secret(plaintext, "different-key-also-long-enough-here")
        assert t1 != t2

    def test_wrong_key_raises_on_decrypt(self):
        """Decrypting with the wrong key must raise an exception."""
        from cryptography.fernet import InvalidToken

        token = encrypt_secret("secret", SECRET_KEY)
        with pytest.raises(InvalidToken):
            decrypt_secret(token, "wrong-key-also-long-enough-to-derive")

    def test_same_key_produces_consistent_fernet(self):
        """The same secret key must always produce the same Fernet key."""
        f1 = get_fernet(SECRET_KEY)
        f2 = get_fernet(SECRET_KEY)
        # Both should decrypt the same token
        token = f1.encrypt(b"test")
        assert f2.decrypt(token) == b"test"
