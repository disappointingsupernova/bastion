"""Unit tests for the FIDO2 module — credential helpers and begin_authentication."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from bastion.fido2 import _load_credentials, _save_credentials, begin_registration
from bastion.models import User, UserRole, UserStatus


def _make_user(fido2_credentials: str | None = None) -> User:
    """Return an unsaved User instance for testing."""
    user = User(
        username="alice",
        email="alice@example.com",
        hashed_password="x",
        role=UserRole.USER,
        status=UserStatus.ACTIVE,
    )
    user.fido2_credentials = fido2_credentials
    return user


class TestLoadCredentials:
    """Tests for _load_credentials."""

    def test_returns_empty_list_when_no_credentials(self):
        """_load_credentials must return [] when fido2_credentials is None."""
        user = _make_user(fido2_credentials=None)
        result = _load_credentials(user, "secret-key")
        assert result == []

    def test_returns_decrypted_credentials(self):
        """_load_credentials must decrypt and return stored credentials."""
        from bastion.crypto.encryption import encrypt_secret

        creds = [{"credential_id": "abc123", "sign_count": 0}]
        encrypted = encrypt_secret(json.dumps(creds), "secret-key")
        user = _make_user(fido2_credentials=encrypted)

        result = _load_credentials(user, "secret-key")
        assert result == creds

    def test_returns_empty_list_on_decryption_failure(self):
        """_load_credentials must return [] if decryption fails (wrong key)."""
        from bastion.crypto.encryption import encrypt_secret

        creds = [{"credential_id": "abc123"}]
        encrypted = encrypt_secret(json.dumps(creds), "correct-key")
        user = _make_user(fido2_credentials=encrypted)

        result = _load_credentials(user, "wrong-key")
        assert result == []


class TestSaveCredentials:
    """Tests for _save_credentials."""

    def test_saves_encrypted_credentials(self):
        """_save_credentials must encrypt and store credentials on the user."""
        from bastion.crypto.encryption import decrypt_secret

        user = _make_user()
        creds = [{"credential_id": "def456", "sign_count": 1}]
        _save_credentials(user, creds, "secret-key")

        assert user.fido2_credentials is not None
        decrypted = json.loads(decrypt_secret(user.fido2_credentials, "secret-key"))
        assert decrypted == creds

    def test_overwrites_existing_credentials(self):
        """_save_credentials must overwrite any previously stored credentials."""
        from bastion.crypto.encryption import decrypt_secret, encrypt_secret

        old_creds = [{"credential_id": "old", "sign_count": 0}]
        user = _make_user(fido2_credentials=encrypt_secret(json.dumps(old_creds), "key"))

        new_creds = [{"credential_id": "new", "sign_count": 5}]
        _save_credentials(user, new_creds, "key")

        decrypted = json.loads(decrypt_secret(user.fido2_credentials, "key"))
        assert decrypted == new_creds


class TestBeginRegistration:
    """Tests for begin_registration."""

    def test_returns_dict(self):
        """begin_registration must return a dict (options)."""
        result = begin_registration("user-id-123", "alice")
        assert isinstance(result, dict)

    def test_different_users_produce_different_options(self):
        """Different user IDs must produce different registration options."""
        r1 = begin_registration("user-id-1", "alice")
        r2 = begin_registration("user-id-2", "bob")
        assert r1 != r2


@pytest.mark.asyncio
class TestBeginAuthentication:
    """Tests for begin_authentication."""

    async def test_raises_400_when_no_credentials(self, db_session):
        """begin_authentication must raise HTTP 400 when the user has no FIDO2 credentials."""
        from fastapi import HTTPException

        from bastion.fido2 import begin_authentication

        user = _make_user(fido2_credentials=None)
        db_session.add(user)
        await db_session.flush()

        with pytest.raises(HTTPException) as exc_info:
            await begin_authentication(db_session, user, "secret-key")
        assert exc_info.value.status_code == 400

    async def test_returns_options_and_state_token_when_credentials_present(self, db_session):
        """begin_authentication must return (options_dict, state_token) when credentials exist."""
        from bastion.crypto.encryption import encrypt_secret
        from bastion.fido2 import begin_authentication

        creds = [{"credential_id": "aabbcc", "sign_count": 0, "public_key": "Ed25519PublicKey"}]
        encrypted = encrypt_secret(json.dumps(creds), "secret-key")
        user = _make_user(fido2_credentials=encrypted)
        db_session.add(user)
        await db_session.flush()

        with patch("bastion.fido2._server") as mock_server_fn:
            mock_server = MagicMock()
            mock_server.authenticate_begin.return_value = ({"challenge": "abc"}, {"state": "xyz"})
            mock_server_fn.return_value = mock_server

            options, state_token = await begin_authentication(db_session, user, "secret-key")

        assert isinstance(options, dict)
        assert isinstance(state_token, str)
        assert len(state_token) > 0
