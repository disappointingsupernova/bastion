"""Unit tests for the recordings module — key derivation and channel naming."""

from __future__ import annotations

from bastion.recordings import (
    admin_key_fingerprint,
    derive_admin_decrypt_key,
    live_channel,
)


class TestLiveChannel:
    """Tests for live_channel."""

    def test_returns_prefixed_channel_name(self):
        """live_channel must return a string prefixed with the expected prefix."""
        result = live_channel("session-abc-123")
        assert result == "bastion:session:live:session-abc-123"

    def test_different_session_ids_produce_different_channels(self):
        """Different session IDs must produce different channel names."""
        assert live_channel("id-1") != live_channel("id-2")

    def test_empty_session_id(self):
        """An empty session ID must still produce a valid channel name."""
        result = live_channel("")
        assert result == "bastion:session:live:"


class TestDeriveAdminDecryptKey:
    """Tests for derive_admin_decrypt_key."""

    def test_returns_32_bytes(self):
        """The derived key must be exactly 32 bytes (SHA-256 output)."""
        key = derive_admin_decrypt_key("master-key", "admin-user-id")
        assert len(key) == 32

    def test_deterministic(self):
        """The same inputs must always produce the same key."""
        k1 = derive_admin_decrypt_key("master", "admin-1")
        k2 = derive_admin_decrypt_key("master", "admin-1")
        assert k1 == k2

    def test_different_admin_ids_produce_different_keys(self):
        """Different admin user IDs must produce different keys."""
        k1 = derive_admin_decrypt_key("master", "admin-1")
        k2 = derive_admin_decrypt_key("master", "admin-2")
        assert k1 != k2

    def test_different_master_keys_produce_different_keys(self):
        """Different master keys must produce different derived keys."""
        k1 = derive_admin_decrypt_key("master-a", "admin-1")
        k2 = derive_admin_decrypt_key("master-b", "admin-1")
        assert k1 != k2

    def test_returns_bytes(self):
        """The return type must be bytes."""
        key = derive_admin_decrypt_key("master", "admin")
        assert isinstance(key, bytes)


class TestAdminKeyFingerprint:
    """Tests for admin_key_fingerprint."""

    def test_returns_16_char_hex_string(self):
        """The fingerprint must be a 16-character hex string."""
        fp = admin_key_fingerprint("admin-1", "master")
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)

    def test_deterministic(self):
        """The same inputs must always produce the same fingerprint."""
        fp1 = admin_key_fingerprint("admin-1", "master")
        fp2 = admin_key_fingerprint("admin-1", "master")
        assert fp1 == fp2

    def test_different_admins_different_fingerprints(self):
        """Different admin IDs must produce different fingerprints."""
        fp1 = admin_key_fingerprint("admin-1", "master")
        fp2 = admin_key_fingerprint("admin-2", "master")
        assert fp1 != fp2

    def test_different_master_keys_different_fingerprints(self):
        """Different master keys must produce different fingerprints."""
        fp1 = admin_key_fingerprint("admin-1", "master-a")
        fp2 = admin_key_fingerprint("admin-1", "master-b")
        assert fp1 != fp2
