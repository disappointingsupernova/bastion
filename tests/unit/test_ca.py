"""Unit tests for the SSH CA module — key validation, principal validation, and keypair generation."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from bastion.crypto.ca import (
    _validate_principal,
    _validate_public_key,
    generate_ca_keypair,
)


class TestValidatePrincipal:
    """Tests for _validate_principal."""

    def test_valid_principal_returned(self):
        """A valid Unix username principal must be returned unchanged."""
        assert _validate_principal("alice") == "alice"

    def test_principal_with_numbers_valid(self):
        """Principals with numbers are valid."""
        assert _validate_principal("user01") == "user01"

    def test_principal_with_hyphen_valid(self):
        """Principals with hyphens are valid."""
        assert _validate_principal("deploy-user") == "deploy-user"

    def test_principal_starting_with_digit_raises(self):
        """A principal starting with a digit must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid principal"):
            _validate_principal("1baduser")

    def test_principal_with_space_raises(self):
        """A principal containing a space must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid principal"):
            _validate_principal("bad user")

    def test_principal_with_semicolon_raises(self):
        """A principal containing a semicolon must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid principal"):
            _validate_principal("user;evil")

    def test_empty_principal_raises(self):
        """An empty principal must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid principal"):
            _validate_principal("")

    def test_principal_too_long_raises(self):
        """A principal exceeding 32 characters must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid principal"):
            _validate_principal("a" * 33)


class TestValidatePublicKey:
    """Tests for _validate_public_key."""

    def test_ed25519_key_accepted(self):
        """An ssh-ed25519 key must be accepted without raising."""
        key = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test-key"
        _validate_public_key(key)  # must not raise

    def test_ecdsa_nistp256_key_accepted(self):
        """An ecdsa-sha2-nistp256 key must be accepted."""
        key = b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAI test"
        _validate_public_key(key)  # must not raise

    def test_rsa_key_accepted(self):
        """An ssh-rsa key must be accepted."""
        key = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB test"
        _validate_public_key(key)  # must not raise

    def test_unknown_key_type_raises(self):
        """An unrecognised key type must raise ValueError."""
        with pytest.raises(ValueError, match="not a recognised OpenSSH key type"):
            _validate_public_key(b"ssh-dss AAAAB3NzaC1kc3M test")

    def test_empty_key_raises(self):
        """An empty key must raise ValueError."""
        with pytest.raises(ValueError, match="not a recognised OpenSSH key type"):
            _validate_public_key(b"")

    def test_key_too_large_raises(self):
        """A key exceeding 8192 bytes must raise ValueError."""
        key = b"ssh-ed25519 " + b"A" * 8200
        with pytest.raises(ValueError, match="exceeds maximum"):
            _validate_public_key(key)

    def test_ecdsa_nistp384_accepted(self):
        """An ecdsa-sha2-nistp384 key must be accepted."""
        key = b"ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQ test"
        _validate_public_key(key)  # must not raise

    def test_ecdsa_nistp521_accepted(self):
        """An ecdsa-sha2-nistp521 key must be accepted."""
        key = b"ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjE test"
        _validate_public_key(key)  # must not raise


class TestGenerateCaKeypair:
    """Tests for generate_ca_keypair."""

    def test_generates_private_and_public_key_files(self):
        """generate_ca_keypair must create both the private key and .pub files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "ca" / "bastion_ca"
            generate_ca_keypair(key_path, passphrase=b"test-passphrase")

            assert key_path.exists()
            pub_path = key_path.with_suffix(".pub")
            assert pub_path.exists()

    def test_private_key_is_pem_encoded(self):
        """The generated private key must be PEM-encoded OpenSSH format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "bastion_ca"
            generate_ca_keypair(key_path, passphrase=b"passphrase")
            content = key_path.read_bytes()
            assert b"BEGIN OPENSSH PRIVATE KEY" in content

    def test_public_key_is_openssh_format(self):
        """The generated public key must be in OpenSSH format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "bastion_ca"
            generate_ca_keypair(key_path, passphrase=b"passphrase")
            pub_content = key_path.with_suffix(".pub").read_bytes()
            assert pub_content.startswith(b"ssh-ed25519 ")

    def test_private_key_permissions(self):
        """The private key file must have mode 0600 on POSIX systems."""
        import platform
        import stat

        if platform.system() == "Windows":
            pytest.skip("File permission bits are not enforced on Windows")

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "bastion_ca"
            generate_ca_keypair(key_path, passphrase=b"passphrase")
            mode = stat.S_IMODE(key_path.stat().st_mode)
            assert mode == 0o600

    def test_public_key_permissions(self):
        """The public key file must have mode 0644 on POSIX systems."""
        import platform
        import stat

        if platform.system() == "Windows":
            pytest.skip("File permission bits are not enforced on Windows")

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "bastion_ca"
            generate_ca_keypair(key_path, passphrase=b"passphrase")
            pub_path = key_path.with_suffix(".pub")
            mode = stat.S_IMODE(pub_path.stat().st_mode)
            assert mode == 0o644

    def test_creates_parent_directories(self):
        """generate_ca_keypair must create parent directories if they do not exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "deep" / "nested" / "bastion_ca"
            generate_ca_keypair(key_path, passphrase=b"passphrase")
            assert key_path.exists()
