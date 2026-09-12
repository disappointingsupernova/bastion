"""Unit tests for the provisioning module — input validation and command building."""

from __future__ import annotations

import pytest

from bastion.provisioning import (
    _validate_package_name,
    _validate_username,
    check_connectivity,
)


class TestValidateUsername:
    """Tests for _validate_username."""

    def test_valid_username_returned(self):
        """A valid Unix username must be returned unchanged."""
        assert _validate_username("alice") == "alice"

    def test_username_with_numbers_valid(self):
        """Usernames with numbers are valid."""
        assert _validate_username("user01") == "user01"

    def test_username_with_hyphen_valid(self):
        """Usernames with hyphens are valid."""
        assert _validate_username("deploy-user") == "deploy-user"

    def test_username_with_underscore_valid(self):
        """Usernames with underscores are valid."""
        assert _validate_username("_svc_account") == "_svc_account"

    def test_username_starting_with_digit_raises(self):
        """A username starting with a digit must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid username"):
            _validate_username("1baduser")

    def test_username_with_space_raises(self):
        """A username containing a space must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid username"):
            _validate_username("bad user")

    def test_username_with_semicolon_raises(self):
        """A username containing a semicolon must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid username"):
            _validate_username("user;rm -rf /")

    def test_empty_username_raises(self):
        """An empty username must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid username"):
            _validate_username("")

    def test_username_too_long_raises(self):
        """A username exceeding 32 characters must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid username"):
            _validate_username("a" * 33)


class TestValidatePackageName:
    """Tests for _validate_package_name."""

    def test_valid_package_name_returned(self):
        """A valid package name must be returned unchanged."""
        assert _validate_package_name("openssh-server") == "openssh-server"

    def test_package_with_version_valid(self):
        """Package names with dots and plus signs are valid."""
        assert _validate_package_name("libssl1.1") == "libssl1.1"

    def test_package_with_plus_valid(self):
        """Package names with plus signs are valid."""
        assert _validate_package_name("g++") == "g++"

    def test_package_starting_with_semicolon_raises(self):
        """A package name with a semicolon must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid package name"):
            _validate_package_name("pkg;rm -rf /")

    def test_package_with_space_raises(self):
        """A package name with a space must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid package name"):
            _validate_package_name("bad package")

    def test_empty_package_name_raises(self):
        """An empty package name must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid package name"):
            _validate_package_name("")


@pytest.mark.asyncio
class TestCheckConnectivity:
    """Tests for check_connectivity."""

    async def test_unreachable_host_returns_false(self):
        """A host that refuses connection must return False."""
        # Port 1 on localhost is almost certainly closed
        result = await check_connectivity("127.0.0.1", port=1, timeout=0.5)
        assert result is False

    async def test_invalid_hostname_returns_false(self):
        """An invalid hostname must return False without raising."""
        result = await check_connectivity("this.host.does.not.exist.invalid", timeout=0.5)
        assert result is False

    async def test_returns_bool(self):
        """check_connectivity must always return a bool."""
        result = await check_connectivity("127.0.0.1", port=1, timeout=0.1)
        assert isinstance(result, bool)
