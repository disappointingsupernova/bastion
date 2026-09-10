"""Unit tests for the configuration module."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


class TestSettings:
    """Tests for the Settings pydantic-settings model."""

    def test_secret_key_loaded_from_env(self):
        """SECRET_KEY must be loaded from the environment."""
        from bastion.config import get_settings

        settings = get_settings()
        assert settings.secret_key == os.environ["SECRET_KEY"]

    def test_default_db_backend_is_sqlite(self):
        """Default database backend must be SQLite."""
        from bastion.config import DatabaseBackend, get_settings

        settings = get_settings()
        assert settings.db_backend == DatabaseBackend.SQLITE

    def test_is_sqlite_property(self):
        """is_sqlite must return True when backend is SQLite."""
        from bastion.config import get_settings

        settings = get_settings()
        assert settings.is_sqlite is True

    def test_default_ha_mode_is_false(self):
        """HA mode must be disabled by default."""
        from bastion.config import get_settings

        settings = get_settings()
        assert settings.ha_mode is False
        assert settings.is_ha is False

    def test_default_cert_validity_hours(self):
        """Default certificate validity must be 8 hours."""
        from bastion.config import get_settings

        settings = get_settings()
        assert settings.ssh_cert_validity_hours == 8

    def test_default_anomaly_threshold(self):
        """Default anomaly score threshold must be 70."""
        from bastion.config import get_settings

        settings = get_settings()
        assert settings.anomaly_score_alert_threshold == 70

    def test_excluded_system_users_contains_root(self):
        """root must always be in the excluded system users list."""
        from bastion.config import get_settings

        settings = get_settings()
        assert "root" in settings.excluded_system_users

    def test_excluded_system_users_contains_bastion(self):
        """bastion must always be in the excluded system users list."""
        from bastion.config import get_settings

        settings = get_settings()
        assert "bastion" in settings.excluded_system_users

    def test_bastion_root_is_path(self):
        """bastion_root must be a Path instance."""
        from bastion.config import get_settings

        settings = get_settings()
        assert isinstance(settings.bastion_root, Path)

    def test_ca_key_path_is_path(self):
        """ca_key_path must be a Path instance."""
        from bastion.config import get_settings

        settings = get_settings()
        assert isinstance(settings.ca_key_path, Path)

    def test_get_settings_returns_same_instance(self):
        """get_settings() must return the same cached instance on repeated calls."""
        from bastion.config import get_settings

        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2

    def test_default_recordings_enabled(self):
        """Session recordings must be enabled by default."""
        from bastion.config import get_settings

        settings = get_settings()
        assert settings.recordings_enabled is True

    def test_default_storage_is_local(self):
        """Default recording storage must be local."""
        from bastion.config import StorageBackend, get_settings

        settings = get_settings()
        assert settings.recordings_storage == StorageBackend.LOCAL

    def test_default_rate_limit(self):
        """Default auth rate limit must be 10 per minute."""
        from bastion.config import get_settings

        settings = get_settings()
        assert settings.rate_limit_auth_per_minute == 10
