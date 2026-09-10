"""Unit tests for ORM models — defaults, constraints, and enum values."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from bastion.models import (
    AlertChannel,
    AlertSeverity,
    CertStatus,
    MfaMethod,
    OsFamily,
    Server,
    ServerAccess,
    ServerStatus,
    SessionStatus,
    User,
    UserRole,
    UserStatus,
)


@pytest.mark.asyncio
class TestUserModel:
    """Tests for the User ORM model."""

    async def test_user_created_with_defaults(self, db_session):
        """A new user must have sensible default values."""
        from bastion.auth import hash_password

        user = User(
            username="alice",
            email="alice@example.com",
            hashed_password=hash_password("pw"),
        )
        db_session.add(user)
        await db_session.flush()

        assert user.id is not None
        assert user.role == UserRole.USER
        assert user.status == UserStatus.ACTIVE
        assert user.mfa_enabled is False
        assert user.failed_login_count == 0
        assert user.deleted_at is None

    async def test_duplicate_username_raises(self, db_session):
        """Inserting two users with the same username must raise IntegrityError."""
        from bastion.auth import hash_password

        for _ in range(2):
            db_session.add(
                User(
                    username="duplicate",
                    email=f"unique{_}@example.com",
                    hashed_password=hash_password("pw"),
                )
            )
        with pytest.raises(IntegrityError):
            await db_session.flush()

    async def test_duplicate_email_raises(self, db_session):
        """Inserting two users with the same email must raise IntegrityError."""
        from bastion.auth import hash_password

        for i in range(2):
            db_session.add(
                User(
                    username=f"user{i}",
                    email="same@example.com",
                    hashed_password=hash_password("pw"),
                )
            )
        with pytest.raises(IntegrityError):
            await db_session.flush()

    async def test_user_id_is_uuid_format(self, db_session):
        """User ID must be a valid UUID string."""
        import uuid

        from bastion.auth import hash_password

        user = User(
            username="uuidtest",
            email="uuid@example.com",
            hashed_password=hash_password("pw"),
        )
        db_session.add(user)
        await db_session.flush()

        # Should not raise
        uuid.UUID(user.id)

    async def test_soft_delete_preserves_record(self, db_session):
        """Soft-deleting a user must set deleted_at but keep the record."""
        from datetime import UTC, datetime

        from bastion.auth import hash_password

        user = User(
            username="todelete",
            email="delete@example.com",
            hashed_password=hash_password("pw"),
        )
        db_session.add(user)
        await db_session.flush()

        user.deleted_at = datetime.now(tz=UTC)
        user.status = UserStatus.DELETED
        await db_session.flush()

        result = await db_session.execute(select(User).where(User.username == "todelete"))
        found = result.scalar_one_or_none()
        assert found is not None
        assert found.deleted_at is not None
        assert found.status == UserStatus.DELETED


@pytest.mark.asyncio
class TestServerModel:
    """Tests for the Server ORM model."""

    async def test_server_created_with_defaults(self, db_session):
        """A new server must have sensible default values."""
        server = Server(hostname="srv.example.com")
        db_session.add(server)
        await db_session.flush()

        assert server.id is not None
        assert server.ssh_port == 22
        assert server.os_family == OsFamily.UNKNOWN
        assert server.status == ServerStatus.ACTIVE
        assert server.hardening_applied is False
        assert server.deleted_at is None

    async def test_duplicate_hostname_raises(self, db_session):
        """Two servers with the same hostname must raise IntegrityError."""
        for _ in range(2):
            db_session.add(Server(hostname="duplicate.example.com"))
        with pytest.raises(IntegrityError):
            await db_session.flush()


@pytest.mark.asyncio
class TestServerAccessModel:
    """Tests for the ServerAccess ORM model."""

    async def test_duplicate_access_grant_raises(self, db_session, regular_user, test_server):
        """Granting the same user access to the same server twice must raise IntegrityError."""
        for _ in range(2):
            db_session.add(
                ServerAccess(
                    user_id=regular_user.id,
                    server_id=test_server.id,
                )
            )
        with pytest.raises(IntegrityError):
            await db_session.flush()

    async def test_access_defaults_no_sudo(self, db_session, regular_user, test_server):
        """A new access grant must default to allow_sudo=False."""
        access = ServerAccess(
            user_id=regular_user.id,
            server_id=test_server.id,
        )
        db_session.add(access)
        await db_session.flush()

        assert access.allow_sudo is False
        assert access.provisioned is False


class TestEnumerations:
    """Tests for StrEnum values used throughout the models."""

    def test_user_roles(self):
        """UserRole must contain all expected values."""
        assert set(UserRole) == {"admin", "user", "auditor", "read_only"}

    def test_user_statuses(self):
        """UserStatus must contain all expected values."""
        assert set(UserStatus) == {"active", "suspended", "deleted"}

    def test_server_statuses(self):
        """ServerStatus must contain all expected values."""
        assert set(ServerStatus) == {"active", "unreachable", "maintenance", "deleted"}

    def test_session_statuses(self):
        """SessionStatus must contain all expected values."""
        assert set(SessionStatus) == {"active", "completed", "terminated", "revoked"}

    def test_cert_statuses(self):
        """CertStatus must contain all expected values."""
        assert set(CertStatus) == {"active", "expired", "revoked"}

    def test_alert_channels(self):
        """AlertChannel must contain all expected values."""
        assert set(AlertChannel) == {"email", "ses", "slack", "pagerduty", "pushover"}

    def test_alert_severities(self):
        """AlertSeverity must contain all expected values."""
        assert set(AlertSeverity) == {"info", "warning", "critical"}

    def test_mfa_methods(self):
        """MfaMethod must contain all expected values."""
        assert set(MfaMethod) == {"totp", "email"}

    def test_os_families(self):
        """OsFamily must contain all expected values."""
        assert set(OsFamily) == {"debian", "rhel", "unknown"}

    def test_str_enum_equality(self):
        """StrEnum values must compare equal to their string equivalents."""
        assert UserRole.ADMIN == "admin"
        assert ServerStatus.ACTIVE == "active"
        assert CertStatus.REVOKED == "revoked"
