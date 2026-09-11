"""Unit tests for compliance report generation."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta

import pytest

from bastion.compliance import (
    _rows_to_csv,
    build_report,
    generate_access_matrix,
    generate_failed_auth_summary,
    generate_sessions_report,
)
from bastion.models import (
    AuditLog,
    OsFamily,
    Server,
    ServerAccess,
    ServerStatus,
    Session,
    SessionStatus,
    User,
    UserRole,
    UserStatus,
)


def _make_user(username: str, email: str | None = None) -> User:
    return User(
        username=username,
        email=email or f"{username}@example.com",
        hashed_password="x",
        role=UserRole.USER,
        status=UserStatus.ACTIVE,
    )


def _make_server(hostname: str) -> Server:
    return Server(
        hostname=hostname,
        ssh_port=22,
        os_family=OsFamily.DEBIAN,
        status=ServerStatus.ACTIVE,
    )


class TestRowsToCsv:
    """Tests for _rows_to_csv."""

    def test_empty_rows_returns_empty_bytes(self):
        """An empty list must return empty bytes."""
        assert _rows_to_csv([]) == b""

    def test_single_row_has_header_and_data(self):
        """A single row must produce a header line and a data line."""
        rows = [{"username": "alice", "server": "web01"}]
        result = _rows_to_csv(rows)
        lines = result.decode().strip().splitlines()
        assert lines[0] == "username,server"
        assert lines[1] == "alice,web01"

    def test_multiple_rows_all_present(self):
        """All rows must appear in the CSV output."""
        rows = [{"a": "1"}, {"a": "2"}, {"a": "3"}]
        result = _rows_to_csv(rows)
        reader = csv.DictReader(io.StringIO(result.decode()))
        values = [r["a"] for r in reader]
        assert values == ["1", "2", "3"]

    def test_returns_bytes(self):
        """_rows_to_csv must return bytes, not str."""
        result = _rows_to_csv([{"x": "y"}])
        assert isinstance(result, bytes)


@pytest.mark.asyncio
class TestGenerateAccessMatrix:
    """Tests for generate_access_matrix."""

    async def test_empty_db_returns_empty_list(self, db_session):
        """With no access grants, the matrix must be empty."""
        result = await generate_access_matrix(db_session)
        assert result == []

    async def test_single_grant_appears_in_matrix(self, db_session):
        """A single active access grant must appear in the matrix."""
        user = _make_user("alice")
        server = _make_server("web01.example.com")
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        access = ServerAccess(user_id=user.id, server_id=server.id, allow_sudo=False)
        db_session.add(access)
        await db_session.flush()

        result = await generate_access_matrix(db_session)
        assert len(result) == 1
        assert result[0]["username"] == "alice"
        assert result[0]["server"] == "web01.example.com"
        assert result[0]["sudo"] == "no"

    async def test_sudo_grant_shows_yes(self, db_session):
        """A sudo grant must show 'yes' in the sudo column."""
        user = _make_user("bob")
        server = _make_server("db01.example.com")
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        access = ServerAccess(user_id=user.id, server_id=server.id, allow_sudo=True)
        db_session.add(access)
        await db_session.flush()

        result = await generate_access_matrix(db_session)
        assert result[0]["sudo"] == "yes"

    async def test_revoked_grant_excluded(self, db_session):
        """A revoked access grant must not appear in the matrix."""
        user = _make_user("carol")
        server = _make_server("srv.example.com")
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        access = ServerAccess(
            user_id=user.id,
            server_id=server.id,
            allow_sudo=False,
            revoked_at=datetime.now(tz=UTC),
        )
        db_session.add(access)
        await db_session.flush()

        result = await generate_access_matrix(db_session)
        assert result == []

    async def test_expires_at_shown_when_set(self, db_session):
        """A grant with expires_at must show the ISO timestamp."""
        user = _make_user("dave")
        server = _make_server("tmp.example.com")
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        expires = datetime(2025, 12, 31, 23, 59, 59, tzinfo=UTC)
        access = ServerAccess(
            user_id=user.id, server_id=server.id, allow_sudo=False, expires_at=expires
        )
        db_session.add(access)
        await db_session.flush()

        result = await generate_access_matrix(db_session)
        assert "2025-12-31" in result[0]["expires_at"]

    async def test_no_expiry_shows_never(self, db_session):
        """A grant without expires_at must show 'never'."""
        user = _make_user("eve")
        server = _make_server("perm.example.com")
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        access = ServerAccess(user_id=user.id, server_id=server.id, allow_sudo=False)
        db_session.add(access)
        await db_session.flush()

        result = await generate_access_matrix(db_session)
        assert result[0]["expires_at"] == "never"


@pytest.mark.asyncio
class TestGenerateSessionsReport:
    """Tests for generate_sessions_report."""

    async def test_empty_db_returns_empty_list(self, db_session):
        """With no sessions, the report must be empty."""
        result = await generate_sessions_report(db_session)
        assert result == []

    async def test_session_counted_per_server(self, db_session):
        """Sessions must be grouped and counted per server."""
        user = _make_user("alice")
        server = _make_server("web01.example.com")
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        now = datetime.now(tz=UTC)
        for _ in range(3):
            db_session.add(
                Session(
                    user_id=user.id,
                    server_id=server.id,
                    status=SessionStatus.COMPLETED,
                    started_at=now,
                    bytes_sent=100,
                    bytes_received=200,
                )
            )
        await db_session.flush()

        result = await generate_sessions_report(db_session)
        assert len(result) == 1
        assert result[0]["server"] == "web01.example.com"
        assert result[0]["session_count"] == 3

    async def test_old_sessions_excluded_by_days_filter(self, db_session):
        """Sessions older than the days window must be excluded."""
        user = _make_user("alice")
        server = _make_server("old.example.com")
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        old_time = datetime.now(tz=UTC) - timedelta(days=60)
        db_session.add(
            Session(
                user_id=user.id,
                server_id=server.id,
                status=SessionStatus.COMPLETED,
                started_at=old_time,
            )
        )
        await db_session.flush()

        result = await generate_sessions_report(db_session, days=30)
        assert result == []


@pytest.mark.asyncio
class TestGenerateFailedAuthSummary:
    """Tests for generate_failed_auth_summary."""

    async def test_empty_db_returns_empty_list(self, db_session):
        """With no failed logins, the summary must be empty."""
        result = await generate_failed_auth_summary(db_session)
        assert result == []

    async def test_failed_logins_counted_per_user(self, db_session):
        """Failed logins must be grouped and counted per user."""
        user = _make_user("alice")
        db_session.add(user)
        await db_session.flush()

        now = datetime.now(tz=UTC)
        for _ in range(5):
            db_session.add(
                AuditLog(
                    user_id=user.id,
                    action="auth.login",
                    success=False,
                    created_at=now,
                    updated_at=now,
                )
            )
        await db_session.flush()

        result = await generate_failed_auth_summary(db_session)
        assert len(result) == 1
        assert result[0]["username"] == "alice"
        assert result[0]["failed_count"] == 5

    async def test_successful_logins_excluded(self, db_session):
        """Successful logins must not appear in the failed auth summary."""
        user = _make_user("bob")
        db_session.add(user)
        await db_session.flush()

        now = datetime.now(tz=UTC)
        db_session.add(
            AuditLog(
                user_id=user.id,
                action="auth.login",
                success=True,
                created_at=now,
                updated_at=now,
            )
        )
        await db_session.flush()

        result = await generate_failed_auth_summary(db_session)
        assert result == []


@pytest.mark.asyncio
class TestBuildReport:
    """Tests for build_report."""

    async def test_unknown_report_type_raises(self, db_session):
        """An unknown report type must raise ValueError."""
        with pytest.raises(ValueError, match="Unknown report type"):
            await build_report(db_session, "nonexistent_type")

    async def test_csv_format_returns_bytes_and_filename(self, db_session):
        """A CSV report must return bytes and a .csv filename."""
        content, filename = await build_report(db_session, "access_matrix", fmt="csv")
        assert isinstance(content, bytes)
        assert filename.endswith(".csv")
        assert "access_matrix" in filename

    async def test_all_report_types_succeed(self, db_session):
        """All four report types must complete without error on an empty DB."""
        for report_type in ("access_matrix", "sessions", "cert_history", "failed_auth"):
            content, filename = await build_report(db_session, report_type, fmt="csv")
            assert isinstance(content, bytes)
