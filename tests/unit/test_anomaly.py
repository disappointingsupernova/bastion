"""Unit tests for the heuristic anomaly detection engine."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from bastion.anomaly import (
    SCORE_CONCURRENT_SESSIONS,
    SCORE_FAILED_AUTH_BURST,
    SCORE_HIGH_DATA_TRANSFER,
    SCORE_NEW_SOURCE_IP,
    SCORE_RAPID_CERT_ISSUANCE,
    evaluate_cert_issuance,
    evaluate_login,
    evaluate_session,
)
from bastion.models import (
    AnomalyEvent,
    AuditLog,
    OsFamily,
    Server,
    ServerStatus,
    Session,
    SessionStatus,
    User,
    UserRole,
    UserStatus,
)

# Patch the threshold to 0 so any non-zero score triggers an event in tests


def _settings_with_low_threshold():
    """Return a mock settings object with a threshold of 0."""
    from unittest.mock import MagicMock

    s = MagicMock()
    s.anomaly_score_alert_threshold = 0
    return s


def _make_user(username: str = "alice") -> User:
    """Return an unsaved User instance for testing."""
    return User(
        username=username,
        email=f"{username}@example.com",
        hashed_password="x",
        role=UserRole.USER,
        status=UserStatus.ACTIVE,
    )


def _make_server() -> Server:
    """Return an unsaved Server instance for testing."""
    return Server(
        hostname="srv.example.com",
        ssh_port=22,
        os_family=OsFamily.DEBIAN,
        status=ServerStatus.ACTIVE,
    )


def _make_session(user_id: str, server_id: str, **kwargs) -> Session:
    """Return an unsaved Session instance for testing."""
    return Session(
        user_id=user_id,
        server_id=server_id,
        status=SessionStatus.COMPLETED,
        started_at=datetime.now(tz=UTC),
        bytes_sent=kwargs.get("bytes_sent", 0),
        bytes_received=kwargs.get("bytes_received", 0),
    )


def _audit_log(user_id: str, success: bool, ip: str = "1.2.3.4") -> AuditLog:
    """Return an AuditLog with explicit timestamps for reliable SQLite queries."""
    now = datetime.now(tz=UTC) - timedelta(minutes=1)
    return AuditLog(
        user_id=user_id,
        action="auth.login",
        success=success,
        ip_address=ip,
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
class TestEvaluateLogin:
    """Tests for evaluate_login anomaly scoring."""

    async def test_clean_login_below_threshold_returns_none(self, db_session):
        """A normal login from a known IP with no prior failures must not trigger an anomaly."""
        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        # Seed a prior successful login from the same IP so it's not "new"
        db_session.add(_audit_log(user.id, success=True, ip="1.2.3.4"))
        await db_session.flush()

        # Use real threshold (70) — score should be 0 for a clean known-IP login
        result = await evaluate_login(db_session, user, "1.2.3.4", success=True)
        assert result is None

    async def test_new_ip_scores_new_source_ip(self, db_session):
        """A successful login from a brand-new IP must contribute SCORE_NEW_SOURCE_IP."""
        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        # With threshold=0, any score triggers an event
        with patch("bastion.anomaly.get_settings", return_value=_settings_with_low_threshold()):
            result = await evaluate_login(db_session, user, "9.9.9.9", success=True)

        assert result is not None
        assert result.score >= SCORE_NEW_SOURCE_IP

    async def test_failed_auth_burst_triggers_anomaly(self, db_session):
        """Five or more failed logins in 10 minutes must trigger an anomaly event."""
        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        for _ in range(5):
            db_session.add(_audit_log(user.id, success=False))
        await db_session.flush()

        with patch("bastion.anomaly.get_settings", return_value=_settings_with_low_threshold()):
            result = await evaluate_login(db_session, user, "1.2.3.4", success=False)

        assert result is not None
        assert result.score >= SCORE_FAILED_AUTH_BURST
        detail = json.loads(result.detail)
        assert any("burst" in f.lower() for f in detail["factors"])

    async def test_failed_auth_below_burst_threshold_no_anomaly(self, db_session):
        """Fewer than 5 failed logins must not trigger a burst anomaly."""
        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        for _ in range(4):
            db_session.add(_audit_log(user.id, success=False))
        await db_session.flush()

        # Use the real threshold (70) — 4 failures scores 0, which is below 70
        result = await evaluate_login(db_session, user, "1.2.3.4", success=False)

        # 4 failures = no burst factor, score = 0, no event
        assert result is None

    async def test_score_capped_at_100(self, db_session):
        """Anomaly score must never exceed 100 regardless of how many factors fire."""
        user = _make_user()
        server = _make_server()
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        for _ in range(5):
            db_session.add(_audit_log(user.id, success=False))
        await db_session.flush()

        with patch("bastion.anomaly.get_settings", return_value=_settings_with_low_threshold()):
            result = await evaluate_login(db_session, user, "1.2.3.4", success=False)

        if result is not None:
            assert result.score <= 100

    async def test_anomaly_event_stored_in_db(self, db_session):
        """A triggered anomaly must be persisted to the database."""
        from sqlalchemy import select

        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        for _ in range(5):
            db_session.add(_audit_log(user.id, success=False, ip="5.5.5.5"))
        await db_session.flush()

        with patch("bastion.anomaly.get_settings", return_value=_settings_with_low_threshold()):
            await evaluate_login(db_session, user, "5.5.5.5", success=False)

        result = await db_session.execute(
            select(AnomalyEvent).where(AnomalyEvent.user_id == user.id)
        )
        events = result.scalars().all()
        assert len(events) == 1
        assert events[0].alerted is False

    async def test_concurrent_sessions_factor(self, db_session):
        """More than 3 concurrent active sessions must contribute to the score."""
        user = _make_user()
        server = _make_server()
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        # Seed a prior login from this IP so new-IP factor doesn't fire
        db_session.add(_audit_log(user.id, success=True, ip="1.2.3.4"))

        for _ in range(4):
            db_session.add(
                Session(
                    user_id=user.id,
                    server_id=server.id,
                    status=SessionStatus.ACTIVE,
                    started_at=datetime.now(tz=UTC),
                )
            )
        await db_session.flush()

        with patch("bastion.anomaly.get_settings", return_value=_settings_with_low_threshold()):
            result = await evaluate_login(db_session, user, "1.2.3.4", success=True)

        assert result is not None
        assert result.score >= SCORE_CONCURRENT_SESSIONS


@pytest.mark.asyncio
class TestEvaluateSession:
    """Tests for evaluate_session anomaly scoring."""

    async def test_normal_session_no_anomaly(self, db_session):
        """A session with low data transfer must not trigger an anomaly."""
        user = _make_user()
        server = _make_server()
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        session = _make_session(user.id, server.id, bytes_sent=1024, bytes_received=4096)
        db_session.add(session)
        await db_session.flush()

        result = await evaluate_session(db_session, session)
        assert result is None

    async def test_high_data_transfer_triggers_anomaly(self, db_session):
        """A session transferring more than 500 MB must trigger an anomaly."""
        user = _make_user()
        server = _make_server()
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        big = 300 * 1024 * 1024  # 300 MB each = 600 MB total
        session = _make_session(user.id, server.id, bytes_sent=big, bytes_received=big)
        db_session.add(session)
        await db_session.flush()

        with patch("bastion.anomaly.get_settings", return_value=_settings_with_low_threshold()):
            result = await evaluate_session(db_session, session)

        assert result is not None
        assert result.score == SCORE_HIGH_DATA_TRANSFER
        detail = json.loads(result.detail)
        assert any("transfer" in f.lower() for f in detail["factors"])

    async def test_exactly_500mb_no_anomaly(self, db_session):
        """Exactly 500 MB must not trigger the high-transfer anomaly (threshold is strictly >)."""
        user = _make_user()
        server = _make_server()
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        exactly = 500 * 1024 * 1024
        session = _make_session(user.id, server.id, bytes_sent=exactly, bytes_received=0)
        db_session.add(session)
        await db_session.flush()

        result = await evaluate_session(db_session, session)
        assert result is None


@pytest.mark.asyncio
class TestEvaluateCertIssuance:
    """Tests for evaluate_cert_issuance anomaly scoring."""

    async def test_few_certs_no_anomaly(self, db_session):
        """Three or fewer certificates in 5 minutes must not trigger an anomaly."""
        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        from bastion.models import CertStatus, SshCertificate

        now = datetime.now(tz=UTC)
        for i in range(3):
            db_session.add(
                SshCertificate(
                    user_id=user.id,
                    serial=i + 1,
                    key_id=f"key-{i}",
                    principals='["alice"]',
                    valid_after=now,
                    valid_before=now + timedelta(hours=8),
                    status=CertStatus.ACTIVE,
                    created_at=now - timedelta(minutes=1),
                    updated_at=now - timedelta(minutes=1),
                )
            )
        await db_session.flush()

        result = await evaluate_cert_issuance(db_session, user.id)
        assert result is None

    async def test_rapid_cert_issuance_triggers_anomaly(self, db_session):
        """More than 3 certificates in 5 minutes must trigger an anomaly."""
        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        from bastion.models import CertStatus, SshCertificate

        now = datetime.now(tz=UTC)
        for i in range(4):
            db_session.add(
                SshCertificate(
                    user_id=user.id,
                    serial=i + 100,
                    key_id=f"rapid-key-{i}",
                    principals='["alice"]',
                    valid_after=now,
                    valid_before=now + timedelta(hours=8),
                    status=CertStatus.ACTIVE,
                    created_at=now - timedelta(minutes=1),
                    updated_at=now - timedelta(minutes=1),
                )
            )
        await db_session.flush()

        with patch("bastion.anomaly.get_settings", return_value=_settings_with_low_threshold()):
            result = await evaluate_cert_issuance(db_session, user.id)

        assert result is not None
        assert result.score == SCORE_RAPID_CERT_ISSUANCE
