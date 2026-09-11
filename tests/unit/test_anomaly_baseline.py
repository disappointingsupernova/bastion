"""Unit tests for anomaly baseline learning and deviation scoring."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from bastion.anomaly import (
    _deviation_score,
    update_baseline,
)
from bastion.models import (
    AnomalyBaseline,
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


def _make_user(username: str = "alice") -> User:
    return User(
        username=username,
        email=f"{username}@example.com",
        hashed_password="x",
        role=UserRole.USER,
        status=UserStatus.ACTIVE,
    )


def _make_server() -> Server:
    return Server(
        hostname="srv.example.com",
        ssh_port=22,
        os_family=OsFamily.DEBIAN,
        status=ServerStatus.ACTIVE,
    )


class TestDeviationScore:
    """Tests for _deviation_score."""

    def test_value_below_baseline_returns_zero(self):
        """A value at or below the baseline must return 0."""
        assert _deviation_score(50.0, 100.0, 30) == 0

    def test_value_equal_to_baseline_returns_zero(self):
        """A value exactly equal to the baseline must return 0."""
        assert _deviation_score(100.0, 100.0, 30) == 0

    def test_value_3x_baseline_returns_full_score(self):
        """A value 3x the baseline must return the full base_score."""
        assert _deviation_score(300.0, 100.0, 30) == 30

    def test_value_2x_baseline_returns_half_score(self):
        """A value 2x the baseline must return approximately half the base_score."""
        result = _deviation_score(200.0, 100.0, 30)
        assert 0 < result < 30

    def test_zero_baseline_returns_full_score(self):
        """A zero baseline must return the full base_score (no division by zero)."""
        assert _deviation_score(100.0, 0.0, 30) == 30

    def test_score_never_exceeds_base_score(self):
        """The result must never exceed base_score regardless of the ratio."""
        assert _deviation_score(10000.0, 1.0, 50) == 50


@pytest.mark.asyncio
class TestUpdateBaseline:
    """Tests for update_baseline."""

    async def test_creates_baseline_for_new_user(self, db_session):
        """update_baseline must create an AnomalyBaseline record for a new user."""
        from sqlalchemy import select

        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        await update_baseline(db_session, user.id)

        result = await db_session.execute(
            select(AnomalyBaseline).where(AnomalyBaseline.user_id == user.id)
        )
        baseline = result.scalar_one_or_none()
        assert baseline is not None

    async def test_known_ips_populated_from_audit_log(self, db_session):
        """Known IPs must be populated from recent successful login audit entries."""
        from sqlalchemy import select

        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        now = datetime.now(tz=UTC)
        db_session.add(
            AuditLog(
                user_id=user.id,
                action="auth.login",
                success=True,
                ip_address="10.0.0.1",
                created_at=now,
                updated_at=now,
            )
        )
        db_session.add(
            AuditLog(
                user_id=user.id,
                action="auth.login",
                success=True,
                ip_address="10.0.0.2",
                created_at=now,
                updated_at=now,
            )
        )
        await db_session.flush()

        await update_baseline(db_session, user.id)

        result = await db_session.execute(
            select(AnomalyBaseline).where(AnomalyBaseline.user_id == user.id)
        )
        baseline = result.scalar_one()
        known_ips = json.loads(baseline.known_ips)
        assert "10.0.0.1" in known_ips
        assert "10.0.0.2" in known_ips

    async def test_typical_hours_populated(self, db_session):
        """Typical hours must be populated from recent successful login timestamps."""
        from sqlalchemy import select

        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        # Create a login at a specific hour
        login_time = datetime.now(tz=UTC).replace(hour=14, minute=0, second=0, microsecond=0)
        db_session.add(
            AuditLog(
                user_id=user.id,
                action="auth.login",
                success=True,
                ip_address="1.2.3.4",
                created_at=login_time,
                updated_at=login_time,
            )
        )
        await db_session.flush()

        await update_baseline(db_session, user.id)

        result = await db_session.execute(
            select(AnomalyBaseline).where(AnomalyBaseline.user_id == user.id)
        )
        baseline = result.scalar_one()
        typical_hours = json.loads(baseline.typical_hours)
        assert 14 in typical_hours

    async def test_session_stats_updated_with_session(self, db_session):
        """Providing a session must update avg_session_duration_seconds and avg_session_bytes."""
        from sqlalchemy import select

        user = _make_user()
        server = _make_server()
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        now = datetime.now(tz=UTC)
        session = Session(
            user_id=user.id,
            server_id=server.id,
            status=SessionStatus.COMPLETED,
            started_at=now - timedelta(minutes=30),
            ended_at=now,
            bytes_sent=1024,
            bytes_received=2048,
        )
        db_session.add(session)
        await db_session.flush()

        await update_baseline(db_session, user.id, session=session)

        result = await db_session.execute(
            select(AnomalyBaseline).where(AnomalyBaseline.user_id == user.id)
        )
        baseline = result.scalar_one()
        assert baseline.avg_session_duration_seconds is not None
        assert baseline.avg_session_duration_seconds > 0
        assert baseline.avg_session_bytes == 3072.0
        assert baseline.sample_count == 1

    async def test_ema_applied_on_second_session(self, db_session):
        """The second session must apply EMA smoothing to the existing baseline."""
        from sqlalchemy import select

        user = _make_user()
        server = _make_server()
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        now = datetime.now(tz=UTC)

        # First session: 10 minutes, 1000 bytes
        s1 = Session(
            user_id=user.id,
            server_id=server.id,
            status=SessionStatus.COMPLETED,
            started_at=now - timedelta(minutes=10),
            ended_at=now,
            bytes_sent=500,
            bytes_received=500,
        )
        db_session.add(s1)
        await db_session.flush()
        await update_baseline(db_session, user.id, session=s1)

        # Second session: 60 minutes, 10000 bytes
        s2 = Session(
            user_id=user.id,
            server_id=server.id,
            status=SessionStatus.COMPLETED,
            started_at=now - timedelta(minutes=60),
            ended_at=now,
            bytes_sent=5000,
            bytes_received=5000,
        )
        db_session.add(s2)
        await db_session.flush()
        await update_baseline(db_session, user.id, session=s2)

        result = await db_session.execute(
            select(AnomalyBaseline).where(AnomalyBaseline.user_id == user.id)
        )
        baseline = result.scalar_one()
        # EMA should be between the two values, not equal to either
        assert baseline.sample_count == 2
        assert 1000.0 < baseline.avg_session_bytes < 10000.0

    async def test_idempotent_update_does_not_duplicate(self, db_session):
        """Calling update_baseline twice must not create duplicate records."""
        from sqlalchemy import select

        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        await update_baseline(db_session, user.id)
        await update_baseline(db_session, user.id)

        result = await db_session.execute(
            select(AnomalyBaseline).where(AnomalyBaseline.user_id == user.id)
        )
        baselines = result.scalars().all()
        assert len(baselines) == 1
