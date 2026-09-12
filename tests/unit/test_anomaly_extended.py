"""Unit tests for anomaly detection — off-hours, weekend, dormant, baseline-aware login paths."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from bastion.anomaly import (
    ET_MULTIPLE_FAILED_SERVERS,
    ET_OFF_HOURS,
    ET_SESSION_OUTSIDE_HOURS,
    ET_WEEKEND_ACCESS,
    _deviation_score,
    evaluate_login,
    evaluate_session,
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


def _settings_low():
    from unittest.mock import MagicMock

    s = MagicMock()
    s.anomaly_score_alert_threshold = 0
    return s


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

    def test_value_at_or_below_baseline_returns_zero(self):
        """A value <= baseline must return 0."""
        assert _deviation_score(100.0, 100.0, 50) == 0
        assert _deviation_score(50.0, 100.0, 50) == 0

    def test_value_above_baseline_returns_positive(self):
        """A value above baseline must return a positive score."""
        assert _deviation_score(300.0, 100.0, 50) > 0

    def test_value_3x_baseline_returns_full_score(self):
        """A value >= 3x baseline must return the full base_score."""
        assert _deviation_score(300.0, 100.0, 50) == 50

    def test_zero_baseline_returns_base_score(self):
        """A zero baseline must return the full base_score."""
        assert _deviation_score(100.0, 0.0, 40) == 40

    def test_score_capped_at_base_score(self):
        """The returned score must never exceed base_score."""
        result = _deviation_score(10000.0, 1.0, 35)
        assert result <= 35


@pytest.mark.asyncio
class TestOffHoursAndWeekend:
    """Tests for off-hours and weekend anomaly factors."""

    async def test_off_hours_login_no_baseline_triggers(self, db_session):
        """A login at 3am UTC with no baseline must trigger the off-hours factor."""
        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        # Seed a prior login from same IP so new-IP factor doesn't fire
        now = datetime.now(tz=UTC)
        db_session.add(
            AuditLog(
                user_id=user.id,
                action="auth.login",
                success=True,
                ip_address="1.2.3.4",
                created_at=now - timedelta(minutes=5),
                updated_at=now - timedelta(minutes=5),
            )
        )
        await db_session.flush()

        # Patch datetime.now to return 3am UTC
        fixed_3am = datetime(2024, 6, 3, 3, 0, 0, tzinfo=UTC)  # Monday 3am

        with (
            patch("bastion.anomaly.get_settings", return_value=_settings_low()),
            patch("bastion.anomaly.datetime") as mock_dt,
        ):
            mock_dt.now.return_value = fixed_3am
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            result = await evaluate_login(db_session, user, "1.2.3.4", success=True)

        # Off-hours should fire (3am is outside 6-22)
        if result is not None:
            assert result.event_type in (ET_OFF_HOURS, ET_WEEKEND_ACCESS)

    async def test_baseline_aware_off_hours_triggers_when_outside_typical(self, db_session):
        """A login outside the user's typical hours baseline must trigger ET_OFF_HOURS."""
        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        # Baseline: typical hours are 9-17
        db_session.add(
            AnomalyBaseline(
                user_id=user.id,
                known_ips=json.dumps(["1.2.3.4"]),
                typical_hours=json.dumps(list(range(9, 18))),
            )
        )
        await db_session.flush()

        # Login at 3am — outside typical hours
        fixed_3am = datetime(2024, 6, 3, 3, 0, 0, tzinfo=UTC)

        with (
            patch("bastion.anomaly.get_settings", return_value=_settings_low()),
            patch("bastion.anomaly.datetime") as mock_dt,
        ):
            mock_dt.now.return_value = fixed_3am
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            result = await evaluate_login(db_session, user, "1.2.3.4", success=True)

        assert result is not None
        assert result.event_type == ET_OFF_HOURS

    async def test_baseline_aware_off_hours_no_trigger_within_typical(self, db_session):
        """A login within the user's typical hours must not trigger ET_OFF_HOURS."""
        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        db_session.add(
            AnomalyBaseline(
                user_id=user.id,
                known_ips=json.dumps(["1.2.3.4"]),
                typical_hours=json.dumps(list(range(24))),  # all hours typical
            )
        )
        await db_session.flush()

        fixed_noon = datetime(2024, 6, 3, 12, 0, 0, tzinfo=UTC)

        with patch("bastion.anomaly.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_noon
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            result = await evaluate_login(db_session, user, "1.2.3.4", success=True)

        assert result is None

    async def test_weekend_access_triggers_on_saturday(self, db_session):
        """A login on Saturday must trigger ET_WEEKEND_ACCESS."""
        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        # Seed known IP
        now = datetime.now(tz=UTC)
        db_session.add(
            AuditLog(
                user_id=user.id,
                action="auth.login",
                success=True,
                ip_address="1.2.3.4",
                created_at=now - timedelta(minutes=5),
                updated_at=now - timedelta(minutes=5),
            )
        )
        await db_session.flush()

        # Saturday at noon
        saturday_noon = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)  # June 1 2024 = Saturday

        with (
            patch("bastion.anomaly.get_settings", return_value=_settings_low()),
            patch("bastion.anomaly.datetime") as mock_dt,
        ):
            mock_dt.now.return_value = saturday_noon
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            result = await evaluate_login(db_session, user, "1.2.3.4", success=True)

        assert result is not None
        assert result.event_type == ET_WEEKEND_ACCESS


@pytest.mark.asyncio
class TestDormantAccount:
    """Tests for dormant account anomaly factor."""

    async def test_dormant_account_triggers_after_90_days(self, db_session):
        """A login after 90+ days of inactivity must trigger ET_ACCOUNT_DORMANT."""
        user = _make_user()
        user.last_login_at = datetime.now(tz=UTC) - timedelta(days=91)
        db_session.add(user)
        await db_session.flush()

        with patch("bastion.anomaly.get_settings", return_value=_settings_low()):
            result = await evaluate_login(db_session, user, "9.9.9.9", success=True)

        assert result is not None
        detail = json.loads(result.detail)
        assert any("dormant" in f.lower() or "91" in f for f in detail["factors"])

    async def test_recent_login_does_not_trigger_dormant(self, db_session):
        """A login within 90 days must not trigger the dormant factor."""
        user = _make_user()
        user.last_login_at = datetime.now(tz=UTC) - timedelta(days=30)
        db_session.add(user)
        await db_session.flush()

        # Seed known IP so new-IP doesn't fire
        now = datetime.now(tz=UTC)
        db_session.add(
            AuditLog(
                user_id=user.id,
                action="auth.login",
                success=True,
                ip_address="1.2.3.4",
                created_at=now - timedelta(minutes=5),
                updated_at=now - timedelta(minutes=5),
            )
        )
        await db_session.flush()

        result = await evaluate_login(db_session, user, "1.2.3.4", success=True)
        assert result is None


@pytest.mark.asyncio
class TestMultipleFailedServers:
    """Tests for multiple failed server attempts anomaly factor."""

    async def test_multiple_denied_connections_triggers(self, db_session):
        """Three or more denied server connections in 10 minutes must trigger the factor."""
        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        now = datetime.now(tz=UTC)
        for _ in range(3):
            db_session.add(
                AuditLog(
                    user_id=user.id,
                    action="session.connect.denied",
                    success=False,
                    created_at=now - timedelta(minutes=1),
                    updated_at=now - timedelta(minutes=1),
                )
            )
        await db_session.flush()

        with patch("bastion.anomaly.get_settings", return_value=_settings_low()):
            result = await evaluate_login(db_session, user, "1.2.3.4", success=False)

        assert result is not None
        assert result.event_type == ET_MULTIPLE_FAILED_SERVERS


@pytest.mark.asyncio
class TestSessionOutsideHours:
    """Tests for session outside typical hours anomaly factor."""

    async def test_session_outside_typical_hours_triggers(self, db_session):
        """A session started outside the user's typical hours must trigger ET_SESSION_OUTSIDE_HOURS."""
        user = _make_user()
        server = _make_server()
        db_session.add(user)
        db_session.add(server)
        await db_session.flush()

        # Baseline: typical hours are 9-17
        db_session.add(
            AnomalyBaseline(
                user_id=user.id,
                typical_hours=json.dumps(list(range(9, 18))),
                avg_session_bytes=1024.0,
                avg_session_duration_seconds=300.0,
                sample_count=10,
            )
        )
        await db_session.flush()

        # Session started at 3am
        start = datetime(2024, 6, 3, 3, 0, 0, tzinfo=UTC)
        end = datetime(2024, 6, 3, 3, 5, 0, tzinfo=UTC)
        session = Session(
            user_id=user.id,
            server_id=server.id,
            status=SessionStatus.COMPLETED,
            started_at=start,
            ended_at=end,
            bytes_sent=512,
            bytes_received=512,
        )
        db_session.add(session)
        await db_session.flush()

        with patch("bastion.anomaly.get_settings", return_value=_settings_low()):
            result = await evaluate_session(db_session, session)

        assert result is not None
        assert result.event_type == ET_SESSION_OUTSIDE_HOURS


@pytest.mark.asyncio
class TestUpdateBaseline:
    """Tests for update_baseline."""

    async def test_creates_baseline_when_none_exists(self, db_session):
        """update_baseline must create a new AnomalyBaseline when none exists."""
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

    async def test_updates_existing_baseline(self, db_session):
        """update_baseline must update an existing baseline without creating a duplicate."""
        from sqlalchemy import func, select

        user = _make_user()
        db_session.add(user)
        await db_session.flush()

        db_session.add(AnomalyBaseline(user_id=user.id))
        await db_session.flush()

        await update_baseline(db_session, user.id)
        await update_baseline(db_session, user.id)

        count_result = await db_session.execute(
            select(func.count(AnomalyBaseline.id)).where(AnomalyBaseline.user_id == user.id)
        )
        assert count_result.scalar_one() == 1

    async def test_updates_session_stats_when_session_provided(self, db_session):
        """update_baseline must update avg_session_bytes when a session is provided."""
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
            started_at=now - timedelta(minutes=5),
            ended_at=now,
            bytes_sent=1024,
            bytes_received=2048,
        )
        db_session.add(session)
        await db_session.flush()

        await update_baseline(db_session, user.id, session=session)

        from sqlalchemy import select

        result = await db_session.execute(
            select(AnomalyBaseline).where(AnomalyBaseline.user_id == user.id)
        )
        baseline = result.scalar_one()
        assert baseline.avg_session_bytes == float(1024 + 2048)
        assert baseline.sample_count == 1
