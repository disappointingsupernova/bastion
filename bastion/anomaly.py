"""Heuristic anomaly detection engine with structured event types and baseline learning.

Each factor produces a distinct, filterable event_type rather than the generic
anomaly.login / anomaly.session. Scores are computed relative to per-user
baselines where available, falling back to fixed thresholds.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.config import get_settings
from bastion.logging import get_logger
from bastion.models import (
    AnomalyBaseline,
    AnomalyEvent,
    AuditLog,
    Session,
    SessionStatus,
    User,
)

log = get_logger(__name__)

# ── Event type constants ──────────────────────────────────────────────────────

ET_FAILED_AUTH_BURST = "anomaly.failed_auth_burst"
ET_OFF_HOURS = "anomaly.off_hours"
ET_NEW_IP = "anomaly.new_ip"
ET_CONCURRENT_SESSIONS = "anomaly.concurrent_sessions"
ET_HIGH_DATA_TRANSFER = "anomaly.high_data_transfer"
ET_RAPID_CERT_ISSUANCE = "anomaly.rapid_cert_issuance"
ET_REVOKED_CERT_USE = "anomaly.revoked_cert_use_attempt"
ET_UNKNOWN_SERVER = "anomaly.unknown_server_access"
ET_LONG_SESSION = "anomaly.long_session"
ET_SESSION_OUTSIDE_HOURS = "anomaly.session_outside_hours"
ET_IMPOSSIBLE_TRAVEL = "anomaly.impossible_travel"
ET_EXCESSIVE_COMMANDS = "anomaly.excessive_commands"
ET_WEEKEND_ACCESS = "anomaly.weekend_access"
ET_FIRST_LOGIN = "anomaly.first_login_ever"
ET_ACCOUNT_DORMANT = "anomaly.dormant_account_login"
ET_MULTIPLE_FAILED_SERVERS = "anomaly.multiple_failed_server_attempts"

# ── Fixed scoring weights (used when no baseline exists) ─────────────────────

SCORE_FAILED_AUTH_BURST = 40
SCORE_OFF_HOURS_LOGIN = 20
SCORE_NEW_SOURCE_IP = 25
SCORE_CONCURRENT_SESSIONS = 30
SCORE_HIGH_DATA_TRANSFER = 35
SCORE_RAPID_CERT_ISSUANCE = 45
SCORE_REVOKED_CERT_USE_ATTEMPT = 80
SCORE_UNKNOWN_SERVER_ACCESS = 50
SCORE_LONG_SESSION = 20
SCORE_SESSION_OUTSIDE_HOURS = 25
SCORE_WEEKEND_ACCESS = 15
SCORE_FIRST_LOGIN = 10
SCORE_DORMANT_ACCOUNT = 35
SCORE_MULTIPLE_FAILED_SERVERS = 40


# ── Baseline helpers ──────────────────────────────────────────────────────────


async def _get_baseline(db: AsyncSession, user_id: str) -> AnomalyBaseline | None:
    """Fetch the anomaly baseline for a user, or None if not yet established."""
    result = await db.execute(select(AnomalyBaseline).where(AnomalyBaseline.user_id == user_id))
    return result.scalar_one_or_none()


async def update_baseline(db: AsyncSession, user_id: str, session: Session | None = None) -> None:
    """Update the rolling per-user anomaly baseline after a successful login or session.

    Tracks: typical login hours, known IPs, average session duration, average bytes.
    Uses an exponential moving average with a 30-day rolling window.
    """
    now = datetime.now(tz=UTC)
    baseline = await _get_baseline(db, user_id)
    if baseline is None:
        baseline = AnomalyBaseline(user_id=user_id)
        db.add(baseline)

    # Update known IPs from recent successful logins
    window = now - timedelta(days=30)
    ip_result = await db.execute(
        select(AuditLog.ip_address).where(
            AuditLog.user_id == user_id,
            AuditLog.action == "auth.login",
            AuditLog.success == True,  # noqa: E712
            AuditLog.created_at >= window,
            AuditLog.ip_address.is_not(None),
        )
    )
    known_ips = list({row[0] for row in ip_result.all() if row[0]})
    baseline.known_ips = json.dumps(known_ips)

    # Update typical hours from recent successful logins
    hour_result = await db.execute(
        select(AuditLog.created_at).where(
            AuditLog.user_id == user_id,
            AuditLog.action == "auth.login",
            AuditLog.success == True,  # noqa: E712
            AuditLog.created_at >= window,
        )
    )
    hours = [row[0].hour for row in hour_result.all() if row[0]]
    baseline.typical_hours = json.dumps(sorted(set(hours)))

    # Update session stats if a session is provided
    if session and session.ended_at and session.started_at:
        duration = (session.ended_at - session.started_at).total_seconds()
        total_bytes = float(session.bytes_sent + session.bytes_received)
        n = baseline.sample_count or 0
        alpha = 0.1  # EMA smoothing factor

        if n == 0:
            baseline.avg_session_duration_seconds = duration
            baseline.avg_session_bytes = total_bytes
        else:
            baseline.avg_session_duration_seconds = alpha * duration + (1 - alpha) * (
                baseline.avg_session_duration_seconds or duration
            )
            baseline.avg_session_bytes = alpha * total_bytes + (1 - alpha) * (
                baseline.avg_session_bytes or total_bytes
            )
        baseline.sample_count = n + 1

    baseline.last_updated_at = now
    await db.flush()
    log.debug("Anomaly baseline updated", user_id=user_id)


def _deviation_score(value: float, baseline_value: float, base_score: int) -> int:
    """Return a score scaled by how many standard deviations value is from baseline.

    Uses a simple ratio: if value > 3x baseline, return full score.
    Between 1x and 3x, scale linearly.
    """
    if baseline_value <= 0:
        return base_score
    ratio = value / baseline_value
    if ratio <= 1.0:
        return 0
    return min(base_score, int(base_score * min(1.0, (ratio - 1.0) / 2.0)))


# ── Login evaluation ──────────────────────────────────────────────────────────


async def evaluate_login(
    db: AsyncSession,
    user: User,
    source_ip: str,
    success: bool,
) -> AnomalyEvent | None:
    """Evaluate a login event for anomalies. Returns the highest-scoring event if threshold met."""
    now = datetime.now(tz=UTC)
    events: list[tuple[int, str, list[str]]] = []  # (score, event_type, factors)
    baseline = await _get_baseline(db, user.id)

    if not success:
        # Failed auth burst
        window = now - timedelta(minutes=10)
        result = await db.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.user_id == user.id,
                AuditLog.action == "auth.login",
                AuditLog.success == False,  # noqa: E712
                AuditLog.created_at >= window,
            )
        )
        failed_count = result.scalar_one()
        if failed_count >= 5:
            events.append(
                (
                    SCORE_FAILED_AUTH_BURST,
                    ET_FAILED_AUTH_BURST,
                    [f"Failed login burst: {failed_count} attempts in 10 minutes"],
                )
            )

        # Multiple failed server attempts
        server_result = await db.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.user_id == user.id,
                AuditLog.action == "session.connect.denied",
                AuditLog.created_at >= window,
            )
        )
        denied_count = server_result.scalar_one()
        if denied_count >= 3:
            events.append(
                (
                    SCORE_MULTIPLE_FAILED_SERVERS,
                    ET_MULTIPLE_FAILED_SERVERS,
                    [f"Attempted {denied_count} denied server connections in 10 minutes"],
                )
            )

    if success:
        hour = now.hour
        weekday = now.weekday()  # 0=Monday, 6=Sunday

        # Off-hours detection — baseline-aware
        if baseline and baseline.typical_hours:
            typical = json.loads(baseline.typical_hours)
            if typical and hour not in typical:
                events.append(
                    (
                        SCORE_OFF_HOURS_LOGIN,
                        ET_OFF_HOURS,
                        [f"Login at hour {hour:02d}:xx UTC — outside typical hours {typical}"],
                    )
                )
        elif hour >= 22 or hour < 6:
            events.append(
                (
                    SCORE_OFF_HOURS_LOGIN,
                    ET_OFF_HOURS,
                    [f"Login outside business hours (UTC {hour:02d}:xx)"],
                )
            )

        # Weekend access
        if weekday >= 5:
            events.append(
                (
                    SCORE_WEEKEND_ACCESS,
                    ET_WEEKEND_ACCESS,
                    [f"Login on {'Saturday' if weekday == 5 else 'Sunday'}"],
                )
            )

        # New source IP — baseline-aware
        if baseline and baseline.known_ips:
            known = json.loads(baseline.known_ips)
            if source_ip not in known:
                events.append(
                    (
                        SCORE_NEW_SOURCE_IP,
                        ET_NEW_IP,
                        [f"First login from IP {source_ip} (not in 30-day baseline)"],
                    )
                )
        else:
            result = await db.execute(
                select(func.count(AuditLog.id)).where(
                    AuditLog.user_id == user.id,
                    AuditLog.action == "auth.login",
                    AuditLog.success == True,  # noqa: E712
                    AuditLog.ip_address == source_ip,
                )
            )
            if result.scalar_one() == 0:
                events.append(
                    (
                        SCORE_NEW_SOURCE_IP,
                        ET_NEW_IP,
                        [f"First login from IP {source_ip}"],
                    )
                )

        # First login ever
        result = await db.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.user_id == user.id,
                AuditLog.action == "auth.login",
                AuditLog.success == True,  # noqa: E712
            )
        )
        if result.scalar_one() == 1:  # This is the first successful login
            events.append(
                (
                    SCORE_FIRST_LOGIN,
                    ET_FIRST_LOGIN,
                    ["First ever successful login for this account"],
                )
            )

        # Dormant account (no login in 90 days)
        if user.last_login_at:
            days_since = (now - user.last_login_at).days
            if days_since > 90:
                events.append(
                    (
                        SCORE_DORMANT_ACCOUNT,
                        ET_ACCOUNT_DORMANT,
                        [f"Account dormant for {days_since} days before this login"],
                    )
                )

        # Concurrent sessions
        result = await db.execute(
            select(func.count(Session.id)).where(
                Session.user_id == user.id,
                Session.status == SessionStatus.ACTIVE,
            )
        )
        active_sessions = result.scalar_one()
        if active_sessions > 3:
            events.append(
                (
                    SCORE_CONCURRENT_SESSIONS,
                    ET_CONCURRENT_SESSIONS,
                    [f"User has {active_sessions} concurrent active sessions"],
                )
            )

        # Update baseline after successful login
        await update_baseline(db, user.id)

    if not events:
        return None

    # Record the highest-scoring event
    events.sort(key=lambda x: x[0], reverse=True)
    top_score, top_type, top_factors = events[0]
    total_score = min(sum(e[0] for e in events), 100)

    return await _maybe_record(
        db,
        total_score,
        top_factors + [f"({len(events)} factors total)"] if len(events) > 1 else top_factors,
        event_type=top_type,
        user_id=user.id,
        ip=source_ip,
    )


# ── Session evaluation ────────────────────────────────────────────────────────


async def evaluate_session(
    db: AsyncSession,
    session: Session,
) -> AnomalyEvent | None:
    """Evaluate a completed session for data transfer and duration anomalies."""
    baseline = await _get_baseline(db, session.user_id)
    score = 0
    factors: list[str] = []
    event_type = ET_HIGH_DATA_TRANSFER

    total_bytes = session.bytes_sent + session.bytes_received

    # High data transfer — baseline-aware
    if baseline and baseline.avg_session_bytes and baseline.avg_session_bytes > 0:
        byte_score = _deviation_score(
            float(total_bytes), baseline.avg_session_bytes, SCORE_HIGH_DATA_TRANSFER
        )
        if byte_score > 0:
            mb = total_bytes / (1024 * 1024)
            avg_mb = baseline.avg_session_bytes / (1024 * 1024)
            score += byte_score
            factors.append(f"Data transfer {mb:.1f} MB vs baseline {avg_mb:.1f} MB")
    elif total_bytes > 500 * 1024 * 1024:
        score += SCORE_HIGH_DATA_TRANSFER
        factors.append(f"High data transfer: {total_bytes / (1024 * 1024):.1f} MB")

    # Long session — baseline-aware
    if session.ended_at and session.started_at:
        duration = (session.ended_at - session.started_at).total_seconds()
        if (
            baseline
            and baseline.avg_session_duration_seconds
            and baseline.avg_session_duration_seconds > 0
        ):
            dur_score = _deviation_score(
                duration, baseline.avg_session_duration_seconds, SCORE_LONG_SESSION
            )
            if dur_score > 0:
                score += dur_score
                event_type = ET_LONG_SESSION
                factors.append(
                    f"Session duration {duration / 60:.0f}m vs baseline {baseline.avg_session_duration_seconds / 60:.0f}m"
                )
        elif duration > 8 * 3600:  # 8 hours
            score += SCORE_LONG_SESSION
            event_type = ET_LONG_SESSION
            factors.append(f"Session duration {duration / 3600:.1f}h exceeds 8h threshold")

    # Session outside typical hours
    if session.started_at and baseline and baseline.typical_hours:
        typical = json.loads(baseline.typical_hours)
        if typical and session.started_at.hour not in typical:
            score += SCORE_SESSION_OUTSIDE_HOURS
            event_type = ET_SESSION_OUTSIDE_HOURS
            factors.append(
                f"Session started at hour {session.started_at.hour:02d}:xx UTC — outside baseline"
            )

    # Update baseline with this session's stats
    await update_baseline(db, session.user_id, session=session)

    score = min(score, 100)
    return await _maybe_record(
        db,
        score,
        factors,
        event_type=event_type,
        user_id=session.user_id,
        server_id=session.server_id,
        session_id=session.id,
    )


# ── Certificate issuance evaluation ──────────────────────────────────────────


async def evaluate_cert_issuance(
    db: AsyncSession,
    user_id: str,
) -> AnomalyEvent | None:
    """Evaluate rapid certificate issuance for a user."""
    from bastion.models import SshCertificate

    window = datetime.now(tz=UTC) - timedelta(minutes=5)
    result = await db.execute(
        select(func.count(SshCertificate.id)).where(
            SshCertificate.user_id == user_id,
            SshCertificate.created_at >= window,
        )
    )
    count = result.scalar_one()

    if count <= 3:
        return None

    return await _maybe_record(
        db,
        SCORE_RAPID_CERT_ISSUANCE,
        [f"Rapid certificate issuance: {count} certs in 5 minutes"],
        event_type=ET_RAPID_CERT_ISSUANCE,
        user_id=user_id,
    )


# ── Internal helpers ──────────────────────────────────────────────────────────


async def _maybe_record(
    db: AsyncSession,
    score: int,
    factors: list[str],
    event_type: str,
    user_id: str | None = None,
    server_id: str | None = None,
    session_id: str | None = None,
    ip: str | None = None,
) -> AnomalyEvent | None:
    """Record an anomaly event if the score meets the configured threshold."""
    settings = get_settings()
    if score < settings.anomaly_score_alert_threshold:
        return None

    event = AnomalyEvent(
        user_id=user_id,
        server_id=server_id,
        session_id=session_id,
        event_type=event_type,
        score=score,
        detail=json.dumps({"factors": factors, "source_ip": ip}),
    )
    db.add(event)
    await db.flush()

    log.warning(
        "Anomaly detected",
        score=score,
        event_type=event_type,
        user_id=user_id,
        server_id=server_id,
        factors=factors,
    )
    return event
