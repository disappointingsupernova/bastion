"""Heuristic anomaly detection engine for the Bastion service."""

from __future__ import annotations

import json
from datetime import datetime, time, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.config import get_settings
from bastion.logging import get_logger
from bastion.models import AnomalyEvent, AuditLog, Session, SessionStatus, User

log = get_logger(__name__)

# ── Scoring weights ───────────────────────────────────────────────────────────
# Each factor contributes a score from 0–100. The final score is the sum,
# capped at 100. Scores at or above the configured threshold trigger an alert.

SCORE_FAILED_AUTH_BURST = 40       # ≥5 failed logins in 10 minutes
SCORE_OFF_HOURS_LOGIN = 20         # Login between 22:00 and 06:00 UTC
SCORE_NEW_SOURCE_IP = 25           # First time this IP has been seen for this user
SCORE_CONCURRENT_SESSIONS = 30     # User has >3 concurrent active sessions
SCORE_HIGH_DATA_TRANSFER = 35      # Session transferred >500 MB
SCORE_RAPID_CERT_ISSUANCE = 45     # >3 certs issued in 5 minutes
SCORE_REVOKED_CERT_USE_ATTEMPT = 80  # Attempt to use a revoked certificate
SCORE_UNKNOWN_SERVER_ACCESS = 50   # Access attempt to a server not in the user's access list


async def evaluate_login(
    db: AsyncSession,
    user: User,
    source_ip: str,
    success: bool,
) -> Optional[AnomalyEvent]:
    """Evaluate a login event for anomalies. Returns an AnomalyEvent if the score exceeds the threshold."""
    score = 0
    factors: list[str] = []

    if not success:
        # Check for a burst of failed logins
        window = datetime.now(tz=timezone.utc) - timedelta(minutes=10)
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
            score += SCORE_FAILED_AUTH_BURST
            factors.append(f"Failed login burst: {failed_count} attempts in 10 minutes")

    if success:
        # Off-hours detection (UTC)
        hour = datetime.now(tz=timezone.utc).hour
        if hour >= 22 or hour < 6:
            score += SCORE_OFF_HOURS_LOGIN
            factors.append(f"Login outside business hours (UTC {hour:02d}:xx)")

        # New source IP detection
        result = await db.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.user_id == user.id,
                AuditLog.action == "auth.login",
                AuditLog.success == True,  # noqa: E712
                AuditLog.ip_address == source_ip,
            )
        )
        prior_logins_from_ip = result.scalar_one()
        if prior_logins_from_ip == 0:
            score += SCORE_NEW_SOURCE_IP
            factors.append(f"First login from IP {source_ip}")

        # Concurrent sessions
        result = await db.execute(
            select(func.count(Session.id)).where(
                Session.user_id == user.id,
                Session.status == SessionStatus.ACTIVE,
            )
        )
        active_sessions = result.scalar_one()
        if active_sessions > 3:
            score += SCORE_CONCURRENT_SESSIONS
            factors.append(f"User has {active_sessions} concurrent active sessions")

    score = min(score, 100)
    return await _maybe_record(db, score, factors, user_id=user.id, ip=source_ip)


async def evaluate_session(
    db: AsyncSession,
    session: Session,
) -> Optional[AnomalyEvent]:
    """Evaluate a completed session for data transfer anomalies."""
    score = 0
    factors: list[str] = []

    total_bytes = session.bytes_sent + session.bytes_received
    if total_bytes > 500 * 1024 * 1024:  # 500 MB
        score += SCORE_HIGH_DATA_TRANSFER
        mb = total_bytes / (1024 * 1024)
        factors.append(f"High data transfer: {mb:.1f} MB in session")

    score = min(score, 100)
    return await _maybe_record(
        db, score, factors,
        user_id=session.user_id,
        server_id=session.server_id,
        session_id=session.id,
    )


async def evaluate_cert_issuance(
    db: AsyncSession,
    user_id: str,
) -> Optional[AnomalyEvent]:
    """Evaluate rapid certificate issuance for a user."""
    from bastion.models import SshCertificate

    window = datetime.now(tz=timezone.utc) - timedelta(minutes=5)
    result = await db.execute(
        select(func.count(SshCertificate.id)).where(
            SshCertificate.user_id == user_id,
            SshCertificate.created_at >= window,
        )
    )
    count = result.scalar_one()

    score = 0
    factors: list[str] = []
    if count > 3:
        score = SCORE_RAPID_CERT_ISSUANCE
        factors.append(f"Rapid certificate issuance: {count} certs in 5 minutes")

    return await _maybe_record(db, score, factors, user_id=user_id)


async def _maybe_record(
    db: AsyncSession,
    score: int,
    factors: list[str],
    user_id: Optional[str] = None,
    server_id: Optional[str] = None,
    session_id: Optional[str] = None,
    ip: Optional[str] = None,
) -> Optional[AnomalyEvent]:
    """Record an anomaly event if the score meets the threshold."""
    settings = get_settings()
    if score < settings.anomaly_score_alert_threshold:
        return None

    event_type = "anomaly." + ("login" if session_id is None else "session")
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
        user_id=user_id,
        server_id=server_id,
        factors=factors,
    )
    return event
