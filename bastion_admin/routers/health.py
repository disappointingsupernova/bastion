"""Admin health dashboard — service metrics, storage, active sessions, and cluster node status."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.db import get_db
from bastion.logging import get_logger
from bastion.models import (
    AnomalyEvent,
    BastionNode,
    CertStatus,
    Session,
    SessionStatus,
    SshCertificate,
    User,
    UserRole,
    UserStatus,
)
from bastion_api.deps import require_role

log = get_logger(__name__)
router = APIRouter(prefix="/health", tags=["Health"])

_admin_or_auditor = require_role(UserRole.ADMIN, UserRole.AUDITOR)


class NodeStatus(BaseModel):
    node_id: str
    version: str | None
    last_heartbeat_at: datetime | None
    alive: bool
    load_metrics: str | None


class HealthDashboard(BaseModel):
    service: str = "bastion-admin"
    status: str = "ok"
    db_size_bytes: int | None
    recording_storage_bytes: int | None
    active_sessions: int
    pending_anomaly_events: int
    certs_expiring_soon: int
    active_users: int
    cluster_nodes: list[NodeStatus]
    generated_at: datetime


@router.get("/dashboard", response_model=HealthDashboard)
async def health_dashboard(
    current_user: Annotated[object, Depends(_admin_or_auditor)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> HealthDashboard:
    """Return a comprehensive health and status dashboard for the Bastion service."""
    from bastion.config import get_settings

    settings = get_settings()
    now = datetime.now(tz=UTC)

    # Active sessions
    active_sessions = (
        await db.execute(
            select(func.count(Session.id)).where(Session.status == SessionStatus.ACTIVE)
        )
    ).scalar_one()

    # Pending anomaly events
    pending_anomalies = (
        await db.execute(
            select(func.count(AnomalyEvent.id)).where(AnomalyEvent.alerted == False)  # noqa: E712
        )
    ).scalar_one()

    # Certs expiring in the next hour
    warn_before = now + timedelta(hours=1)
    certs_expiring = (
        await db.execute(
            select(func.count(SshCertificate.id)).where(
                SshCertificate.status == CertStatus.ACTIVE,
                SshCertificate.valid_before <= warn_before,
                SshCertificate.valid_before > now,
            )
        )
    ).scalar_one()

    # Active users
    active_users = (
        await db.execute(
            select(func.count(User.id)).where(
                User.status == UserStatus.ACTIVE,
                User.deleted_at.is_(None),
            )
        )
    ).scalar_one()

    # DB size
    db_size: int | None = None
    if settings.is_sqlite:
        try:
            db_path = settings.bastion_root / "data" / "bastion.db"
            db_size = db_path.stat().st_size if db_path.exists() else None
        except OSError as exc:
            log.debug("Could not read SQLite database size", error=str(exc))
    else:
        try:
            result = await db.execute(text("SELECT pg_database_size(current_database())"))
            db_size = result.scalar_one()
        except Exception as exc:
            log.debug("Could not query PostgreSQL database size", error=str(exc))

    # Recording storage
    recording_bytes: int | None = None
    try:
        rec_path = settings.recordings_path
        if rec_path.exists():
            recording_bytes = sum(f.stat().st_size for f in rec_path.rglob("*") if f.is_file())
    except OSError as exc:
        log.debug("Could not calculate recording storage size", error=str(exc))

    # Cluster nodes
    nodes_result = await db.execute(select(BastionNode).order_by(BastionNode.node_id))
    stale_threshold = now - timedelta(minutes=2)
    cluster_nodes = [
        NodeStatus(
            node_id=n.node_id,
            version=n.version,
            last_heartbeat_at=n.last_heartbeat_at,
            alive=bool(n.last_heartbeat_at and n.last_heartbeat_at > stale_threshold),
            load_metrics=n.load_metrics,
        )
        for n in nodes_result.scalars().all()
    ]

    return HealthDashboard(
        db_size_bytes=db_size,
        recording_storage_bytes=recording_bytes,
        active_sessions=active_sessions,
        pending_anomaly_events=pending_anomalies,
        certs_expiring_soon=certs_expiring,
        active_users=active_users,
        cluster_nodes=cluster_nodes,
        generated_at=now,
    )
