"""Admin sessions router — list all sessions and forcibly terminate active ones."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.audit import audit
from bastion.db import get_db
from bastion.logging import get_logger
from bastion.models import Server, Session, SessionStatus, User, UserRole
from bastion.session_kill import publish_kill_signal
from bastion_api.deps import require_role

log = get_logger(__name__)
router = APIRouter(prefix="/sessions", tags=["Sessions (Admin)"])

_admin = require_role(UserRole.ADMIN)
_admin_or_auditor = require_role(UserRole.ADMIN, UserRole.AUDITOR, UserRole.READ_ONLY)


class AdminSessionSummary(BaseModel):
    id: str
    user_id: str
    server_hostname: str
    status: str
    started_at: datetime
    ended_at: datetime | None
    remote_username: str | None
    bytes_sent: int
    bytes_received: int
    recording_available: bool

    model_config = {"from_attributes": True}


@router.get("/", response_model=list[AdminSessionSummary])
async def list_all_sessions(
    current_user: Annotated[User, Depends(_admin_or_auditor)],
    db: Annotated[AsyncSession, Depends(get_db)],
    active_only: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> list[AdminSessionSummary]:
    """List all SSH sessions across all users."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    query = (
        select(Session, Server.hostname)
        .join(Server, Session.server_id == Server.id)
        .order_by(Session.started_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if active_only:
        query = query.where(Session.status == SessionStatus.ACTIVE)

    rows = (await db.execute(query)).all()
    return [
        AdminSessionSummary(
            id=s.id,
            user_id=s.user_id,
            server_hostname=hostname,
            status=str(s.status),
            started_at=s.started_at,
            ended_at=s.ended_at,
            remote_username=s.remote_username,
            bytes_sent=s.bytes_sent,
            bytes_received=s.bytes_received,
            recording_available=bool(s.recording_path),
        )
        for s, hostname in rows
    ]


@router.post("/{session_id}/terminate", status_code=status.HTTP_204_NO_CONTENT)
async def admin_terminate_session(
    session_id: str,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Forcibly terminate an active session in real-time.

    Publishes a kill signal to Redis which the proxy process receives and
    uses to close the SSH connection immediately. Also marks the session
    as TERMINATED in the database.
    """
    result = await db.execute(
        select(Session).where(
            Session.id == session_id,
            Session.status == SessionStatus.ACTIVE,
        )
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active session not found.",
        )

    # Publish the real-time kill signal to the proxy process
    await publish_kill_signal(session_id)

    # Mark terminated in the database
    session.status = SessionStatus.TERMINATED
    session.ended_at = datetime.now(tz=UTC)
    session.termination_reason = f"Forcibly terminated by admin {current_user.username}"
    await db.flush()

    await audit(
        db,
        "admin.session.terminate",
        success=True,
        user_id=current_user.id,
        resource_type="session",
        resource_id=session_id,
        detail={"terminated_by": current_user.username},
    )
    log.info(
        "Session forcibly terminated by admin",
        session_id=session_id,
        admin=current_user.username,
    )
