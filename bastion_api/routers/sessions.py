"""Sessions router — initiate SSH connections and retrieve session history."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.audit import audit
from bastion.config import get_settings
from bastion.db import get_db
from bastion.logging import get_logger
from bastion.models import (
    Server,
    ServerAccess,
    ServerStatus,
    Session,
    SessionStatus,
    User,
)
from bastion_api.deps import get_current_user

log = get_logger(__name__)
router = APIRouter(prefix="/sessions", tags=["Sessions"])


class ConnectRequest(BaseModel):
    hostname: str
    public_key: str  # User's public key to issue a cert against


class SessionSummary(BaseModel):
    id: str
    server_hostname: str
    status: str
    started_at: datetime
    ended_at: Optional[datetime]
    bytes_sent: int
    bytes_received: int
    recording_available: bool

    model_config = {"from_attributes": True}


@router.post("/connect")
async def connect(
    body: ConnectRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Initiate an SSH session to the specified server.

    Validates access permissions, issues a certificate, and returns connection
    details for the CLI to establish the proxied SSH session.
    """
    settings = get_settings()

    # Resolve server
    result = await db.execute(
        select(Server).where(
            Server.hostname == body.hostname,
            Server.status != ServerStatus.DELETED,
            Server.deleted_at.is_(None),
        )
    )
    server = result.scalar_one_or_none()
    if server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found.")

    if server.status == ServerStatus.UNREACHABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server is currently unreachable.",
        )

    # Check access
    result = await db.execute(
        select(ServerAccess).where(
            ServerAccess.user_id == current_user.id,
            ServerAccess.server_id == server.id,
            ServerAccess.revoked_at.is_(None),
        )
    )
    access = result.scalar_one_or_none()
    if access is None:
        await audit(
            db, "session.connect.denied", success=False,
            user_id=current_user.id,
            resource_type="server",
            resource_id=server.id,
            detail={"hostname": body.hostname, "reason": "No access grant"},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access to this server is not permitted.")

    # Issue certificate
    from bastion.crypto.ca import issue_certificate
    principals = [access.remote_username or current_user.username]
    cert_bytes, cert_record = await issue_certificate(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        public_key_bytes=body.public_key.encode(),
        principals=principals,
    )

    # Create session record
    recording_path = None
    if settings.recordings_enabled:
        recordings_dir = settings.recordings_path
        recordings_dir.mkdir(parents=True, exist_ok=True)
        recording_path = str(
            recordings_dir / f"{current_user.username}-{server.hostname}-{uuid4().hex[:8]}.cast"
        )

    session = Session(
        user_id=current_user.id,
        server_id=server.id,
        certificate_id=cert_record.id,
        status=SessionStatus.ACTIVE,
        started_at=datetime.now(tz=timezone.utc),
        remote_username=access.remote_username or current_user.username,
        recording_path=recording_path,
    )
    db.add(session)
    await db.flush()

    await audit(
        db, "session.connect", success=True,
        user_id=current_user.id,
        resource_type="session",
        resource_id=session.id,
        detail={"hostname": body.hostname, "remote_user": session.remote_username},
    )

    log.info(
        "SSH session initiated",
        user_id=current_user.id,
        hostname=body.hostname,
        session_id=session.id,
    )

    return {
        "session_id": session.id,
        "certificate": cert_bytes.decode(),
        "hostname": server.hostname,
        "port": server.ssh_port,
        "remote_username": session.remote_username,
        "proxy_jump": server.proxy_jump_server_id is not None,
    }


@router.get("/", response_model=list[SessionSummary])
async def list_sessions(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 50,
    offset: int = 0,
) -> list[SessionSummary]:
    """List the authenticated user's SSH sessions, most recent first."""
    result = await db.execute(
        select(Session, Server.hostname)
        .join(Server, Session.server_id == Server.id)
        .where(Session.user_id == current_user.id)
        .order_by(Session.started_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = result.all()
    return [
        SessionSummary(
            id=s.id,
            server_hostname=hostname,
            status=s.status.value,
            started_at=s.started_at,
            ended_at=s.ended_at,
            bytes_sent=s.bytes_sent,
            bytes_received=s.bytes_received,
            recording_available=bool(s.recording_path),
        )
        for s, hostname in rows
    ]


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def terminate_session(
    session_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Terminate an active SSH session."""
    result = await db.execute(
        select(Session).where(
            Session.id == session_id,
            Session.user_id == current_user.id,
            Session.status == SessionStatus.ACTIVE,
        )
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active session not found.")

    session.status = SessionStatus.TERMINATED
    session.ended_at = datetime.now(tz=timezone.utc)
    session.termination_reason = "Terminated by user"

    await audit(
        db, "session.terminate", success=True,
        user_id=current_user.id,
        resource_type="session",
        resource_id=session_id,
    )
    log.info("Session terminated by user", session_id=session_id, user_id=current_user.id)
