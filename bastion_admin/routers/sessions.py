"""Admin sessions router — list, terminate, live-tail, and play back session recordings."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.audit import audit
from bastion.db import get_db
from bastion.logging import get_logger
from bastion.models import RecordingDecryptLog, Server, Session, SessionStatus, User, UserRole
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
    """Forcibly terminate an active session in real-time via Redis kill signal."""
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

    await publish_kill_signal(session_id)

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


@router.get("/{session_id}/tail")
async def tail_live_session(
    session_id: str,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> StreamingResponse:
    """Stream live output of an active session as Server-Sent Events.

    Each event contains a chunk of terminal output as it is written.
    The stream ends when the session terminates.
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

    await audit(
        db,
        "admin.session.tail",
        success=True,
        user_id=current_user.id,
        resource_type="session",
        resource_id=session_id,
    )

    from bastion.recordings import subscribe_live_output

    async def _event_stream() -> AsyncGenerator[str, None]:
        """Yield SSE-formatted output chunks."""
        async for chunk in subscribe_live_output(session_id):
            # Escape newlines within the data field per SSE spec
            escaped = chunk.replace("\n", "\ndata: ")
            yield f"data: {escaped}\n\n"
        yield "data: [SESSION_ENDED]\n\n"

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


class PlaybackRequest(BaseModel):
    """Request body for recording playback — does not contain the age identity.

    The age identity (private key) is passed via the X-Age-Identity request header
    to avoid it being captured by request-body logging middleware.
    """


@router.post("/{session_id}/playback")
async def playback_recording(
    session_id: str,
    request: Request,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> StreamingResponse:
    """Stream a decrypted session recording back to an authorised admin.

    The admin provides their age identity (private key) in the X-Age-Identity
    request header. It is used immediately for decryption and never stored.
    Passing it as a header rather than a request body prevents it being captured
    by any request-body logging middleware.
    Each decryption event is logged with the admin's key fingerprint.
    """
    from pathlib import Path

    from bastion.recordings import decrypt_recording

    age_identity = request.headers.get("X-Age-Identity", "")
    if not age_identity:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Age-Identity header is required — provide your age identity key.",
        )

    result = await db.execute(select(Session).where(Session.id == session_id))
    session = result.scalar_one_or_none()
    if session is None or not session.recording_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session recording not found.",
        )

    recording_path = Path(session.recording_path)
    if not recording_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recording file not found on disk.",
        )

    try:
        plaintext = decrypt_recording(recording_path, age_identity)
    except RuntimeError as exc:
        await audit(
            db,
            "admin.session.playback",
            success=False,
            user_id=current_user.id,
            resource_type="session",
            resource_id=session_id,
            detail={"reason": "Decryption failed"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Recording decryption failed — check your age identity key.",
        ) from exc

    # Log the decryption event with a fingerprint of the identity used
    import hashlib

    key_fingerprint = hashlib.sha256(age_identity.encode()).hexdigest()[:16]
    decrypt_log = RecordingDecryptLog(
        session_id=session_id,
        admin_user_id=current_user.id,
        key_fingerprint=key_fingerprint,
    )
    db.add(decrypt_log)
    await audit(
        db,
        "admin.session.playback",
        success=True,
        user_id=current_user.id,
        resource_type="session",
        resource_id=session_id,
        detail={"key_fingerprint": key_fingerprint},
    )
    log.info(
        "Session recording decrypted and streamed",
        session_id=session_id,
        admin=current_user.username,
        key_fingerprint=key_fingerprint,
    )

    return StreamingResponse(
        iter([plaintext]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{session_id}.cast"'},
    )


@router.get("/{session_id}/playback/derived")
async def playback_recording_derived_key(
    session_id: str,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> StreamingResponse:
    """Stream a decrypted recording using a key derived from the master recordings key.

    Each admin has a unique derived key (HMAC-SHA256 of master_key + admin_user_id).
    The master key is set via RECORDINGS_MASTER_KEY in the environment.
    Decryption events are logged with the admin's key fingerprint.

    Note: this endpoint only works if recordings were encrypted with the admin's
    derived public key. Use /playback for recordings encrypted with a custom age key.
    """
    from pathlib import Path

    from bastion.config import get_settings
    from bastion.recordings import (
        admin_key_fingerprint,
        decrypt_recording,
        derive_admin_decrypt_key,
    )

    settings = get_settings()
    if not settings.recordings_master_key:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="RECORDINGS_MASTER_KEY is not configured.",
        )

    result = await db.execute(select(Session).where(Session.id == session_id))
    session = result.scalar_one_or_none()
    if session is None or not session.recording_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session recording not found.",
        )

    recording_path = Path(session.recording_path)
    if not recording_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recording file not found on disk.",
        )

    derived_key = derive_admin_decrypt_key(settings.recordings_master_key, current_user.id)
    fingerprint = admin_key_fingerprint(current_user.id, settings.recordings_master_key)

    # Convert raw bytes to an age identity format (X25519 secret key)
    import base64

    age_identity = f"AGE-SECRET-KEY-1{base64.b32encode(derived_key).decode().upper().rstrip('=')}"

    try:
        plaintext = decrypt_recording(recording_path, age_identity)
    except RuntimeError as exc:
        await audit(
            db,
            "admin.session.playback.derived",
            success=False,
            user_id=current_user.id,
            resource_type="session",
            resource_id=session_id,
            detail={"key_fingerprint": fingerprint, "reason": "Decryption failed"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Recording decryption failed with derived key.",
        ) from exc

    decrypt_log = RecordingDecryptLog(
        session_id=session_id,
        admin_user_id=current_user.id,
        key_fingerprint=fingerprint,
    )
    db.add(decrypt_log)
    await audit(
        db,
        "admin.session.playback.derived",
        success=True,
        user_id=current_user.id,
        resource_type="session",
        resource_id=session_id,
        detail={"key_fingerprint": fingerprint},
    )
    log.info(
        "Session recording decrypted via derived key",
        session_id=session_id,
        admin=current_user.username,
        key_fingerprint=fingerprint,
    )

    return StreamingResponse(
        iter([plaintext]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{session_id}.cast"'},
    )
