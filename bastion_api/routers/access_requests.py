"""Just-in-time access request router — users submit and withdraw access requests."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.audit import audit
from bastion.db import get_db
from bastion.logging import get_logger
from bastion.models import (
    AccessRequest,
    AccessRequestStatus,
    Server,
    ServerStatus,
    User,
)
from bastion_api.deps import get_current_user

log = get_logger(__name__)
router = APIRouter(prefix="/access-requests", tags=["Access Requests"])

_MAX_DURATION_HOURS = 72


class CreateAccessRequestBody(BaseModel):
    server_hostname: str
    reason: str = Field(..., min_length=10, max_length=1024)
    requested_duration_hours: int = Field(..., ge=1, le=_MAX_DURATION_HOURS)
    allow_sudo: bool = False


class AccessRequestResponse(BaseModel):
    id: str
    server_hostname: str
    reason: str
    allow_sudo: bool
    requested_duration_hours: int
    status: str
    expires_at: datetime | None
    review_note: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


@router.post("/", response_model=AccessRequestResponse, status_code=status.HTTP_201_CREATED)
async def create_access_request(
    body: CreateAccessRequestBody,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AccessRequestResponse:
    """Submit a just-in-time access request for a server.

    Only available to users with jit_access_enabled=True on their account.
    """
    if not current_user.jit_access_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Just-in-time access requests are not enabled for your account.",
        )

    server_result = await db.execute(
        select(Server).where(
            Server.hostname == body.server_hostname,
            Server.status != ServerStatus.DELETED,
            Server.deleted_at.is_(None),
        )
    )
    server = server_result.scalar_one_or_none()
    if server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found.")

    # Check for an existing pending request for the same user/server
    existing = await db.execute(
        select(AccessRequest).where(
            AccessRequest.user_id == current_user.id,
            AccessRequest.server_id == server.id,
            AccessRequest.status == AccessRequestStatus.PENDING,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You already have a pending access request for this server.",
        )

    req = AccessRequest(
        user_id=current_user.id,
        server_id=server.id,
        reason=body.reason,
        allow_sudo=body.allow_sudo,
        requested_duration_hours=body.requested_duration_hours,
        status=AccessRequestStatus.PENDING,
    )
    db.add(req)
    await db.flush()

    await audit(
        db,
        "access_request.create",
        success=True,
        user_id=current_user.id,
        resource_type="access_request",
        resource_id=req.id,
        detail={"server": body.server_hostname, "duration_hours": body.requested_duration_hours},
    )
    log.info(
        "JIT access request submitted",
        user_id=current_user.id,
        server=body.server_hostname,
        request_id=req.id,
    )
    return AccessRequestResponse(
        id=req.id,
        server_hostname=server.hostname,
        reason=req.reason,
        allow_sudo=req.allow_sudo,
        requested_duration_hours=req.requested_duration_hours,
        status=req.status,
        expires_at=req.expires_at,
        review_note=req.review_note,
        created_at=req.created_at,
    )


@router.get("/", response_model=list[AccessRequestResponse])
async def list_my_access_requests(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    req_status: AccessRequestStatus | None = None,
) -> list[AccessRequestResponse]:
    """List the authenticated user's access requests."""
    query = (
        select(AccessRequest, Server.hostname)
        .join(Server, AccessRequest.server_id == Server.id)
        .where(AccessRequest.user_id == current_user.id)
    )
    if req_status:
        query = query.where(AccessRequest.status == req_status)
    query = query.order_by(AccessRequest.created_at.desc()).limit(100)
    rows = (await db.execute(query)).all()
    return [
        AccessRequestResponse(
            id=r.id,
            server_hostname=hostname,
            reason=r.reason,
            allow_sudo=r.allow_sudo,
            requested_duration_hours=r.requested_duration_hours,
            status=r.status,
            expires_at=r.expires_at,
            review_note=r.review_note,
            created_at=r.created_at,
        )
        for r, hostname in rows
    ]


@router.delete("/{request_id}", status_code=status.HTTP_204_NO_CONTENT)
async def withdraw_access_request(
    request_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Withdraw a pending access request."""
    req_result = await db.execute(
        select(AccessRequest).where(
            AccessRequest.id == request_id,
            AccessRequest.user_id == current_user.id,
            AccessRequest.status == AccessRequestStatus.PENDING,
        )
    )
    req = req_result.scalar_one_or_none()
    if req is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pending access request not found.",
        )
    req.status = AccessRequestStatus.WITHDRAWN
    await db.flush()
    await audit(
        db,
        "access_request.withdraw",
        success=True,
        user_id=current_user.id,
        resource_type="access_request",
        resource_id=request_id,
    )
