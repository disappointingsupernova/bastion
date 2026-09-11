"""Admin access request router — approve, deny, and list JIT access requests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
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
    ServerAccess,
    User,
    UserRole,
)
from bastion_api.deps import require_role

log = get_logger(__name__)
router = APIRouter(prefix="/access-requests", tags=["Access Requests"])

_admin = require_role(UserRole.ADMIN)
_admin_or_auditor = require_role(UserRole.ADMIN, UserRole.AUDITOR)


class ReviewBody(BaseModel):
    approved: bool
    note: str | None = Field(None, max_length=512)


class AccessRequestAdminResponse(BaseModel):
    id: str
    user_id: str
    username: str
    server_hostname: str
    reason: str
    allow_sudo: bool
    requested_duration_hours: int
    status: str
    expires_at: datetime | None
    reviewed_by: str | None
    reviewed_at: datetime | None
    review_note: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


@router.get("/", response_model=list[AccessRequestAdminResponse])
async def list_access_requests(
    current_user: Annotated[User, Depends(_admin_or_auditor)],
    db: Annotated[AsyncSession, Depends(get_db)],
    req_status: AccessRequestStatus | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AccessRequestAdminResponse]:
    """List all JIT access requests, optionally filtered by status."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    query = (
        select(AccessRequest, User.username, Server.hostname)
        .join(User, AccessRequest.user_id == User.id)
        .join(Server, AccessRequest.server_id == Server.id)
        .order_by(AccessRequest.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if req_status:
        query = query.where(AccessRequest.status == req_status)

    rows = (await db.execute(query)).all()
    results = []
    for req, username, hostname in rows:
        reviewer_name: str | None = None
        if req.reviewed_by_user_id:
            rv = await db.execute(select(User.username).where(User.id == req.reviewed_by_user_id))
            reviewer_name = rv.scalar_one_or_none()
        results.append(
            AccessRequestAdminResponse(
                id=req.id,
                user_id=req.user_id,
                username=username,
                server_hostname=hostname,
                reason=req.reason,
                allow_sudo=req.allow_sudo,
                requested_duration_hours=req.requested_duration_hours,
                status=req.status,
                expires_at=req.expires_at,
                reviewed_by=reviewer_name,
                reviewed_at=req.reviewed_at,
                review_note=req.review_note,
                created_at=req.created_at,
            )
        )
    return results


@router.post("/{request_id}/review", status_code=status.HTTP_204_NO_CONTENT)
async def review_access_request(
    request_id: str,
    body: ReviewBody,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Approve or deny a pending JIT access request.

    On approval, a time-limited ServerAccess record is created and expires_at
    is set. A Celery task will auto-revoke the access at expiry.
    """
    req_result = await db.execute(
        select(AccessRequest).where(
            AccessRequest.id == request_id,
            AccessRequest.status == AccessRequestStatus.PENDING,
        )
    )
    req = req_result.scalar_one_or_none()
    if req is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pending access request not found.",
        )

    now = datetime.now(tz=UTC)
    req.reviewed_by_user_id = current_user.id
    req.reviewed_at = now
    req.review_note = body.note

    if body.approved:
        expires_at = now + timedelta(hours=req.requested_duration_hours)
        req.expires_at = expires_at
        req.status = AccessRequestStatus.APPROVED

        # Create a time-limited ServerAccess record
        access = ServerAccess(
            user_id=req.user_id,
            server_id=req.server_id,
            allow_sudo=req.allow_sudo,
            provisioned=False,
        )
        db.add(access)
        await db.flush()
        req.server_access_id = access.id

        log.info(
            "JIT access request approved",
            request_id=request_id,
            approved_by=current_user.username,
            expires_at=expires_at.isoformat(),
        )
        action = "access_request.approve"
    else:
        req.status = AccessRequestStatus.DENIED
        log.info(
            "JIT access request denied",
            request_id=request_id,
            denied_by=current_user.username,
        )
        action = "access_request.deny"

    await db.flush()
    await audit(
        db,
        action,
        success=True,
        user_id=current_user.id,
        resource_type="access_request",
        resource_id=request_id,
        detail={"approved": body.approved, "note": body.note},
    )
