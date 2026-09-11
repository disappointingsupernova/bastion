"""Admin dual-approval router — list, approve, and reject pending privileged action requests."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.audit import audit
from bastion.db import get_db
from bastion.dual_approval import approve_dual_approval_request, reject_dual_approval_request
from bastion.logging import get_logger
from bastion.models import DualApprovalRequest, DualApprovalStatus, User, UserRole
from bastion_api.deps import require_role

log = get_logger(__name__)
router = APIRouter(prefix="/dual-approvals", tags=["Dual Approval"])

_admin = require_role(UserRole.ADMIN)


class DualApprovalResponse(BaseModel):
    id: str
    initiated_by_user_id: str
    action_type: str
    action_description: str
    status: str
    expires_at: datetime
    reviewed_by_user_id: str | None
    reviewed_at: datetime | None
    review_note: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ReviewBody(BaseModel):
    approved: bool
    note: str | None = Field(None, max_length=512)


@router.get("/", response_model=list[DualApprovalResponse])
async def list_dual_approvals(
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    req_status: DualApprovalStatus | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[DualApprovalResponse]:
    """List dual-approval requests, optionally filtered by status."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    query = (
        select(DualApprovalRequest)
        .order_by(DualApprovalRequest.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if req_status:
        query = query.where(DualApprovalRequest.status == req_status)
    result = await db.execute(query)
    return [DualApprovalResponse.model_validate(r) for r in result.scalars().all()]


@router.post("/{request_id}/review", status_code=status.HTTP_204_NO_CONTENT)
async def review_dual_approval(
    request_id: str,
    body: ReviewBody,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Approve or reject a pending dual-approval request.

    The reviewing admin must be different from the initiator.
    On approval the action payload is stored — the initiating admin's next
    API call will detect the approved request and execute the action.
    """
    try:
        if body.approved:
            req = await approve_dual_approval_request(db, request_id, current_user, body.note)
            action = "dual_approval.approve"
        else:
            req = await reject_dual_approval_request(db, request_id, current_user, body.note)
            action = "dual_approval.reject"
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    await audit(
        db,
        action,
        success=True,
        user_id=current_user.id,
        resource_type="dual_approval_request",
        resource_id=request_id,
        detail={"approved": body.approved, "action_type": req.action_type},
    )
