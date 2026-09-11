"""Dual-approval service for privileged operations.

When dual_approval_required=True, actions such as granting sudo, revoking a
certificate, or deleting a user are held in a DualApprovalRequest until a
second admin approves within the configured window.

When only one admin exists, the initiating admin must supply a valid TOTP code
(and for super-privileged actions, an email code too) before the action proceeds.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.config import get_settings
from bastion.logging import get_logger
from bastion.models import DualApprovalRequest, DualApprovalStatus, User, UserRole, UserStatus

log = get_logger(__name__)


async def _count_active_admins(db: AsyncSession) -> int:
    """Return the number of active admin users."""
    result = await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.ADMIN,
            User.status == UserStatus.ACTIVE,
            User.deleted_at.is_(None),
        )
    )
    return result.scalar_one()


async def create_dual_approval_request(
    db: AsyncSession,
    initiated_by: User,
    action_type: str,
    action_description: str,
    action_payload: dict[str, Any],
) -> DualApprovalRequest:
    """Create a pending dual-approval request for a privileged action.

    Returns the created request. The caller must NOT execute the action yet —
    it will be executed when the request is approved.
    """
    settings = get_settings()
    expires_at = datetime.now(tz=UTC) + timedelta(minutes=settings.dual_approval_window_minutes)
    req = DualApprovalRequest(
        initiated_by_user_id=initiated_by.id,
        action_type=action_type,
        action_description=action_description,
        action_payload=json.dumps(action_payload),
        status=DualApprovalStatus.PENDING,
        expires_at=expires_at,
    )
    db.add(req)
    await db.flush()
    log.info(
        "Dual-approval request created",
        request_id=req.id,
        action_type=action_type,
        initiated_by=initiated_by.username,
    )
    return req


async def is_dual_approval_required(db: AsyncSession) -> bool:
    """Return True if dual approval is enabled and there are enough admins."""
    settings = get_settings()
    if not settings.dual_approval_required:
        return False
    # With only one admin, fall back to MFA re-verification instead
    admin_count = await _count_active_admins(db)
    return admin_count >= 2


async def approve_dual_approval_request(
    db: AsyncSession,
    request_id: str,
    approving_admin: User,
    note: str | None = None,
) -> DualApprovalRequest:
    """Approve a pending dual-approval request.

    The approving admin must be different from the initiator.
    Returns the updated request with status=APPROVED.
    """
    result = await db.execute(
        select(DualApprovalRequest).where(
            DualApprovalRequest.id == request_id,
            DualApprovalRequest.status == DualApprovalStatus.PENDING,
        )
    )
    req = result.scalar_one_or_none()
    if req is None:
        raise ValueError(f"Pending dual-approval request {request_id!r} not found.")

    if req.initiated_by_user_id == approving_admin.id:
        raise PermissionError("The initiating admin cannot approve their own request.")

    now = datetime.now(tz=UTC)
    if req.expires_at < now:
        req.status = DualApprovalStatus.EXPIRED
        await db.flush()
        raise ValueError("This approval request has expired.")

    req.status = DualApprovalStatus.APPROVED
    req.reviewed_by_user_id = approving_admin.id
    req.reviewed_at = now
    req.review_note = note
    await db.flush()

    log.info(
        "Dual-approval request approved",
        request_id=request_id,
        approved_by=approving_admin.username,
        action_type=req.action_type,
    )
    return req


async def reject_dual_approval_request(
    db: AsyncSession,
    request_id: str,
    rejecting_admin: User,
    note: str | None = None,
) -> DualApprovalRequest:
    """Reject a pending dual-approval request."""
    result = await db.execute(
        select(DualApprovalRequest).where(
            DualApprovalRequest.id == request_id,
            DualApprovalRequest.status == DualApprovalStatus.PENDING,
        )
    )
    req = result.scalar_one_or_none()
    if req is None:
        raise ValueError(f"Pending dual-approval request {request_id!r} not found.")

    req.status = DualApprovalStatus.REJECTED
    req.reviewed_by_user_id = rejecting_admin.id
    req.reviewed_at = datetime.now(tz=UTC)
    req.review_note = note
    await db.flush()

    log.info(
        "Dual-approval request rejected",
        request_id=request_id,
        rejected_by=rejecting_admin.username,
    )
    return req
