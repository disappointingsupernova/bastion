"""Admin audit log router — query the immutable audit trail and verify integrity."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.audit import verify_audit_chain
from bastion.db import get_db
from bastion.models import AuditLog, User, UserRole
from bastion_api.deps import require_role

router = APIRouter(prefix="/audit", tags=["Audit"])

_auditor_or_above = require_role(UserRole.ADMIN, UserRole.AUDITOR)


class AuditLogEntry(BaseModel):
    id: str
    user_id: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    detail: str | None
    ip_address: str | None
    success: bool
    integrity_hash: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ChainVerifyResponse(BaseModel):
    valid: bool
    entries_checked: int
    first_broken_entry_id: str | None


@router.get("/", response_model=list[AuditLogEntry])
async def list_audit_logs(
    current_user: Annotated[User, Depends(_auditor_or_above)],
    db: Annotated[AsyncSession, Depends(get_db)],
    user_id: str | None = None,
    action: str | None = None,
    success: bool | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditLogEntry]:
    """Query the audit log with optional filters."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    query = select(AuditLog)
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if action:
        if len(action) > 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Action filter must not exceed 200 characters.",
            )
        query = query.where(AuditLog.action.ilike(f"%{action}%"))
    if success is not None:
        query = query.where(AuditLog.success == success)
    query = query.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    return [AuditLogEntry.model_validate(e) for e in result.scalars().all()]


@router.get("/verify-chain", response_model=ChainVerifyResponse)
async def verify_chain(
    current_user: Annotated[User, Depends(_auditor_or_above)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ChainVerifyResponse:
    """Verify the HMAC integrity chain of the entire audit log.

    A broken chain indicates that one or more entries have been tampered with.
    Returns the position of the first broken entry if tampering is detected.
    """
    valid, entries_checked, first_broken = await verify_audit_chain(db)
    return ChainVerifyResponse(
        valid=valid,
        entries_checked=entries_checked,
        first_broken_entry_id=first_broken,
    )
