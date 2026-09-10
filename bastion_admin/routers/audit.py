"""Admin audit log router — query the immutable audit trail."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.db import get_db
from bastion.models import AuditLog, User, UserRole
from bastion_api.deps import require_role

router = APIRouter(prefix="/audit", tags=["Audit"])

_auditor_or_above = require_role(UserRole.ADMIN, UserRole.AUDITOR)


class AuditLogEntry(BaseModel):
    id: str
    user_id: Optional[str]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    detail: Optional[str]
    ip_address: Optional[str]
    success: bool
    created_at: datetime

    model_config = {"from_attributes": True}


@router.get("/", response_model=list[AuditLogEntry])
async def list_audit_logs(
    current_user: Annotated[User, Depends(_auditor_or_above)],
    db: Annotated[AsyncSession, Depends(get_db)],
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    success: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditLogEntry]:
    """Query the audit log with optional filters."""
    query = select(AuditLog)
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if action:
        query = query.where(AuditLog.action.ilike(f"%{action}%"))
    if success is not None:
        query = query.where(AuditLog.success == success)
    query = query.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    return [AuditLogEntry.model_validate(e) for e in result.scalars().all()]
