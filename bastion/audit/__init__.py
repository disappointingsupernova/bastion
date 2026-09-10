"""Audit logging — every action in the system is recorded here before and after execution."""

from __future__ import annotations

import json
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from bastion.logging import get_logger
from bastion.models import AuditLog

log = get_logger(__name__)


async def audit(
    db: AsyncSession,
    action: str,
    success: bool,
    user_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    detail: Optional[dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    node_id: Optional[str] = None,
) -> AuditLog:
    """Write an audit log entry to the database.

    This must be called for every action — both on initiation and on completion.
    """
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=json.dumps(detail) if detail else None,
        ip_address=ip_address,
        success=success,
        node_id=node_id,
    )
    db.add(entry)
    await db.flush()

    log.info(
        "Audit event recorded",
        action=action,
        user_id=user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        success=success,
        ip=ip_address,
    )
    return entry
