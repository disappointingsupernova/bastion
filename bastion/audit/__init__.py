"""Audit logging — every action in the system is recorded here before and after execution."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from bastion.logging import get_logger
from bastion.models import AuditLog

log = get_logger(__name__)

# Maximum length of the serialised detail JSON stored in the database
_MAX_DETAIL_BYTES = 4096
# Maximum length of any individual string value within the detail dict
_MAX_VALUE_LEN = 512


def _sanitise_detail(detail: dict[str, Any]) -> dict[str, Any]:
    """Sanitise an audit detail dict before storage.

    - Truncates individual string values to _MAX_VALUE_LEN characters
    - Removes keys whose values are not JSON-serialisable primitives
    - Truncates the entire serialised payload to _MAX_DETAIL_BYTES

    This prevents oversized or misleading data from being embedded in the
    audit log (fix #18).
    """
    safe: dict[str, Any] = {}
    for k, v in detail.items():
        if isinstance(v, str):
            safe[k] = v[:_MAX_VALUE_LEN] if len(v) > _MAX_VALUE_LEN else v
        elif isinstance(v, (int, float, bool)) or v is None:
            safe[k] = v
        elif isinstance(v, (list, dict)):
            # Serialise nested structures but cap their string representation
            try:
                serialised = json.dumps(v)
                safe[k] = json.loads(serialised[:_MAX_VALUE_LEN])
            except (TypeError, ValueError):
                safe[k] = "<non-serialisable>"
        else:
            safe[k] = "<non-serialisable>"

    # Final cap on the entire payload
    payload = json.dumps(safe)
    if len(payload) > _MAX_DETAIL_BYTES:
        safe = {"_truncated": True, "_original_keys": list(safe.keys())}

    return safe


async def audit(
    db: AsyncSession,
    action: str,
    success: bool,
    user_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    detail: dict[str, Any] | None = None,
    ip_address: str | None = None,
    node_id: str | None = None,
) -> AuditLog:
    """Write an audit log entry to the database.

    This must be called for every action — both on initiation and on completion.
    The detail dict is sanitised before storage to prevent oversized or
    misleading data from being embedded (fix #18).
    """
    sanitised = _sanitise_detail(detail) if detail else None

    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=json.dumps(sanitised) if sanitised else None,
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
