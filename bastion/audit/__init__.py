"""Audit logging — every action in the system is recorded here before and after execution.

Each entry is signed with an HMAC-SHA256 that chains to the previous entry's hash,
forming a tamper-evident append-only log. Any modification to a past entry will
break the chain from that point forward, making tampering detectable.
"""

from __future__ import annotations

import hmac
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.logging import get_logger
from bastion.models import AuditLog

log = get_logger(__name__)

_MAX_DETAIL_BYTES = 4096
_MAX_VALUE_LEN = 512


def _sanitise_detail(detail: dict[str, Any]) -> dict[str, Any]:
    """Sanitise an audit detail dict before storage."""
    safe: dict[str, Any] = {}
    for k, v in detail.items():
        if isinstance(v, str):
            safe[k] = v[:_MAX_VALUE_LEN] if len(v) > _MAX_VALUE_LEN else v
        elif isinstance(v, (int, float, bool)) or v is None:
            safe[k] = v
        elif isinstance(v, (list, dict)):
            try:
                serialised = json.dumps(v)
                safe[k] = json.loads(serialised[:_MAX_VALUE_LEN])
            except (TypeError, ValueError):
                safe[k] = "<non-serialisable>"
        else:
            safe[k] = "<non-serialisable>"

    payload = json.dumps(safe)
    if len(payload) > _MAX_DETAIL_BYTES:
        safe = {"_truncated": True, "_original_keys": list(safe.keys())}

    return safe


def _compute_integrity_hash(entry: AuditLog, secret_key: str, previous_hash: str | None) -> str:
    """Compute an HMAC-SHA256 integrity hash for an audit log entry.

    The hash covers all immutable fields plus the previous entry's hash,
    forming a chain. Keyed with the application SECRET_KEY so the chain
    cannot be forged without access to the key.
    """
    chain_input = "|".join(
        [
            entry.id,
            entry.action,
            str(entry.user_id or ""),
            str(entry.resource_type or ""),
            str(entry.resource_id or ""),
            str(entry.detail or ""),
            str(entry.ip_address or ""),
            str(entry.success),
            str(entry.node_id or ""),
            previous_hash or "GENESIS",
        ]
    )
    return hmac.new(
        secret_key.encode(),
        chain_input.encode(),
        digestmod="sha256",
    ).hexdigest()


async def _get_previous_hash(db: AsyncSession) -> str | None:
    """Return the integrity_hash of the most recently inserted audit log entry.

    Uses SELECT FOR UPDATE to serialise concurrent writers in HA deployments,
    preventing two writers from reading the same previous hash simultaneously
    and breaking the chain ordering guarantee.
    Orders by seq (monotonic autoincrement) for reliable insertion-order
    chaining even when multiple entries share the same created_at timestamp.
    """
    result = await db.execute(
        select(AuditLog.integrity_hash)
        .where(AuditLog.integrity_hash.is_not(None))
        .order_by(AuditLog.seq.desc())
        .limit(1)
        .with_for_update()
    )
    return result.scalar_one_or_none()


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
    """Write an audit log entry with an HMAC integrity hash chained to the previous entry.

    Must be called for every action — both on initiation and on completion.
    """
    from bastion.config import get_settings

    settings = get_settings()
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

    # Compute and store the integrity hash after flush (so entry.id is assigned)
    previous_hash = await _get_previous_hash(db)
    entry.integrity_hash = _compute_integrity_hash(entry, settings.secret_key, previous_hash)
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


async def verify_audit_chain(db: AsyncSession) -> tuple[bool, int, str | None]:
    """Verify the integrity of the entire audit log chain.

    Returns (is_valid, entries_checked, first_broken_entry_id).
    A broken chain indicates tampering from that entry onwards.
    """
    from bastion.config import get_settings

    settings = get_settings()

    result = await db.execute(select(AuditLog).order_by(AuditLog.seq.asc()))
    entries = result.scalars().all()

    previous_hash: str | None = None
    for i, entry in enumerate(entries):
        expected = _compute_integrity_hash(entry, settings.secret_key, previous_hash)
        if entry.integrity_hash != expected:
            log.error(
                "Audit log integrity chain broken",
                entry_id=entry.id,
                position=i,
                expected=expected,
                stored=entry.integrity_hash,
            )
            return False, i, entry.id
        previous_hash = entry.integrity_hash

    log.info("Audit log integrity chain verified", entries_checked=len(entries))
    return True, len(entries), None
