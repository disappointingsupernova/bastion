"""Celery task to auto-revoke expired just-in-time access grants."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from bastion.logging import get_logger
from workers.celery_app import app

log = get_logger(__name__)


@app.task(name="workers.tasks.access_requests.expire_jit_access", bind=True)
def expire_jit_access(self) -> None:
    """Revoke ServerAccess records created by approved JIT requests that have expired."""
    asyncio.run(_expire_jit_access())


async def _expire_jit_access() -> None:
    """Async implementation of JIT access expiry — covers both JIT requests and direct grants."""
    from sqlalchemy import select

    from bastion.db import get_db_session
    from bastion.models import AccessRequest, AccessRequestStatus, ServerAccess

    now = datetime.now(tz=UTC)

    async with get_db_session() as db:
        # Expire JIT access requests
        result = await db.execute(
            select(AccessRequest).where(
                AccessRequest.status == AccessRequestStatus.APPROVED,
                AccessRequest.expires_at <= now,
                AccessRequest.server_access_id.is_not(None),
            )
        )
        expired = result.scalars().all()

        for req in expired:
            if req.server_access_id:
                access_result = await db.execute(
                    select(ServerAccess).where(
                        ServerAccess.id == req.server_access_id,
                        ServerAccess.revoked_at.is_(None),
                    )
                )
                access = access_result.scalar_one_or_none()
                if access:
                    access.revoked_at = now
                    log.info(
                        "JIT access grant expired and revoked",
                        request_id=req.id,
                        user_id=req.user_id,
                        server_id=req.server_id,
                    )
            req.status = AccessRequestStatus.EXPIRED

        # Also expire any direct ServerAccess grants with an expires_at
        direct_result = await db.execute(
            select(ServerAccess).where(
                ServerAccess.expires_at <= now,
                ServerAccess.revoked_at.is_(None),
            )
        )
        for access in direct_result.scalars().all():
            access.revoked_at = now
            log.info(
                "Time-limited server access grant expired",
                access_id=access.id,
                user_id=access.user_id,
                server_id=access.server_id,
            )

    if expired:
        log.info("Expired JIT access grants revoked", count=len(expired))
