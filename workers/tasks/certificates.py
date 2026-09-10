"""Celery tasks for expiring stale SSH certificates."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from workers.celery_app import app
from bastion.logging import get_logger

log = get_logger(__name__)


@app.task(name="workers.tasks.certificates.expire_old_certificates", bind=True)
def expire_old_certificates(self) -> None:
    """Mark all certificates whose validity period has passed as expired."""
    asyncio.run(_expire_old_certificates())


async def _expire_old_certificates() -> None:
    """Async implementation of certificate expiry."""
    from bastion.db import get_db_session
    from bastion.models import SshCertificate, CertStatus
    from sqlalchemy import select

    now = datetime.now(tz=timezone.utc)
    async with get_db_session() as db:
        result = await db.execute(
            select(SshCertificate).where(
                SshCertificate.status == CertStatus.ACTIVE,
                SshCertificate.valid_before < now,
            )
        )
        expired = result.scalars().all()
        for cert in expired:
            cert.status = CertStatus.EXPIRED
            log.debug("Certificate marked as expired", cert_id=cert.id, serial=cert.serial)

    if expired:
        log.info("Expired certificates marked", count=len(expired))
