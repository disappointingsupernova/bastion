"""Celery tasks for checking remote server connectivity and dispatching status alerts."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from workers.celery_app import app
from bastion.logging import get_logger

log = get_logger(__name__)


@app.task(name="workers.tasks.connectivity.check_all_servers", bind=True, max_retries=2)
def check_all_servers(self) -> None:
    """Check SSH connectivity for all active servers and update their status."""
    asyncio.run(_check_all_servers())


async def _check_all_servers() -> None:
    """Async implementation of the connectivity check."""
    from bastion.db import get_db_session
    from bastion.models import Server, ServerStatus
    from bastion.provisioning import check_connectivity
    from bastion.alerting import dispatch_alert
    from bastion.models import AlertSeverity
    from sqlalchemy import select

    async with get_db_session() as db:
        result = await db.execute(
            select(Server).where(
                Server.status != ServerStatus.DELETED,
                Server.deleted_at.is_(None),
            )
        )
        servers = result.scalars().all()

    for server in servers:
        reachable = await check_connectivity(server.hostname, server.ssh_port)
        async with get_db_session() as db:
            result = await db.execute(
                select(Server).where(Server.id == server.id)
            )
            s = result.scalar_one_or_none()
            if s is None:
                continue

            previous_status = s.status
            s.last_check_at = datetime.now(tz=timezone.utc)

            if reachable:
                s.last_seen_at = datetime.now(tz=timezone.utc)
                if previous_status == ServerStatus.UNREACHABLE:
                    s.status = ServerStatus.ACTIVE
                    log.info("Server is reachable again", hostname=server.hostname)
                    async with get_db_session() as alert_db:
                        await dispatch_alert(
                            alert_db,
                            subject=f"Server {server.hostname} is reachable again",
                            body=f"The server {server.hostname} has recovered and is now reachable.",
                            severity=AlertSeverity.INFO,
                        )
            else:
                if previous_status == ServerStatus.ACTIVE:
                    s.status = ServerStatus.UNREACHABLE
                    log.warning("Server is unreachable", hostname=server.hostname)
                    async with get_db_session() as alert_db:
                        await dispatch_alert(
                            alert_db,
                            subject=f"Server {server.hostname} is unreachable",
                            body=f"The server {server.hostname} failed its connectivity check on port {server.ssh_port}.",
                            severity=AlertSeverity.CRITICAL,
                        )
