"""Celery tasks for checking and applying package updates on remote servers."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from workers.celery_app import app
from bastion.logging import get_logger

log = get_logger(__name__)


@app.task(name="workers.tasks.packages.check_all_servers", bind=True, max_retries=2)
def check_all_servers(self) -> None:
    """Check for available package updates on all active servers."""
    asyncio.run(_check_all_servers())


async def _check_all_servers() -> None:
    """Async implementation of the package update check."""
    from bastion.db import get_db_session
    from bastion.models import Server, ServerStatus, ServerPackage
    from bastion.provisioning import get_available_updates
    from sqlalchemy import select
    import asyncssh

    async with get_db_session() as db:
        result = await db.execute(
            select(Server).where(
                Server.status == ServerStatus.ACTIVE,
                Server.deleted_at.is_(None),
            )
        )
        servers = result.scalars().all()

    for server in servers:
        try:
            async with asyncssh.connect(
                server.hostname,
                port=server.ssh_port,
                username="bastion",
                known_hosts=None,
            ) as conn:
                updates = await get_available_updates(conn, server.os_family.value)

            async with get_db_session() as db:
                for pkg in updates:
                    result = await db.execute(
                        select(ServerPackage).where(
                            ServerPackage.server_id == server.id,
                            ServerPackage.package_name == pkg["name"],
                        )
                    )
                    record = result.scalar_one_or_none()
                    if record is None:
                        record = ServerPackage(
                            server_id=server.id,
                            package_name=pkg["name"],
                        )
                        db.add(record)
                    record.available_version = pkg["available_version"]
                    record.installed_version = pkg.get("installed_version") or record.installed_version
                    record.update_available = True
                    record.last_checked_at = datetime.now(tz=timezone.utc)

            log.info(
                "Package update check completed",
                hostname=server.hostname,
                updates_available=len(updates),
            )
        except Exception as exc:
            log.error(
                "Package update check failed",
                hostname=server.hostname,
                error=str(exc),
            )
