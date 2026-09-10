"""Celery tasks for remote server provisioning — user creation, SSH hardening, and reboots."""

from __future__ import annotations

import asyncio

from workers.celery_app import app
from bastion.logging import get_logger

log = get_logger(__name__)


@app.task(name="workers.tasks.provisioning.provision_server", bind=True, max_retries=2)
def provision_server(self, server_id: str, triggered_by_user_id: str) -> None:
    """Provision all granted users onto a server and apply SSH hardening.

    Connects to the server as the bastion system user, creates Unix accounts
    for all users with active access grants, configures sudo where permitted,
    and applies the SSH hardening configuration.
    """
    asyncio.run(_provision_server(server_id, triggered_by_user_id))


@app.task(name="workers.tasks.provisioning.provision_user_on_server", bind=True, max_retries=2)
def provision_user_on_server(self, server_id: str, user_id: str, triggered_by_user_id: str) -> None:
    """Provision a single user onto a single server."""
    asyncio.run(_provision_user_on_server(server_id, user_id, triggered_by_user_id))


@app.task(name="workers.tasks.provisioning.deprovision_user_from_server", bind=True, max_retries=2)
def deprovision_user_from_server(self, server_id: str, username: str, triggered_by_user_id: str) -> None:
    """Remove a user account from a remote server."""
    asyncio.run(_deprovision_user_from_server(server_id, username, triggered_by_user_id))


@app.task(name="workers.tasks.provisioning.reboot_server", bind=True, max_retries=1)
def reboot_server(self, server_id: str, delay_seconds: int, triggered_by_user_id: str) -> None:
    """Schedule a reboot on a remote server."""
    asyncio.run(_reboot_server(server_id, delay_seconds, triggered_by_user_id))


# ── Async implementations ─────────────────────────────────────────────────────

async def _get_server_connection(server):
    """Open an asyncssh connection to a server using the bastion system key."""
    import asyncssh
    from bastion.config import get_settings

    settings = get_settings()
    connect_kwargs = {
        "username": "bastion",
        "client_keys": [str(settings.ca_key_path.parent / "bastion_host_key")],
        "known_hosts": None,
    }

    if server.proxy_jump_server_id:
        from bastion.db import get_db_session
        from bastion.models import Server
        from sqlalchemy import select

        async with get_db_session() as db:
            result = await db.execute(
                select(Server).where(Server.id == server.proxy_jump_server_id)
            )
            jump = result.scalar_one_or_none()

        if jump:
            tunnel = await asyncssh.connect(
                jump.hostname,
                port=jump.ssh_port,
                **connect_kwargs,
            )
            connect_kwargs["tunnel"] = tunnel

    return await asyncssh.connect(server.hostname, port=server.ssh_port, **connect_kwargs)


async def _provision_server(server_id: str, triggered_by_user_id: str) -> None:
    """Async implementation of full server provisioning."""
    from bastion.db import get_db_session
    from bastion.models import Server, ServerAccess, ServerStatus, User
    from bastion.provisioning import apply_ssh_hardening, provision_user
    from bastion.audit import audit
    from bastion.config import get_settings
    from sqlalchemy import select
    from datetime import datetime, timezone

    settings = get_settings()

    async with get_db_session() as db:
        result = await db.execute(
            select(Server).where(Server.id == server_id, Server.deleted_at.is_(None))
        )
        server = result.scalar_one_or_none()

    if server is None:
        log.error("Provisioning task failed — server not found", server_id=server_id)
        return

    log.info("Starting server provisioning", hostname=server.hostname, server_id=server_id)

    ca_pub_key = settings.ca_key_path.with_suffix(".pub").read_text().strip()

    try:
        conn = await _get_server_connection(server)
    except Exception as exc:
        log.error(
            "Provisioning failed — could not connect to server",
            hostname=server.hostname,
            error=str(exc),
        )
        async with get_db_session() as db:
            await audit(
                db, "worker.provision.connect_failed", success=False,
                user_id=triggered_by_user_id,
                resource_type="server",
                resource_id=server_id,
                detail={"error": str(exc)},
            )
        return

    async with conn:
        # Apply SSH hardening first
        try:
            await apply_ssh_hardening(conn, ca_pub_key)
            async with get_db_session() as db:
                result = await db.execute(select(Server).where(Server.id == server_id))
                s = result.scalar_one_or_none()
                if s:
                    s.hardening_applied = True
            log.info("SSH hardening applied", hostname=server.hostname)
        except Exception as exc:
            log.error(
                "SSH hardening failed",
                hostname=server.hostname,
                error=str(exc),
            )

        # Provision all users with active access grants
        async with get_db_session() as db:
            result = await db.execute(
                select(ServerAccess, User)
                .join(User, ServerAccess.user_id == User.id)
                .where(
                    ServerAccess.server_id == server_id,
                    ServerAccess.revoked_at.is_(None),
                )
            )
            grants = result.all()

        for access, user in grants:
            remote_username = access.remote_username or user.username
            try:
                await provision_user(
                    conn=conn,
                    username=remote_username,
                    uid=user.unix_uid,
                    allow_sudo=access.allow_sudo,
                    ca_public_key=ca_pub_key,
                )
                async with get_db_session() as db:
                    result = await db.execute(
                        select(ServerAccess).where(ServerAccess.id == access.id)
                    )
                    a = result.scalar_one_or_none()
                    if a:
                        a.provisioned = True
                        a.provisioned_at = datetime.now(tz=timezone.utc)

                log.info(
                    "User provisioned on server",
                    username=remote_username,
                    hostname=server.hostname,
                    sudo=access.allow_sudo,
                )
            except Exception as exc:
                log.error(
                    "User provisioning failed",
                    username=remote_username,
                    hostname=server.hostname,
                    error=str(exc),
                )

    async with get_db_session() as db:
        await audit(
            db, "worker.provision.completed", success=True,
            user_id=triggered_by_user_id,
            resource_type="server",
            resource_id=server_id,
            detail={"hostname": server.hostname, "users_provisioned": len(grants)},
        )

    log.info(
        "Server provisioning completed",
        hostname=server.hostname,
        users_provisioned=len(grants),
    )


async def _provision_user_on_server(server_id: str, user_id: str, triggered_by_user_id: str) -> None:
    """Async implementation of single-user provisioning."""
    from bastion.db import get_db_session
    from bastion.models import Server, ServerAccess, User
    from bastion.provisioning import provision_user
    from bastion.audit import audit
    from bastion.config import get_settings
    from sqlalchemy import select
    from datetime import datetime, timezone

    settings = get_settings()
    ca_pub_key = settings.ca_key_path.with_suffix(".pub").read_text().strip()

    async with get_db_session() as db:
        result = await db.execute(
            select(Server).where(Server.id == server_id, Server.deleted_at.is_(None))
        )
        server = result.scalar_one_or_none()

        result = await db.execute(
            select(ServerAccess, User)
            .join(User, ServerAccess.user_id == User.id)
            .where(
                ServerAccess.server_id == server_id,
                ServerAccess.user_id == user_id,
                ServerAccess.revoked_at.is_(None),
            )
        )
        row = result.one_or_none()

    if server is None or row is None:
        log.error(
            "Single-user provisioning failed — server or access grant not found",
            server_id=server_id,
            user_id=user_id,
        )
        return

    access, user = row
    remote_username = access.remote_username or user.username

    try:
        conn = await _get_server_connection(server)
        async with conn:
            await provision_user(
                conn=conn,
                username=remote_username,
                uid=user.unix_uid,
                allow_sudo=access.allow_sudo,
                ca_public_key=ca_pub_key,
            )

        async with get_db_session() as db:
            result = await db.execute(
                select(ServerAccess).where(ServerAccess.id == access.id)
            )
            a = result.scalar_one_or_none()
            if a:
                a.provisioned = True
                a.provisioned_at = datetime.now(tz=timezone.utc)

            await audit(
                db, "worker.provision.user.completed", success=True,
                user_id=triggered_by_user_id,
                resource_type="server_access",
                resource_id=access.id,
                detail={"hostname": server.hostname, "remote_username": remote_username},
            )

        log.info(
            "Single-user provisioning completed",
            username=remote_username,
            hostname=server.hostname,
        )
    except Exception as exc:
        log.error(
            "Single-user provisioning failed",
            username=remote_username,
            hostname=server.hostname,
            error=str(exc),
        )
        async with get_db_session() as db:
            await audit(
                db, "worker.provision.user.failed", success=False,
                user_id=triggered_by_user_id,
                resource_type="server_access",
                resource_id=access.id,
                detail={"error": str(exc)},
            )


async def _deprovision_user_from_server(server_id: str, username: str, triggered_by_user_id: str) -> None:
    """Async implementation of user deprovisioning."""
    from bastion.db import get_db_session
    from bastion.models import Server
    from bastion.provisioning import deprovision_user
    from bastion.audit import audit
    from sqlalchemy import select

    async with get_db_session() as db:
        result = await db.execute(
            select(Server).where(Server.id == server_id, Server.deleted_at.is_(None))
        )
        server = result.scalar_one_or_none()

    if server is None:
        log.error("Deprovisioning failed — server not found", server_id=server_id)
        return

    try:
        conn = await _get_server_connection(server)
        async with conn:
            await deprovision_user(conn, username)

        async with get_db_session() as db:
            await audit(
                db, "worker.deprovision.user.completed", success=True,
                user_id=triggered_by_user_id,
                resource_type="server",
                resource_id=server_id,
                detail={"hostname": server.hostname, "username": username},
            )

        log.info("User deprovisioned from server", username=username, hostname=server.hostname)
    except Exception as exc:
        log.error(
            "User deprovisioning failed",
            username=username,
            hostname=server.hostname,
            error=str(exc),
        )


async def _reboot_server(server_id: str, delay_seconds: int, triggered_by_user_id: str) -> None:
    """Async implementation of server reboot."""
    from bastion.db import get_db_session
    from bastion.models import Server
    from bastion.provisioning import reboot_server
    from bastion.audit import audit
    from sqlalchemy import select

    async with get_db_session() as db:
        result = await db.execute(
            select(Server).where(Server.id == server_id, Server.deleted_at.is_(None))
        )
        server = result.scalar_one_or_none()

    if server is None:
        log.error("Reboot task failed — server not found", server_id=server_id)
        return

    try:
        conn = await _get_server_connection(server)
        async with conn:
            await reboot_server(conn, delay_seconds)

        async with get_db_session() as db:
            await audit(
                db, "worker.reboot.scheduled", success=True,
                user_id=triggered_by_user_id,
                resource_type="server",
                resource_id=server_id,
                detail={"hostname": server.hostname, "delay_seconds": delay_seconds},
            )

        log.info(
            "Server reboot scheduled",
            hostname=server.hostname,
            delay_seconds=delay_seconds,
        )
    except Exception as exc:
        log.error(
            "Server reboot task failed",
            hostname=server.hostname,
            error=str(exc),
        )
