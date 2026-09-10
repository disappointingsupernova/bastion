"""Admin servers router — onboard, configure, provision, and manage remote servers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.audit import audit
from bastion.db import get_db
from bastion.logging import get_logger
from bastion.models import (
    OsFamily,
    Server,
    ServerAccess,
    ServerPackage,
    ServerStatus,
    User,
    UserRole,
)
from bastion_api.deps import require_role

log = get_logger(__name__)
router = APIRouter(prefix="/servers", tags=["Servers"])

_admin = require_role(UserRole.ADMIN)
_admin_or_auditor = require_role(UserRole.ADMIN, UserRole.AUDITOR, UserRole.READ_ONLY)


class OnboardServerRequest(BaseModel):
    hostname: str
    display_name: str | None = None
    ssh_port: int = 22
    os_family: OsFamily = OsFamily.UNKNOWN
    tags: list[str] | None = None
    notes: str | None = None
    proxy_jump_hostname: str | None = None


class ServerResponse(BaseModel):
    id: str
    hostname: str
    display_name: str | None
    ssh_port: int
    os_family: str
    status: str
    hardening_applied: bool
    last_seen_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class GrantAccessRequest(BaseModel):
    user_id: str
    allow_sudo: bool = False
    remote_username: str | None = None


class PackageUpdateRequest(BaseModel):
    package_names: list[str] | None = None  # None means update all


@router.post("/", response_model=ServerResponse, status_code=status.HTTP_201_CREATED)
async def onboard_server(
    body: OnboardServerRequest,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ServerResponse:
    """Onboard a new server into Bastion."""
    import json

    result = await db.execute(
        select(Server).where(Server.hostname == body.hostname, Server.deleted_at.is_(None))
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A server with that hostname is already onboarded.",
        )

    proxy_jump_id = None
    if body.proxy_jump_hostname:
        result = await db.execute(
            select(Server).where(
                Server.hostname == body.proxy_jump_hostname,
                Server.deleted_at.is_(None),
            )
        )
        jump = result.scalar_one_or_none()
        if jump is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Proxy jump server '{body.proxy_jump_hostname}' not found.",
            )
        proxy_jump_id = jump.id

    server = Server(
        hostname=body.hostname,
        display_name=body.display_name,
        ssh_port=body.ssh_port,
        os_family=body.os_family,
        tags=json.dumps(body.tags or []),
        notes=body.notes,
        proxy_jump_server_id=proxy_jump_id,
    )
    db.add(server)
    await db.flush()

    await audit(
        db,
        "admin.server.onboard",
        success=True,
        user_id=current_user.id,
        resource_type="server",
        resource_id=server.id,
        detail={"hostname": body.hostname},
    )
    log.info("Server onboarded", hostname=body.hostname, onboarded_by=current_user.username)
    return ServerResponse.model_validate(server)


@router.get("/", response_model=list[ServerResponse])
async def list_servers(
    current_user: Annotated[User, Depends(_admin_or_auditor)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[ServerResponse]:
    """List all onboarded servers."""
    result = await db.execute(
        select(Server).where(Server.deleted_at.is_(None)).order_by(Server.hostname)
    )
    return [ServerResponse.model_validate(s) for s in result.scalars().all()]


@router.post("/{server_id}/access", status_code=status.HTTP_201_CREATED)
async def grant_access(
    server_id: str,
    body: GrantAccessRequest,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Grant a user access to a server, optionally with sudo."""
    result = await db.execute(
        select(Server).where(Server.id == server_id, Server.deleted_at.is_(None))
    )
    server = result.scalar_one_or_none()
    if server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found.")

    result = await db.execute(
        select(ServerAccess).where(
            ServerAccess.user_id == body.user_id,
            ServerAccess.server_id == server_id,
            ServerAccess.revoked_at.is_(None),
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already has access to this server.",
        )

    access = ServerAccess(
        user_id=body.user_id,
        server_id=server_id,
        allow_sudo=body.allow_sudo,
        remote_username=body.remote_username,
    )
    db.add(access)
    await db.flush()

    await audit(
        db,
        "admin.server.access.grant",
        success=True,
        user_id=current_user.id,
        resource_type="server_access",
        resource_id=access.id,
        detail={"target_user_id": body.user_id, "server_id": server_id, "sudo": body.allow_sudo},
    )
    log.info(
        "Server access granted",
        target_user_id=body.user_id,
        server_id=server_id,
        sudo=body.allow_sudo,
        granted_by=current_user.username,
    )
    return {"id": access.id, "message": "Access granted."}


@router.delete("/{server_id}/access/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_access(
    server_id: str,
    user_id: str,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Revoke a user's access to a server."""
    result = await db.execute(
        select(ServerAccess).where(
            ServerAccess.user_id == user_id,
            ServerAccess.server_id == server_id,
            ServerAccess.revoked_at.is_(None),
        )
    )
    access = result.scalar_one_or_none()
    if access is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access grant not found.")

    access.revoked_at = datetime.now(tz=UTC)
    await db.flush()
    await audit(
        db,
        "admin.server.access.revoke",
        success=True,
        user_id=current_user.id,
        resource_type="server_access",
        resource_id=access.id,
        detail={"target_user_id": user_id, "server_id": server_id},
    )
    log.info("Server access revoked", target_user_id=user_id, server_id=server_id)


@router.post("/{server_id}/provision", status_code=status.HTTP_202_ACCEPTED)
async def provision_server(
    server_id: str,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Provision all granted users onto the server and apply SSH hardening.

    This is an async operation — the task is queued and returns immediately.
    """
    # Trigger provisioning via Celery
    from celery import current_app

    current_app.send_task(
        "workers.tasks.provisioning.provision_server",
        args=[server_id, current_user.id],
    )
    await audit(
        db,
        "admin.server.provision",
        success=True,
        user_id=current_user.id,
        resource_type="server",
        resource_id=server_id,
    )
    return {"message": "Provisioning task queued.", "server_id": server_id}


@router.get("/{server_id}/packages", response_model=list[dict])
async def list_packages(
    server_id: str,
    current_user: Annotated[User, Depends(_admin_or_auditor)],
    db: Annotated[AsyncSession, Depends(get_db)],
    updates_only: bool = False,
) -> list[dict]:
    """List tracked packages for a server, optionally filtered to those with updates available."""
    query = select(ServerPackage).where(ServerPackage.server_id == server_id)
    if updates_only:
        query = query.where(ServerPackage.update_available == True)  # noqa: E712
    result = await db.execute(query.order_by(ServerPackage.package_name))
    return [
        {
            "name": p.package_name,
            "installed_version": p.installed_version,
            "available_version": p.available_version,
            "update_available": p.update_available,
            "last_checked_at": p.last_checked_at,
        }
        for p in result.scalars().all()
    ]


@router.post("/{server_id}/packages/update", status_code=status.HTTP_202_ACCEPTED)
async def apply_package_updates(
    server_id: str,
    body: PackageUpdateRequest,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Queue a package update task for the specified server."""
    from celery import current_app

    current_app.send_task(
        "workers.tasks.packages.apply_updates_for_server",
        args=[server_id, body.package_names, current_user.id],
    )
    await audit(
        db,
        "admin.server.packages.update",
        success=True,
        user_id=current_user.id,
        resource_type="server",
        resource_id=server_id,
        detail={"packages": body.package_names},
    )
    return {"message": "Package update task queued.", "server_id": server_id}


@router.post("/{server_id}/reboot", status_code=status.HTTP_202_ACCEPTED)
async def reboot_server(
    server_id: str,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    delay_seconds: int = 60,
) -> dict:
    """Queue a reboot for the specified server.

    delay_seconds must be between 60 and 3600 (fix #21).
    """

    if not (60 <= delay_seconds <= 3600):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="delay_seconds must be between 60 and 3600.",
        )
    from celery import current_app

    current_app.send_task(
        "workers.tasks.provisioning.reboot_server",
        args=[server_id, delay_seconds, current_user.id],
    )
    await audit(
        db,
        "admin.server.reboot",
        success=True,
        user_id=current_user.id,
        resource_type="server",
        resource_id=server_id,
        detail={"delay_seconds": delay_seconds},
    )
    return {"message": f"Reboot queued with {delay_seconds}s delay.", "server_id": server_id}


@router.delete("/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_server(
    server_id: str,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Soft-delete a server from Bastion."""
    result = await db.execute(
        select(Server).where(Server.id == server_id, Server.deleted_at.is_(None))
    )
    server = result.scalar_one_or_none()
    if server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found.")

    server.status = ServerStatus.DELETED
    server.deleted_at = datetime.now(tz=UTC)
    await db.flush()
    await audit(
        db,
        "admin.server.delete",
        success=True,
        user_id=current_user.id,
        resource_type="server",
        resource_id=server_id,
    )
    log.info("Server soft-deleted", server_id=server_id, deleted_by=current_user.username)
