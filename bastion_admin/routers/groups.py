"""Admin user groups router — create groups, manage membership, and grant group server access."""

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
    GroupServerAccess,
    Server,
    ServerAccess,
    User,
    UserGroup,
    UserGroupMembership,
    UserRole,
)
from bastion_api.deps import require_role

log = get_logger(__name__)
router = APIRouter(prefix="/groups", tags=["User Groups"])

_admin = require_role(UserRole.ADMIN)
_admin_or_auditor = require_role(UserRole.ADMIN, UserRole.AUDITOR, UserRole.READ_ONLY)


class CreateGroupRequest(BaseModel):
    name: str
    description: str | None = None


class GroupResponse(BaseModel):
    id: str
    name: str
    description: str | None
    member_count: int = 0

    model_config = {"from_attributes": True}


class GroupServerAccessRequest(BaseModel):
    server_id: str
    allow_sudo: bool = False
    remote_username: str | None = None


@router.post("/", response_model=GroupResponse, status_code=status.HTTP_201_CREATED)
async def create_group(
    body: CreateGroupRequest,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> GroupResponse:
    """Create a new user group."""
    existing = await db.execute(
        select(UserGroup).where(UserGroup.name == body.name, UserGroup.deleted_at.is_(None))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Group name already exists.")

    group = UserGroup(name=body.name, description=body.description)
    db.add(group)
    await db.flush()
    await audit(
        db, "admin.group.create", success=True, user_id=current_user.id,
        resource_type="group", resource_id=group.id, detail={"name": body.name},
    )
    log.info("User group created", name=body.name, created_by=current_user.username)
    return GroupResponse(id=group.id, name=group.name, description=group.description)


@router.get("/", response_model=list[GroupResponse])
async def list_groups(
    current_user: Annotated[User, Depends(_admin_or_auditor)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[GroupResponse]:
    """List all user groups."""
    result = await db.execute(
        select(UserGroup).where(UserGroup.deleted_at.is_(None)).order_by(UserGroup.name)
    )
    groups = result.scalars().all()
    out = []
    for g in groups:
        count_result = await db.execute(
            select(UserGroupMembership).where(UserGroupMembership.group_id == g.id)
        )
        out.append(GroupResponse(
            id=g.id, name=g.name, description=g.description,
            member_count=len(count_result.scalars().all()),
        ))
    return out


@router.post("/{group_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def add_member(
    group_id: str,
    user_id: str,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Add a user to a group. Automatically provisions them on all group servers."""
    group = (await db.execute(
        select(UserGroup).where(UserGroup.id == group_id, UserGroup.deleted_at.is_(None))
    )).scalar_one_or_none()
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found.")

    user = (await db.execute(
        select(User).where(User.id == user_id, User.deleted_at.is_(None))
    )).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    existing = (await db.execute(
        select(UserGroupMembership).where(
            UserGroupMembership.user_id == user_id,
            UserGroupMembership.group_id == group_id,
        )
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already in group.")

    membership = UserGroupMembership(user_id=user_id, group_id=group_id)
    db.add(membership)

    # Auto-provision: create ServerAccess for all group server grants
    group_access_result = await db.execute(
        select(GroupServerAccess).where(
            GroupServerAccess.group_id == group_id,
            GroupServerAccess.revoked_at.is_(None),
        )
    )
    for gsa in group_access_result.scalars().all():
        existing_access = (await db.execute(
            select(ServerAccess).where(
                ServerAccess.user_id == user_id,
                ServerAccess.server_id == gsa.server_id,
                ServerAccess.revoked_at.is_(None),
            )
        )).scalar_one_or_none()
        if not existing_access:
            db.add(ServerAccess(
                user_id=user_id,
                server_id=gsa.server_id,
                allow_sudo=gsa.allow_sudo,
                remote_username=gsa.remote_username,
            ))

    await db.flush()
    await audit(
        db, "admin.group.member.add", success=True, user_id=current_user.id,
        resource_type="group", resource_id=group_id,
        detail={"added_user_id": user_id},
    )
    log.info("User added to group", user_id=user_id, group_id=group_id)


@router.delete("/{group_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    group_id: str,
    user_id: str,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Remove a user from a group."""
    membership = (await db.execute(
        select(UserGroupMembership).where(
            UserGroupMembership.user_id == user_id,
            UserGroupMembership.group_id == group_id,
        )
    )).scalar_one_or_none()
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Membership not found.")

    await db.delete(membership)
    await db.flush()
    await audit(
        db, "admin.group.member.remove", success=True, user_id=current_user.id,
        resource_type="group", resource_id=group_id,
        detail={"removed_user_id": user_id},
    )


@router.post("/{group_id}/servers", status_code=status.HTTP_201_CREATED)
async def grant_group_server_access(
    group_id: str,
    body: GroupServerAccessRequest,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Grant a group access to a server. All current members are provisioned immediately."""
    group = (await db.execute(
        select(UserGroup).where(UserGroup.id == group_id, UserGroup.deleted_at.is_(None))
    )).scalar_one_or_none()
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found.")

    server = (await db.execute(
        select(Server).where(Server.id == body.server_id, Server.deleted_at.is_(None))
    )).scalar_one_or_none()
    if server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found.")

    gsa = GroupServerAccess(
        group_id=group_id,
        server_id=body.server_id,
        allow_sudo=body.allow_sudo,
        remote_username=body.remote_username,
    )
    db.add(gsa)

    # Provision all current members
    members_result = await db.execute(
        select(UserGroupMembership).where(UserGroupMembership.group_id == group_id)
    )
    provisioned = 0
    for m in members_result.scalars().all():
        existing = (await db.execute(
            select(ServerAccess).where(
                ServerAccess.user_id == m.user_id,
                ServerAccess.server_id == body.server_id,
                ServerAccess.revoked_at.is_(None),
            )
        )).scalar_one_or_none()
        if not existing:
            db.add(ServerAccess(
                user_id=m.user_id,
                server_id=body.server_id,
                allow_sudo=body.allow_sudo,
                remote_username=body.remote_username,
            ))
            provisioned += 1

    await db.flush()
    await audit(
        db, "admin.group.server.grant", success=True, user_id=current_user.id,
        resource_type="group", resource_id=group_id,
        detail={"server_id": body.server_id, "provisioned_members": provisioned},
    )
    log.info("Group server access granted", group_id=group_id, server_id=body.server_id, provisioned=provisioned)
    return {"message": f"Access granted. {provisioned} members provisioned.", "group_server_access_id": gsa.id}
