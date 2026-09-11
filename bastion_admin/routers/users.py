"""Admin users router — create, update, suspend, and delete Bastion users."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.audit import audit
from bastion.auth import hash_password
from bastion.config import get_settings
from bastion.db import get_db
from bastion.logging import get_logger
from bastion.models import MfaMethod, User, UserRole, UserStatus
from bastion_api.deps import require_role

log = get_logger(__name__)
router = APIRouter(prefix="/users", tags=["Users"])

_admin_or_above = require_role(UserRole.ADMIN)


class CreateUserRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str | None = None
    role: UserRole = UserRole.USER
    mfa_method: MfaMethod | None = None


class UpdateUserRequest(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = None
    role: UserRole | None = None
    mfa_method: MfaMethod | None = None
    password: str | None = None
    ssh_public_key: str | None = None
    ip_allowlist: list[str] | None = None


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: str | None
    role: str
    status: str
    mfa_enabled: bool
    mfa_method: str | None
    last_login_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: CreateUserRequest,
    current_user: Annotated[User, Depends(_admin_or_above)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> UserResponse:
    """Create a new Bastion user account."""
    settings = get_settings()

    if body.username in settings.excluded_system_users:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"The username '{body.username}' is reserved and cannot be used.",
        )

    # Check for duplicate username or email
    result = await db.execute(
        select(User).where(
            (User.username == body.username) | (User.email == body.email),
            User.deleted_at.is_(None),
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with that username or email already exists.",
        )

    user = User(
        username=body.username,
        email=body.email,
        hashed_password=hash_password(body.password),
        full_name=body.full_name,
        role=body.role,
        mfa_method=body.mfa_method,
    )
    db.add(user)
    await db.flush()

    await audit(
        db,
        "admin.user.create",
        success=True,
        user_id=current_user.id,
        resource_type="user",
        resource_id=user.id,
        detail={"username": body.username, "role": body.role.value},
    )
    log.info("User created", username=body.username, created_by=current_user.username)
    return UserResponse.model_validate(user)


@router.get("/", response_model=list[UserResponse])
async def list_users(
    current_user: Annotated[
        User, Depends(require_role(UserRole.ADMIN, UserRole.AUDITOR, UserRole.READ_ONLY))
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    include_deleted: bool = False,
) -> list[UserResponse]:
    """List all Bastion users."""
    query = select(User)
    if not include_deleted:
        query = query.where(User.deleted_at.is_(None))
    result = await db.execute(query.order_by(User.created_at.desc()))
    return [UserResponse.model_validate(u) for u in result.scalars().all()]


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: Annotated[
        User, Depends(require_role(UserRole.ADMIN, UserRole.AUDITOR, UserRole.READ_ONLY))
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> UserResponse:
    """Retrieve a single user by ID."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return UserResponse.model_validate(user)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    body: UpdateUserRequest,
    current_user: Annotated[User, Depends(_admin_or_above)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> UserResponse:
    """Update a user's details."""
    result = await db.execute(select(User).where(User.id == user_id, User.deleted_at.is_(None)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if body.email is not None:
        user.email = body.email
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.role is not None:
        user.role = body.role
    if body.mfa_method is not None:
        user.mfa_method = body.mfa_method
    if body.password is not None:
        user.hashed_password = hash_password(body.password)
    if body.ssh_public_key is not None:
        user.ssh_public_key = body.ssh_public_key
        user.ssh_public_key_updated_at = datetime.now(tz=UTC)
    if body.ip_allowlist is not None:
        import json

        user.ip_allowlist = json.dumps(body.ip_allowlist)

    await db.flush()
    await audit(
        db,
        "admin.user.update",
        success=True,
        user_id=current_user.id,
        resource_type="user",
        resource_id=user_id,
    )
    return UserResponse.model_validate(user)


@router.post("/{user_id}/suspend", status_code=status.HTTP_204_NO_CONTENT)
async def suspend_user(
    user_id: str,
    current_user: Annotated[User, Depends(_admin_or_above)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Suspend a user account, preventing further logins."""
    result = await db.execute(select(User).where(User.id == user_id, User.deleted_at.is_(None)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    user.status = UserStatus.SUSPENDED
    await db.flush()
    await audit(
        db,
        "admin.user.suspend",
        success=True,
        user_id=current_user.id,
        resource_type="user",
        resource_id=user_id,
    )
    log.info("User suspended", target_user_id=user_id, suspended_by=current_user.username)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    current_user: Annotated[User, Depends(_admin_or_above)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Soft-delete a user account."""
    result = await db.execute(select(User).where(User.id == user_id, User.deleted_at.is_(None)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    user.status = UserStatus.DELETED
    user.deleted_at = datetime.now(tz=UTC)
    await db.flush()
    await audit(
        db,
        "admin.user.delete",
        success=True,
        user_id=current_user.id,
        resource_type="user",
        resource_id=user_id,
    )
    log.info("User soft-deleted", target_user_id=user_id, deleted_by=current_user.username)
