"""Admin import router — bulk user import via CSV and LDAP/Active Directory sync."""

from __future__ import annotations

import csv
import io
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.audit import audit
from bastion.auth import hash_password
from bastion.config import get_settings
from bastion.db import get_db
from bastion.logging import get_logger
from bastion.models import User, UserRole, UserStatus
from bastion_api.deps import require_role

log = get_logger(__name__)
router = APIRouter(prefix="/import", tags=["Import"])

_admin = require_role(UserRole.ADMIN)


class ImportResult(BaseModel):
    created: int
    skipped: int
    errors: list[str]


class LdapSyncResult(BaseModel):
    created: int
    suspended: int
    errors: list[str]


@router.post("/users/csv", response_model=ImportResult)
async def import_users_csv(
    file: UploadFile,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ImportResult:
    """Bulk import users from a CSV file.

    Expected columns: username, email, full_name (optional), role (optional), password (optional).
    Users with duplicate usernames or emails are skipped.
    If no password column is present, a random password is generated — the user must reset it.
    """
    settings = get_settings()
    content = await file.read()
    try:
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not parse CSV: {exc}",
        ) from exc

    created = 0
    skipped = 0
    errors: list[str] = []

    for i, row in enumerate(reader, start=2):
        username = (row.get("username") or "").strip()
        email = (row.get("email") or "").strip()
        if not username or not email:
            errors.append(f"Row {i}: missing username or email — skipped.")
            skipped += 1
            continue

        if username in settings.excluded_system_users:
            errors.append(f"Row {i}: username '{username}' is reserved — skipped.")
            skipped += 1
            continue

        existing = (
            await db.execute(
                select(User).where(
                    (User.username == username) | (User.email == email),
                    User.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        if existing:
            skipped += 1
            continue

        import secrets

        password = row.get("password") or secrets.token_urlsafe(16)
        role_str = (row.get("role") or "user").strip().lower()
        try:
            role = UserRole(role_str)
        except ValueError:
            role = UserRole.USER

        user = User(
            username=username,
            email=email,
            full_name=(row.get("full_name") or "").strip() or None,
            hashed_password=hash_password(password),
            role=role,
        )
        db.add(user)
        try:
            await db.flush()
            created += 1
        except Exception as exc:
            errors.append(f"Row {i}: database error — {exc}")
            await db.rollback()

    await audit(
        db,
        "admin.import.users.csv",
        success=True,
        user_id=current_user.id,
        detail={"created": created, "skipped": skipped, "errors": len(errors)},
    )
    log.info("CSV user import complete", created=created, skipped=skipped, errors=len(errors))
    return ImportResult(created=created, skipped=skipped, errors=errors)


@router.post("/users/ldap-sync", response_model=LdapSyncResult)
async def ldap_sync(
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> LdapSyncResult:
    """Synchronise users from LDAP/Active Directory.

    Creates new users found in the directory. Suspends Bastion users whose
    LDAP accounts are disabled or no longer present in the directory.
    Requires LDAP_URL, LDAP_BIND_DN, LDAP_BIND_PASSWORD, and LDAP_USER_BASE_DN
    to be configured.
    """
    settings = get_settings()
    if not settings.ldap_url or not settings.ldap_user_base_dn:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="LDAP is not configured. Set LDAP_URL and LDAP_USER_BASE_DN.",
        )

    try:
        import ldap3  # type: ignore[import]
    except ImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="ldap3 package is not installed. Add it to requirements.txt.",
        ) from exc

    created = 0
    suspended = 0
    errors: list[str] = []

    try:
        server = ldap3.Server(settings.ldap_url, get_info=ldap3.ALL)
        conn = ldap3.Connection(
            server,
            user=settings.ldap_bind_dn,
            password=settings.ldap_bind_password,
            auto_bind=True,
        )
        conn.search(
            settings.ldap_user_base_dn,
            settings.ldap_user_filter,
            attributes=[
                settings.ldap_username_attr,
                settings.ldap_email_attr,
                "userAccountControl",
            ],
        )
        ldap_entries = conn.entries
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"LDAP connection failed: {exc}",
        ) from exc

    ldap_usernames: set[str] = set()

    for entry in ldap_entries:
        username = str(getattr(entry, settings.ldap_username_attr, "")).strip().lower()
        email = str(getattr(entry, settings.ldap_email_attr, "")).strip()
        if not username or not email:
            continue

        # Check if account is disabled (AD userAccountControl bit 2)
        uac = getattr(entry, "userAccountControl", None)
        is_disabled = uac and (int(str(uac)) & 2)

        ldap_usernames.add(username)

        if username in settings.excluded_system_users:
            continue

        existing = (
            await db.execute(
                select(User).where(User.username == username, User.deleted_at.is_(None))
            )
        ).scalar_one_or_none()

        if existing:
            if is_disabled and existing.status == UserStatus.ACTIVE:
                existing.status = UserStatus.SUSPENDED
                suspended += 1
        else:
            if not is_disabled:
                import secrets

                user = User(
                    username=username,
                    email=email,
                    hashed_password=hash_password(secrets.token_urlsafe(32)),
                    role=UserRole.USER,
                )
                db.add(user)
                try:
                    await db.flush()
                    created += 1
                except Exception as exc:
                    errors.append(f"Failed to create {username}: {exc}")

    # Suspend Bastion users not found in LDAP
    all_users_result = await db.execute(
        select(User).where(User.status == UserStatus.ACTIVE, User.deleted_at.is_(None))
    )
    for user in all_users_result.scalars().all():
        if (
            user.username not in ldap_usernames
            and user.username not in settings.excluded_system_users
        ):
            user.status = UserStatus.SUSPENDED
            suspended += 1
            log.info("User suspended — not found in LDAP", username=user.username)

    await audit(
        db,
        "admin.import.users.ldap_sync",
        success=True,
        user_id=current_user.id,
        detail={"created": created, "suspended": suspended, "errors": len(errors)},
    )
    log.info("LDAP sync complete", created=created, suspended=suspended)
    return LdapSyncResult(created=created, suspended=suspended, errors=errors)
