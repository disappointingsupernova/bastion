"""Shared FastAPI dependencies — authentication, authorisation, and database sessions."""

from __future__ import annotations

from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.auth import decode_token, get_active_user
from bastion.db import get_db
from bastion.logging import get_logger
from bastion.models import User, UserRole

log = get_logger(__name__)

_bearer = HTTPBearer()


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Validate the Bearer JWT and return the authenticated user.

    Raises HTTP 401 if the token is missing, invalid, or the user is inactive.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(credentials.credentials)
        user_id: str = payload.get("sub") or ""
        token_type: str = payload.get("type") or ""
        if not user_id or token_type != "access":
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception from None

    user = await get_active_user(db, user_id)
    if user is None:
        log.warning("Token valid but user not found or inactive", user_id=user_id)
        raise credentials_exception

    return user


def require_role(*roles: UserRole):
    """Return a dependency that enforces one of the given roles."""

    async def _check(user: Annotated[User, Depends(get_current_user)]) -> User:
        if user.role not in roles:
            log.warning(
                "Authorisation denied — insufficient role",
                user_id=user.id,
                user_role=user.role,
                required_roles=[r.value for r in roles],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )
        return user

    return _check


def get_client_ip(request: Request) -> str:
    """Return the client IP address for audit logging.

    Since both APIs are Unix-socket only, X-Forwarded-For can be set by any
    local process and must not be trusted for security decisions. We record
    the Unix socket peer identity instead, falling back to 'unix-socket'.
    X-Forwarded-For is intentionally ignored (fix #10).
    """
    # Unix socket connections have no meaningful remote IP.
    # Record a stable identifier so audit logs are not blank.
    if request.client:
        host = request.client.host
        # Loopback or abstract socket addresses are fine to record
        if host and host not in ("", "unknown"):
            return host
    return "unix-socket"
