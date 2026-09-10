"""Shared FastAPI dependencies — authentication, authorisation, and database sessions."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
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
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type")
        if not user_id or token_type != "access":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

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
    """Extract the client IP address from the request, respecting X-Forwarded-For."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"
