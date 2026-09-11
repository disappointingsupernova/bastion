"""Authentication middleware for the bastion-api service.

Enforces that every request outside the public path set carries a valid
Bearer token. Individual route dependencies enforce role-based access;
this middleware is the last-resort safety net for routes that accidentally
lack a dependency.
"""

from __future__ import annotations

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

_PUBLIC_PATHS = {"/health", "/auth/login", "/auth/mfa/verify", "/auth/refresh"}


class RequireAuthMiddleware(BaseHTTPMiddleware):
    """Reject any request to a non-public path that lacks a Bearer token."""

    async def dispatch(self, request: Request, call_next):
        """Check for a Bearer token on every non-public request."""
        if request.url.path in _PUBLIC_PATHS:
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Authentication required."},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await call_next(request)
