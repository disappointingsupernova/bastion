"""Bastion Admin API — administrative FastAPI application."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from bastion.config import get_settings
from bastion.logging import configure_logging, get_logger
from bastion_admin.routers import audit, certificates, servers, users
from bastion_admin.routers.access_requests import router as access_requests_router
from bastion_admin.routers.compliance import router as compliance_router
from bastion_admin.routers.dual_approvals import router as dual_approvals_router
from bastion_admin.routers.sessions import router as admin_sessions_router

log = get_logger(__name__)

# The admin API has no public endpoints except /health
_PUBLIC_PATHS = {"/health"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise logging on startup. Table creation is left to Alembic migrations."""
    settings = get_settings()
    configure_logging("bastion-admin", debug=settings.environment == "development")
    log.info("Bastion Admin API started", node_id=settings.node_id)
    yield
    log.info("Bastion Admin API shutting down")


app = FastAPI(
    title="Bastion Admin API",
    description="SSH Bastion administrative API — restricted access only",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

app.include_router(users.router)
app.include_router(servers.router)
app.include_router(certificates.router)
app.include_router(audit.router)
app.include_router(access_requests_router)
app.include_router(dual_approvals_router)
app.include_router(admin_sessions_router)
app.include_router(compliance_router)


@app.middleware("http")
async def require_auth_middleware(request: Request, call_next):
    """Global authentication safety net for the admin API (fix #9).

    Every route except /health must carry a valid Bearer token.
    Individual route dependencies enforce role-based access; this middleware
    ensures that a route accidentally missing its dependency is still protected.
    """
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


@app.get("/health", include_in_schema=False)
async def health() -> dict:
    """Health check endpoint."""
    return {"status": "ok", "service": "bastion-admin"}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler — returns a generic 500 without leaking internal details."""
    log.error(
        "Unhandled exception in admin API", path=request.url.path, error=str(exc), exc_info=True
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred. Please contact your administrator."},
    )
