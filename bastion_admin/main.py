"""Bastion Admin API — administrative FastAPI application."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import JSONResponse

from bastion.config import get_settings
from bastion.logging import configure_logging, get_logger
from bastion_admin.middleware.auth import RequireAuthMiddleware
from bastion_admin.routers import audit, certificates, servers, users
from bastion_admin.routers.access_requests import router as access_requests_router
from bastion_admin.routers.compliance import router as compliance_router
from bastion_admin.routers.dual_approvals import router as dual_approvals_router
from bastion_admin.routers.groups import router as groups_router
from bastion_admin.routers.health import router as health_router
from bastion_admin.routers.import_users import router as import_router
from bastion_admin.routers.sessions import router as admin_sessions_router

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise logging on startup. Table creation is left to Alembic migrations."""
    settings = get_settings()
    configure_logging("bastion-admin", debug=settings.environment == "development")
    log.info("Bastion Admin API started", node_id=settings.node_id)
    yield
    log.info("Bastion Admin API shutting down")


settings = get_settings()

app = FastAPI(
    title="Bastion Admin API",
    description="SSH Bastion administrative API — restricted access only",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(RequireAuthMiddleware)

app.include_router(users.router)
app.include_router(servers.router)
app.include_router(certificates.router)
app.include_router(audit.router)
app.include_router(access_requests_router)
app.include_router(dual_approvals_router)
app.include_router(admin_sessions_router)
app.include_router(compliance_router)
app.include_router(groups_router)
app.include_router(health_router)
app.include_router(import_router)


@app.get("/health", include_in_schema=False)
async def health() -> dict:
    """Health check endpoint."""
    return {"status": "ok", "service": "bastion-admin"}


# ── OpenAPI docs behind auth (non-production only) ────────────────────────────

if settings.environment != "production":
    from typing import Annotated

    from fastapi import Depends
    from fastapi.responses import HTMLResponse

    from bastion.models import UserRole
    from bastion_api.deps import require_role

    _admin_dep = require_role(UserRole.ADMIN)

    @app.get("/docs", include_in_schema=False)
    async def swagger_ui(current_user: Annotated[object, Depends(_admin_dep)]) -> HTMLResponse:
        """Swagger UI — admin-only, non-production environments only."""
        return get_swagger_ui_html(openapi_url="/openapi.json", title="Bastion Admin API")

    @app.get("/redoc", include_in_schema=False)
    async def redoc_ui(current_user: Annotated[object, Depends(_admin_dep)]) -> HTMLResponse:
        """ReDoc UI — admin-only, non-production environments only."""
        return get_redoc_html(openapi_url="/openapi.json", title="Bastion Admin API")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler — returns a generic 500 without leaking internal details."""
    log.error(
        "Unhandled exception in admin API", path=request.url.path, error=str(exc), exc_info=True
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. Please contact your administrator."},
    )
