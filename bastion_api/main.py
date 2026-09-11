"""Bastion API — user-facing FastAPI application."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from bastion.config import get_settings
from bastion.logging import configure_logging, get_logger
from bastion_api.middleware.auth import RequireAuthMiddleware
from bastion_api.middleware.rate_limit import make_rate_limit_middleware
from bastion_api.routers.access_requests import router as access_requests_router
from bastion_api.routers.auth import router as auth_router
from bastion_api.routers.sessions import router as sessions_router

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise logging on startup. Table creation is left to Alembic migrations."""
    settings = get_settings()
    configure_logging("bastion-api", debug=settings.environment == "development")
    log.info("Bastion API started", node_id=settings.node_id)
    yield
    log.info("Bastion API shutting down")


settings = get_settings()
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

app = FastAPI(
    title="Bastion API",
    description="SSH Bastion user-facing API",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

# Middleware — registered in reverse execution order (last added = first executed)
app.add_middleware(RequireAuthMiddleware)
app.add_middleware(make_rate_limit_middleware(limiter))
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth_router)
app.include_router(sessions_router)
app.include_router(access_requests_router)


@app.get("/health", include_in_schema=False)
async def health() -> dict:
    """Health check endpoint — unauthenticated, returns service status."""
    return {"status": "ok", "service": "bastion-api"}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler — returns a generic 500 without leaking details."""
    log.error("Unhandled exception", path=request.url.path, error=str(exc), exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. Please contact your administrator."},
    )
