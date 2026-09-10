"""Bastion API — user-facing FastAPI application."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from bastion.config import get_settings
from bastion.db import create_all_tables
from bastion.logging import configure_logging, get_logger
from bastion_api.routers import auth, sessions

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise the database and CA on startup."""
    settings = get_settings()
    configure_logging("bastion-api", debug=settings.environment == "development")
    await create_all_tables()
    log.info("Bastion API started", node_id=settings.node_id)
    yield
    log.info("Bastion API shutting down")


settings = get_settings()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{settings.rate_limit_auth_per_minute}/minute"],
)

app = FastAPI(
    title="Bastion API",
    description="SSH Bastion user-facing API",
    version="0.1.0",
    docs_url=None,  # Disable Swagger UI in production
    redoc_url=None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

# CORS is intentionally restrictive — this API is Unix-socket only
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth.router)
app.include_router(sessions.router)


@app.get("/health", include_in_schema=False)
async def health() -> dict:
    """Health check endpoint — unauthenticated, returns service status."""
    return {"status": "ok", "service": "bastion-api"}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler for unhandled exceptions — returns a generic 500 without leaking details."""
    log.error("Unhandled exception", path=request.url.path, error=str(exc), exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred. Please contact your administrator."},
    )
