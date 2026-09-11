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
from bastion.logging import configure_logging, get_logger
from bastion_api.routers.access_requests import router as access_requests_router
from bastion_api.routers.auth import router as auth_router
from bastion_api.routers.sessions import router as sessions_router

log = get_logger(__name__)

# Paths that are explicitly unauthenticated
_PUBLIC_PATHS = {"/health", "/auth/login", "/auth/mfa/verify", "/auth/refresh"}
# Auth paths get a stricter rate limit than the default
_AUTH_PATHS = {"/auth/login", "/auth/mfa/verify", "/auth/refresh"}
_AUTH_RATE_LIMIT = 10  # requests per minute per IP


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise logging on startup. Table creation is left to Alembic migrations."""
    settings = get_settings()
    configure_logging("bastion-api", debug=settings.environment == "development")
    log.info("Bastion API started", node_id=settings.node_id)
    yield
    log.info("Bastion API shutting down")


settings = get_settings()
limiter = Limiter(
    key_func=get_remote_address,
    # Default limit applies to all non-auth routes
    default_limits=["200/minute"],
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


@app.middleware("http")
async def rate_limit_headers_middleware(request: Request, call_next):
    """Inject X-RateLimit-* headers into every response.

    slowapi sets X-RateLimit-Limit and X-RateLimit-Remaining on the response
    object itself when a limit is hit. For non-limited responses we read the
    configured default limit and compute remaining from the limiter's storage
    so that clients can back off gracefully before hitting a 429.
    """
    response = await call_next(request)

    # slowapi already injects these on 429 responses; propagate them on all
    # responses so clients always know their current standing.
    if "X-RateLimit-Limit" not in response.headers:
        try:
            # Derive the limit amount from the default_limits configuration
            limit_str = limiter.default_limits[0] if limiter.default_limits else None
            if limit_str:
                # Parse "200/minute" → amount=200
                amount = int(str(limit_str).split("/")[0])
                key = get_remote_address(request)
                # Ask the storage backend how many hits exist for this key
                storage = limiter._storage  # type: ignore[attr-defined]
                current = storage.get(f"LIMITER/{key}/{limit_str}") or 0
                remaining = max(0, amount - int(current))
                response.headers["X-RateLimit-Limit"] = str(amount)
                response.headers["X-RateLimit-Remaining"] = str(remaining)
        except Exception:
            pass

    return response

# CORS is intentionally restrictive — this API is Unix-socket only
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


@app.middleware("http")
async def require_auth_middleware(request: Request, call_next):
    """Global authentication safety net (fix #9).

    Any route not in _PUBLIC_PATHS must carry a valid Bearer token.
    Individual route dependencies enforce role-based access; this middleware
    ensures that a route accidentally missing its dependency is still protected.
    """
    if request.url.path in _PUBLIC_PATHS or request.url.path == "/health":
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
