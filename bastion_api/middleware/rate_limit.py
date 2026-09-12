"""Rate limit headers middleware for the bastion-api service.

Injects X-RateLimit-Limit and X-RateLimit-Remaining headers on every
response so CLI tools and integrations can back off gracefully before
hitting a 429.
"""

from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from bastion.logging import get_logger

_log = get_logger(__name__)


def make_rate_limit_middleware(limiter):
    """Return a BaseHTTPMiddleware subclass bound to the given slowapi Limiter."""

    class RateLimitHeadersMiddleware(BaseHTTPMiddleware):
        """Inject X-RateLimit-* headers derived from the slowapi limiter storage."""

        async def dispatch(self, request: Request, call_next):
            """Add rate limit headers to the response."""
            response = await call_next(request)
            if "X-RateLimit-Limit" not in response.headers:
                try:
                    limit_str = limiter.default_limits[0] if limiter.default_limits else None
                    if limit_str:
                        from slowapi.util import get_remote_address

                        amount = int(str(limit_str).split("/")[0])
                        key = get_remote_address(request)
                        storage = limiter._storage  # type: ignore[attr-defined]
                        current = storage.get(f"LIMITER/{key}/{limit_str}") or 0
                        remaining = max(0, amount - int(current))
                        response.headers["X-RateLimit-Limit"] = str(amount)
                        response.headers["X-RateLimit-Remaining"] = str(remaining)
                except Exception as exc:
                    _log.debug("Could not inject rate-limit headers", error=str(exc))
            return response

    return RateLimitHeadersMiddleware
