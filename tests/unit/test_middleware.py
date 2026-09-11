"""Unit tests for the auth and rate-limit middleware modules."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient


def _make_api_app() -> FastAPI:
    """Return a minimal FastAPI app with RequireAuthMiddleware applied."""
    from bastion_api.middleware.auth import RequireAuthMiddleware

    app = FastAPI()
    app.add_middleware(RequireAuthMiddleware)

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.get("/protected")
    async def protected():
        return {"secret": "data"}

    @app.post("/auth/login")
    async def login():
        return {"token": "abc"}

    return app


def _make_admin_app() -> FastAPI:
    """Return a minimal FastAPI app with the admin RequireAuthMiddleware applied."""
    from bastion_admin.middleware.auth import RequireAuthMiddleware

    app = FastAPI()
    app.add_middleware(RequireAuthMiddleware)

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.get("/users/")
    async def users():
        return []

    return app


@pytest.mark.asyncio
class TestApiRequireAuthMiddleware:
    """Tests for bastion_api RequireAuthMiddleware."""

    async def test_health_passes_without_token(self):
        """GET /health must pass through without an Authorization header."""
        app = _make_api_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/health")
        assert response.status_code == 200

    async def test_login_passes_without_token(self):
        """POST /auth/login must pass through without an Authorization header."""
        app = _make_api_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.post("/auth/login")
        assert response.status_code == 200

    async def test_protected_route_without_token_returns_401(self):
        """A protected route without a token must return 401."""
        app = _make_api_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/protected")
        assert response.status_code == 401

    async def test_protected_route_with_bearer_token_passes(self):
        """A protected route with a Bearer token must pass through the middleware."""
        app = _make_api_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/protected", headers={"Authorization": "Bearer some-token"})
        # Middleware passes it through; the route itself returns 200
        assert response.status_code == 200

    async def test_non_bearer_scheme_returns_401(self):
        """An Authorization header with a non-Bearer scheme must return 401."""
        app = _make_api_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/protected", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert response.status_code == 401

    async def test_401_response_has_www_authenticate_header(self):
        """The 401 response must include a WWW-Authenticate: Bearer header."""
        app = _make_api_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/protected")
        assert response.headers.get("www-authenticate") == "Bearer"

    async def test_mfa_verify_path_is_public(self):
        """POST /auth/mfa/verify must pass through without a token."""
        from bastion_api.middleware.auth import RequireAuthMiddleware

        app = FastAPI()
        app.add_middleware(RequireAuthMiddleware)

        @app.post("/auth/mfa/verify")
        async def mfa_verify():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.post("/auth/mfa/verify")
        assert response.status_code == 200

    async def test_refresh_path_is_public(self):
        """POST /auth/refresh must pass through without a token."""
        from bastion_api.middleware.auth import RequireAuthMiddleware

        app = FastAPI()
        app.add_middleware(RequireAuthMiddleware)

        @app.post("/auth/refresh")
        async def refresh():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.post("/auth/refresh")
        assert response.status_code == 200


@pytest.mark.asyncio
class TestAdminRequireAuthMiddleware:
    """Tests for bastion_admin RequireAuthMiddleware."""

    async def test_health_passes_without_token(self):
        """GET /health must pass through without an Authorization header."""
        app = _make_admin_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/health")
        assert response.status_code == 200

    async def test_users_route_without_token_returns_401(self):
        """GET /users/ without a token must return 401."""
        app = _make_admin_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/users/")
        assert response.status_code == 401

    async def test_users_route_with_token_passes(self):
        """GET /users/ with a Bearer token must pass through the middleware."""
        app = _make_admin_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/users/", headers={"Authorization": "Bearer some-token"})
        assert response.status_code == 200

    async def test_401_body_has_detail_field(self):
        """The 401 response body must contain a 'detail' field."""
        app = _make_admin_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/users/")
        assert "detail" in response.json()
