"""Integration tests for the authentication API endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestLoginEndpoint:
    """Tests for POST /auth/login."""

    async def test_login_success_no_mfa(self, api_client: AsyncClient, regular_user, db_session):
        """Successful login without MFA must return access and refresh tokens."""
        response = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data.get("mfa_required") is None

    async def test_login_wrong_password(self, api_client: AsyncClient, regular_user):
        """Login with wrong password must return 401."""
        response = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "wrong-password"},
        )
        assert response.status_code == 401

    async def test_login_unknown_user(self, api_client: AsyncClient):
        """Login with unknown username must return 401."""
        response = await api_client.post(
            "/auth/login",
            json={"username": "nobody", "password": "password"},
        )
        assert response.status_code == 401

    async def test_login_suspended_user(self, api_client: AsyncClient, regular_user, db_session):
        """Login with a suspended account must return 403."""
        from bastion.models import UserStatus
        regular_user.status = UserStatus.SUSPENDED
        await db_session.flush()

        response = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        assert response.status_code == 403


@pytest.mark.asyncio
class TestTokenRefresh:
    """Tests for POST /auth/refresh."""

    async def test_refresh_returns_new_access_token(self, api_client: AsyncClient, regular_user):
        """A valid refresh token must return a new access token."""
        from bastion.auth import create_refresh_token
        refresh = create_refresh_token(regular_user.id)

        response = await api_client.post(
            "/auth/refresh",
            json={"refresh_token": refresh},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()

    async def test_invalid_refresh_token_rejected(self, api_client: AsyncClient):
        """An invalid refresh token must return 401."""
        response = await api_client.post(
            "/auth/refresh",
            json={"refresh_token": "not-a-valid-token"},
        )
        assert response.status_code == 401

    async def test_access_token_rejected_as_refresh(self, api_client: AsyncClient, regular_user):
        """An access token must not be accepted as a refresh token."""
        from bastion.auth import create_access_token
        access = create_access_token(regular_user.id, regular_user.username, regular_user.role.value)

        response = await api_client.post(
            "/auth/refresh",
            json={"refresh_token": access},
        )
        assert response.status_code == 401


@pytest.mark.asyncio
class TestHealthEndpoint:
    """Tests for GET /health."""

    async def test_health_returns_ok(self, api_client: AsyncClient):
        """Health endpoint must return 200 without authentication."""
        response = await api_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_health_does_not_require_auth(self, api_client: AsyncClient):
        """Health endpoint must not require an Authorization header."""
        response = await api_client.get("/health")
        assert response.status_code == 200


@pytest.mark.asyncio
class TestProtectedEndpoints:
    """Tests that protected endpoints reject unauthenticated requests."""

    async def test_sessions_requires_auth(self, api_client: AsyncClient):
        """GET /sessions/ must return 403 without a token."""
        response = await api_client.get("/sessions/")
        assert response.status_code == 403

    async def test_cert_issue_requires_auth(self, api_client: AsyncClient):
        """POST /auth/cert/issue must return 403 without a token."""
        response = await api_client.post(
            "/auth/cert/issue",
            json={"public_key": "ssh-ed25519 AAAA test"},
        )
        assert response.status_code == 403
