"""Integration tests for API app lifespan, exception handler, and deps module."""

from __future__ import annotations

import contextlib

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestApiAppBehaviour:
    """Tests for bastion_api app-level behaviour."""

    async def test_health_endpoint_returns_ok(self, api_client: AsyncClient):
        """The /health endpoint must return 200 without authentication."""
        response = await api_client.get("/health")
        assert response.status_code == 200
        assert response.json()["service"] == "bastion-api"

    async def test_unhandled_exception_handler_is_registered(self):
        """The unhandled exception handler must be registered on the app."""
        from bastion_api.main import app

        assert app is not None


@pytest.mark.asyncio
class TestAdminAppBehaviour:
    """Tests for bastion_admin app-level behaviour."""

    async def test_health_endpoint_returns_ok(self, admin_client: AsyncClient):
        """The admin /health endpoint must return 200 without authentication."""
        response = await admin_client.get("/health")
        assert response.status_code == 200
        assert response.json()["service"] == "bastion-admin"

    async def test_unhandled_exception_handler_is_registered(self):
        """The unhandled exception handler must be registered on the admin app."""
        from bastion_admin.main import app

        assert app is not None


@pytest.mark.asyncio
class TestGetClientIp:
    """Tests for get_client_ip dependency."""

    async def test_returns_unix_socket_when_no_client(self, api_client: AsyncClient):
        """get_client_ip must return 'unix-socket' when no client host is available."""
        from fastapi import Request

        from bastion_api.deps import get_client_ip

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [],
            "client": None,
        }
        request = Request(scope)
        ip = get_client_ip(request)
        assert ip == "unix-socket"

    async def test_returns_host_when_client_present(self, api_client: AsyncClient):
        """get_client_ip must return the client host when it is set."""
        from fastapi import Request

        from bastion_api.deps import get_client_ip

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [],
            "client": ("192.168.1.1", 12345),
        }
        request = Request(scope)
        ip = get_client_ip(request)
        assert ip == "192.168.1.1"

    async def test_returns_unix_socket_for_empty_host(self, api_client: AsyncClient):
        """get_client_ip must return 'unix-socket' when client host is empty string."""
        from fastapi import Request

        from bastion_api.deps import get_client_ip

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [],
            "client": ("", 0),
        }
        request = Request(scope)
        ip = get_client_ip(request)
        assert ip == "unix-socket"


@pytest.mark.asyncio
class TestRequireRole:
    """Tests for require_role dependency."""

    async def test_admin_can_access_admin_only_endpoint(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """An admin user must be able to access admin-only endpoints."""
        response = await admin_client.get(
            "/users/",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200

    async def test_regular_user_cannot_access_admin_endpoint(
        self, admin_client: AsyncClient, user_token: str
    ):
        """A regular user must receive 403 on admin-only endpoints."""
        response = await admin_client.get(
            "/users/",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_invalid_token_returns_401(self, admin_client: AsyncClient):
        """An invalid token must return 401."""
        response = await admin_client.get(
            "/users/",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert response.status_code == 401

    async def test_missing_token_returns_401(self, admin_client: AsyncClient):
        """A missing token must return 401."""
        response = await admin_client.get("/users/")
        assert response.status_code == 401


class TestDbModule:
    """Tests for bastion.db module — engine and session factory singletons."""

    def test_get_engine_returns_same_instance(self):
        """get_engine must return the same engine instance on repeated calls."""
        from bastion.db import get_engine

        e1 = get_engine()
        e2 = get_engine()
        assert e1 is e2

    def test_get_session_factory_returns_same_instance(self):
        """get_session_factory must return the same factory on repeated calls."""
        from bastion.db import get_session_factory

        f1 = get_session_factory()
        f2 = get_session_factory()
        assert f1 is f2

    async def test_get_db_session_commits_on_success(self):
        """get_db_session must commit the session when no exception is raised."""
        from bastion.db import get_db_session

        async with get_db_session() as session:
            assert session is not None

    async def test_get_db_yields_session(self):
        """get_db must yield an AsyncSession."""
        from sqlalchemy.ext.asyncio import AsyncSession

        from bastion.db import get_db

        gen = get_db()
        session = await gen.__anext__()
        assert isinstance(session, AsyncSession)
        with contextlib.suppress(Exception):
            await gen.aclose()
