"""Integration tests for admin user update, listing, and role-based access control."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestListUsers:
    """Tests for GET /users/."""

    async def test_admin_can_list_users(
        self, admin_client: AsyncClient, admin_token: str, regular_user
    ):
        """An admin must be able to list all users."""
        response = await admin_client.get(
            "/users/", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        usernames = [u["username"] for u in response.json()]
        assert "testuser" in usernames

    async def test_auditor_can_list_users(
        self, admin_client: AsyncClient, auditor_token: str, regular_user
    ):
        """An auditor must be able to list users."""
        response = await admin_client.get(
            "/users/", headers={"Authorization": f"Bearer {auditor_token}"}
        )
        assert response.status_code == 200

    async def test_read_only_can_list_users(
        self, admin_client: AsyncClient, read_only_token: str, regular_user
    ):
        """A read-only user must be able to list users."""
        response = await admin_client.get(
            "/users/", headers={"Authorization": f"Bearer {read_only_token}"}
        )
        assert response.status_code == 200

    async def test_regular_user_cannot_list_users(
        self, admin_client: AsyncClient, user_token: str
    ):
        """A regular user must not be able to list users via the admin API."""
        response = await admin_client.get(
            "/users/", headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 403

    async def test_deleted_users_excluded_by_default(
        self, admin_client: AsyncClient, admin_token: str, regular_user, db_session
    ):
        """Soft-deleted users must not appear in the default listing."""
        from datetime import UTC, datetime

        from bastion.models import UserStatus

        regular_user.deleted_at = datetime.now(tz=UTC)
        regular_user.status = UserStatus.DELETED
        await db_session.flush()

        response = await admin_client.get(
            "/users/", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        usernames = [u["username"] for u in response.json()]
        assert "testuser" not in usernames

    async def test_include_deleted_shows_deleted_users(
        self, admin_client: AsyncClient, admin_token: str, regular_user, db_session
    ):
        """include_deleted=true must include soft-deleted users."""
        from datetime import UTC, datetime

        from bastion.models import UserStatus

        regular_user.deleted_at = datetime.now(tz=UTC)
        regular_user.status = UserStatus.DELETED
        await db_session.flush()

        response = await admin_client.get(
            "/users/?include_deleted=true",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        usernames = [u["username"] for u in response.json()]
        assert "testuser" in usernames


@pytest.mark.asyncio
class TestGetUser:
    """Tests for GET /users/{id}."""

    async def test_admin_can_get_user(
        self, admin_client: AsyncClient, admin_token: str, regular_user
    ):
        """An admin must be able to retrieve a user by ID."""
        response = await admin_client.get(
            f"/users/{regular_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert response.json()["username"] == "testuser"

    async def test_get_nonexistent_user_returns_404(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """Retrieving a non-existent user must return 404."""
        response = await admin_client.get(
            "/users/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    async def test_response_does_not_include_password(
        self, admin_client: AsyncClient, admin_token: str, regular_user
    ):
        """The user response must never include the hashed password."""
        response = await admin_client.get(
            f"/users/{regular_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert "hashed_password" not in response.json()
        assert "password" not in response.json()


@pytest.mark.asyncio
class TestUpdateUser:
    """Tests for PATCH /users/{id}."""

    async def test_admin_can_update_email(
        self, admin_client: AsyncClient, admin_token: str, regular_user
    ):
        """An admin must be able to update a user's email."""
        response = await admin_client.patch(
            f"/users/{regular_user.id}",
            json={"email": "newemail@example.com"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert response.json()["email"] == "newemail@example.com"

    async def test_admin_can_update_role(
        self, admin_client: AsyncClient, admin_token: str, regular_user
    ):
        """An admin must be able to change a user's role."""
        response = await admin_client.patch(
            f"/users/{regular_user.id}",
            json={"role": "auditor"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert response.json()["role"] == "auditor"

    async def test_admin_can_update_password(
        self, admin_client: AsyncClient, admin_token: str, regular_user
    ):
        """An admin must be able to reset a user's password."""
        response = await admin_client.patch(
            f"/users/{regular_user.id}",
            json={"password": "new-strong-password-456"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200

    async def test_update_nonexistent_user_returns_404(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """Updating a non-existent user must return 404."""
        response = await admin_client.patch(
            "/users/00000000-0000-0000-0000-000000000000",
            json={"email": "x@example.com"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    async def test_non_admin_cannot_update_user(
        self, admin_client: AsyncClient, auditor_token: str, regular_user
    ):
        """An auditor must not be able to update a user."""
        response = await admin_client.patch(
            f"/users/{regular_user.id}",
            json={"email": "hacked@example.com"},
            headers={"Authorization": f"Bearer {auditor_token}"},
        )
        assert response.status_code == 403


@pytest.mark.asyncio
class TestSuspendUser:
    """Tests for POST /users/{id}/suspend."""

    async def test_suspended_user_cannot_login(
        self,
        api_client: AsyncClient,
        admin_client: AsyncClient,
        admin_token: str,
        regular_user,
    ):
        """A suspended user must not be able to log in."""
        await admin_client.post(
            f"/users/{regular_user.id}/suspend",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        response = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        assert response.status_code == 403

    async def test_suspend_nonexistent_user_returns_404(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """Suspending a non-existent user must return 404."""
        response = await admin_client.post(
            "/users/00000000-0000-0000-0000-000000000000/suspend",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404


@pytest.mark.asyncio
class TestAdminHealth:
    """Tests for GET /health on the admin API."""

    async def test_admin_health_returns_ok(self, admin_client: AsyncClient):
        """Admin health endpoint must return 200 without authentication."""
        response = await admin_client.get("/health")
        assert response.status_code == 200
        assert response.json()["service"] == "bastion-admin"
