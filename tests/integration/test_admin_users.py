"""Integration tests for the admin users API endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestCreateUser:
    """Tests for POST /users/."""

    async def test_admin_can_create_user(self, admin_client: AsyncClient, admin_token: str):
        """An admin must be able to create a new user."""
        response = await admin_client.post(
            "/users/",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "strong-password-123",
                "role": "user",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"
        assert data["role"] == "user"
        assert data["status"] == "active"
        assert "hashed_password" not in data

    async def test_duplicate_username_rejected(
        self, admin_client: AsyncClient, admin_token: str, regular_user
    ):
        """Creating a user with a duplicate username must return 409."""
        response = await admin_client.post(
            "/users/",
            json={
                "username": "testuser",  # already exists
                "email": "other@example.com",
                "password": "password-123",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 409

    async def test_reserved_username_rejected(self, admin_client: AsyncClient, admin_token: str):
        """Creating a user with a reserved system username must return 400."""
        response = await admin_client.post(
            "/users/",
            json={
                "username": "root",
                "email": "root@example.com",
                "password": "password-123",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 400

    async def test_non_admin_cannot_create_user(self, admin_client: AsyncClient, user_token: str):
        """A non-admin user must not be able to create users."""
        response = await admin_client.post(
            "/users/",
            json={
                "username": "anotheruser",
                "email": "another@example.com",
                "password": "password-123",
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_unauthenticated_request_rejected(self, admin_client: AsyncClient):
        """An unauthenticated request must return 401."""
        response = await admin_client.post(
            "/users/",
            json={
                "username": "anotheruser",
                "email": "another@example.com",
                "password": "password-123",
            },
        )
        assert response.status_code == 401


@pytest.mark.asyncio
class TestSuspendDeleteUser:
    """Tests for user suspension and deletion."""

    async def test_admin_can_suspend_user(
        self, admin_client: AsyncClient, admin_token: str, regular_user
    ):
        """An admin must be able to suspend a user."""
        response = await admin_client.post(
            f"/users/{regular_user.id}/suspend",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 204

    async def test_admin_can_delete_user(
        self, admin_client: AsyncClient, admin_token: str, regular_user
    ):
        """An admin must be able to soft-delete a user."""
        response = await admin_client.delete(
            f"/users/{regular_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 204

    async def test_delete_nonexistent_user_returns_404(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """Deleting a non-existent user must return 404."""
        response = await admin_client.delete(
            "/users/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404
