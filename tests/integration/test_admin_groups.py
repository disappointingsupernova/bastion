"""Integration tests for the admin user groups router."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestCreateGroup:
    """Tests for POST /groups/."""

    async def test_admin_can_create_group(self, admin_client: AsyncClient, admin_token: str):
        """An admin must be able to create a new group."""
        response = await admin_client.post(
            "/groups/",
            json={"name": "ops-team", "description": "Operations team"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "ops-team"
        assert data["description"] == "Operations team"
        assert "id" in data

    async def test_duplicate_group_name_returns_409(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """Creating a group with a duplicate name must return 409."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        await admin_client.post("/groups/", json={"name": "dup-team"}, headers=headers)
        response = await admin_client.post("/groups/", json={"name": "dup-team"}, headers=headers)
        assert response.status_code == 409

    async def test_non_admin_cannot_create_group(self, admin_client: AsyncClient, user_token: str):
        """A non-admin user must receive 403 when creating a group."""
        response = await admin_client.post(
            "/groups/",
            json={"name": "forbidden-team"},
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_unauthenticated_returns_401(self, admin_client: AsyncClient):
        """An unauthenticated request must return 401."""
        response = await admin_client.post("/groups/", json={"name": "anon-team"})
        assert response.status_code == 401


@pytest.mark.asyncio
class TestListGroups:
    """Tests for GET /groups/."""

    async def test_empty_list_returned_initially(self, admin_client: AsyncClient, admin_token: str):
        """With no groups, the list must be empty."""
        response = await admin_client.get(
            "/groups/", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_created_group_appears_in_list(self, admin_client: AsyncClient, admin_token: str):
        """A created group must appear in the list."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        await admin_client.post("/groups/", json={"name": "list-team"}, headers=headers)
        response = await admin_client.get("/groups/", headers=headers)
        assert response.status_code == 200
        names = [g["name"] for g in response.json()]
        assert "list-team" in names

    async def test_auditor_can_list_groups(self, admin_client: AsyncClient, auditor_token: str):
        """An auditor must be able to list groups."""
        response = await admin_client.get(
            "/groups/", headers={"Authorization": f"Bearer {auditor_token}"}
        )
        assert response.status_code == 200


@pytest.mark.asyncio
class TestGroupMembership:
    """Tests for POST/DELETE /groups/{group_id}/members/{user_id}."""

    async def test_add_member_to_group(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        regular_user,
    ):
        """An admin must be able to add a user to a group."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        group_resp = await admin_client.post(
            "/groups/", json={"name": "member-test-group"}, headers=headers
        )
        group_id = group_resp.json()["id"]

        response = await admin_client.post(
            f"/groups/{group_id}/members/{regular_user.id}",
            headers=headers,
        )
        assert response.status_code == 204

    async def test_add_member_nonexistent_group_returns_404(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        regular_user,
    ):
        """Adding a member to a non-existent group must return 404."""
        response = await admin_client.post(
            f"/groups/nonexistent-id/members/{regular_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    async def test_add_member_nonexistent_user_returns_404(
        self,
        admin_client: AsyncClient,
        admin_token: str,
    ):
        """Adding a non-existent user to a group must return 404."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        group_resp = await admin_client.post(
            "/groups/", json={"name": "user-404-group"}, headers=headers
        )
        group_id = group_resp.json()["id"]

        response = await admin_client.post(
            f"/groups/{group_id}/members/nonexistent-user-id",
            headers=headers,
        )
        assert response.status_code == 404

    async def test_duplicate_membership_returns_409(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        regular_user,
    ):
        """Adding the same user twice must return 409."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        group_resp = await admin_client.post(
            "/groups/", json={"name": "dup-member-group"}, headers=headers
        )
        group_id = group_resp.json()["id"]

        await admin_client.post(f"/groups/{group_id}/members/{regular_user.id}", headers=headers)
        response = await admin_client.post(
            f"/groups/{group_id}/members/{regular_user.id}", headers=headers
        )
        assert response.status_code == 409

    async def test_remove_member_from_group(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        regular_user,
    ):
        """An admin must be able to remove a member from a group."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        group_resp = await admin_client.post(
            "/groups/", json={"name": "remove-test-group"}, headers=headers
        )
        group_id = group_resp.json()["id"]

        await admin_client.post(f"/groups/{group_id}/members/{regular_user.id}", headers=headers)
        response = await admin_client.delete(
            f"/groups/{group_id}/members/{regular_user.id}", headers=headers
        )
        assert response.status_code == 204

    async def test_remove_nonexistent_membership_returns_404(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        regular_user,
    ):
        """Removing a user who is not a member must return 404."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        group_resp = await admin_client.post(
            "/groups/", json={"name": "no-member-group"}, headers=headers
        )
        group_id = group_resp.json()["id"]

        response = await admin_client.delete(
            f"/groups/{group_id}/members/{regular_user.id}", headers=headers
        )
        assert response.status_code == 404


@pytest.mark.asyncio
class TestGroupServerAccess:
    """Tests for POST /groups/{group_id}/servers."""

    async def test_grant_group_server_access(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        test_server,
    ):
        """An admin must be able to grant a group access to a server."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        group_resp = await admin_client.post(
            "/groups/", json={"name": "server-access-group"}, headers=headers
        )
        group_id = group_resp.json()["id"]

        response = await admin_client.post(
            f"/groups/{group_id}/servers",
            json={"server_id": test_server.id, "allow_sudo": False},
            headers=headers,
        )
        assert response.status_code == 201
        assert "group_server_access_id" in response.json()

    async def test_adding_member_after_server_grant_provisions_access(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """Adding a member after a server grant must auto-provision their access."""
        from sqlalchemy import select

        from bastion.models import ServerAccess

        headers = {"Authorization": f"Bearer {admin_token}"}
        group_resp = await admin_client.post(
            "/groups/", json={"name": "auto-provision-group"}, headers=headers
        )
        group_id = group_resp.json()["id"]

        # Grant server access to the group first
        await admin_client.post(
            f"/groups/{group_id}/servers",
            json={"server_id": test_server.id, "allow_sudo": False},
            headers=headers,
        )

        # Now add the user — they should be auto-provisioned
        await admin_client.post(f"/groups/{group_id}/members/{regular_user.id}", headers=headers)

        result = await db_session.execute(
            select(ServerAccess).where(
                ServerAccess.user_id == regular_user.id,
                ServerAccess.server_id == test_server.id,
                ServerAccess.revoked_at.is_(None),
            )
        )
        access = result.scalar_one_or_none()
        assert access is not None

    async def test_grant_nonexistent_server_returns_404(
        self,
        admin_client: AsyncClient,
        admin_token: str,
    ):
        """Granting access to a non-existent server must return 404."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        group_resp = await admin_client.post(
            "/groups/", json={"name": "bad-server-group"}, headers=headers
        )
        group_id = group_resp.json()["id"]

        response = await admin_client.post(
            f"/groups/{group_id}/servers",
            json={"server_id": "nonexistent-server-id", "allow_sudo": False},
            headers=headers,
        )
        assert response.status_code == 404
