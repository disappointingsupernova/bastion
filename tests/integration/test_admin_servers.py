"""Integration tests for the admin servers API endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestOnboardServer:
    """Tests for POST /servers/."""

    async def test_admin_can_onboard_server(self, admin_client: AsyncClient, admin_token: str):
        """An admin must be able to onboard a new server."""
        response = await admin_client.post(
            "/servers/",
            json={"hostname": "prod.example.com", "os_family": "debian", "ssh_port": 22},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["hostname"] == "prod.example.com"
        assert data["os_family"] == "debian"
        assert data["ssh_port"] == 22
        assert data["hardening_applied"] is False
        assert data["status"] == "active"

    async def test_duplicate_hostname_rejected(self, admin_client: AsyncClient, admin_token: str):
        """Onboarding a server with a duplicate hostname must return 409."""
        payload = {"hostname": "dup.example.com"}
        headers = {"Authorization": f"Bearer {admin_token}"}
        await admin_client.post("/servers/", json=payload, headers=headers)
        response = await admin_client.post("/servers/", json=payload, headers=headers)
        assert response.status_code == 409

    async def test_non_admin_cannot_onboard(self, admin_client: AsyncClient, user_token: str):
        """A non-admin must not be able to onboard a server."""
        response = await admin_client.post(
            "/servers/",
            json={"hostname": "blocked.example.com"},
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_unauthenticated_onboard_rejected(self, admin_client: AsyncClient):
        """An unauthenticated request must return 401."""
        response = await admin_client.post("/servers/", json={"hostname": "anon.example.com"})
        assert response.status_code == 401

    async def test_proxy_jump_server_resolved(self, admin_client: AsyncClient, admin_token: str):
        """Onboarding with a valid proxy_jump_hostname must link the jump server."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        await admin_client.post("/servers/", json={"hostname": "jump.example.com"}, headers=headers)
        response = await admin_client.post(
            "/servers/",
            json={"hostname": "behind.example.com", "proxy_jump_hostname": "jump.example.com"},
            headers=headers,
        )
        assert response.status_code == 201

    async def test_invalid_proxy_jump_returns_404(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """Specifying a non-existent proxy jump server must return 404."""
        response = await admin_client.post(
            "/servers/",
            json={
                "hostname": "new.example.com",
                "proxy_jump_hostname": "nonexistent.example.com",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404


@pytest.mark.asyncio
class TestListServers:
    """Tests for GET /servers/."""

    async def test_admin_can_list_servers(
        self, admin_client: AsyncClient, admin_token: str, test_server
    ):
        """An admin must be able to list all servers."""
        response = await admin_client.get(
            "/servers/", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        hostnames = [s["hostname"] for s in response.json()]
        assert "test.example.com" in hostnames

    async def test_auditor_can_list_servers(
        self, admin_client: AsyncClient, auditor_token: str, test_server
    ):
        """An auditor must be able to list servers."""
        response = await admin_client.get(
            "/servers/", headers={"Authorization": f"Bearer {auditor_token}"}
        )
        assert response.status_code == 200

    async def test_read_only_can_list_servers(
        self, admin_client: AsyncClient, read_only_token: str, test_server
    ):
        """A read-only user must be able to list servers."""
        response = await admin_client.get(
            "/servers/", headers={"Authorization": f"Bearer {read_only_token}"}
        )
        assert response.status_code == 200

    async def test_regular_user_cannot_list_servers(
        self, admin_client: AsyncClient, user_token: str
    ):
        """A regular user must not be able to list servers via the admin API."""
        response = await admin_client.get(
            "/servers/", headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 403


@pytest.mark.asyncio
class TestAccessGrants:
    """Tests for POST /servers/{id}/access and DELETE /servers/{id}/access/{user_id}."""

    async def test_admin_can_grant_access(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        test_server,
        regular_user,
    ):
        """An admin must be able to grant a user access to a server."""
        url = f"/servers/{test_server.id}/access"  # noqa: S105
        response = await admin_client.post(
            url,
            json={"user_id": regular_user.id, "allow_sudo": False},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 201
        assert "id" in response.json()

    async def test_duplicate_access_grant_rejected(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        test_server,
        regular_user,
    ):
        """Granting access twice to the same user/server must return 409."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        payload = {"user_id": regular_user.id}
        await admin_client.post(f"/servers/{test_server.id}/access", json=payload, headers=headers)
        response = await admin_client.post(
            f"/servers/{test_server.id}/access", json=payload, headers=headers
        )
        assert response.status_code == 409

    async def test_grant_with_sudo(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        test_server,
        regular_user,
    ):
        """An access grant with allow_sudo=True must be accepted."""
        response = await admin_client.post(
            f"/servers/{test_server.id}/access",
            json={"user_id": regular_user.id, "allow_sudo": True},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 201

    async def test_admin_can_revoke_access(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        test_server,
        regular_user,
        server_access,
    ):
        """An admin must be able to revoke a user's access to a server."""
        response = await admin_client.delete(
            f"/servers/{test_server.id}/access/{regular_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 204

    async def test_revoke_nonexistent_access_returns_404(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        test_server,
    ):
        """Revoking access that doesn't exist must return 404."""
        response = await admin_client.delete(
            f"/servers/{test_server.id}/access/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    async def test_grant_to_nonexistent_server_returns_404(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        regular_user,
    ):
        """Granting access to a non-existent server must return 404."""
        response = await admin_client.post(
            "/servers/00000000-0000-0000-0000-000000000000/access",
            json={"user_id": regular_user.id},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404


@pytest.mark.asyncio
class TestDeleteServer:
    """Tests for DELETE /servers/{id}."""

    async def test_admin_can_soft_delete_server(
        self, admin_client: AsyncClient, admin_token: str, test_server
    ):
        """An admin must be able to soft-delete a server."""
        response = await admin_client.delete(
            f"/servers/{test_server.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 204

    async def test_delete_nonexistent_server_returns_404(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """Deleting a non-existent server must return 404."""
        response = await admin_client.delete(
            "/servers/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    async def test_non_admin_cannot_delete_server(
        self, admin_client: AsyncClient, user_token: str, test_server
    ):
        """A non-admin must not be able to delete a server."""
        response = await admin_client.delete(
            f"/servers/{test_server.id}",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403


@pytest.mark.asyncio
class TestPackageEndpoints:
    """Tests for GET /servers/{id}/packages."""

    async def test_empty_package_list(
        self, admin_client: AsyncClient, admin_token: str, test_server
    ):
        """A server with no tracked packages must return an empty list."""
        response = await admin_client.get(
            f"/servers/{test_server.id}/packages",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_packages_listed(
        self, admin_client: AsyncClient, admin_token: str, test_server, db_session
    ):
        """Tracked packages must appear in the package list."""
        from bastion.models import ServerPackage

        db_session.add(
            ServerPackage(
                server_id=test_server.id,
                package_name="openssl",
                installed_version="3.0.2",
                available_version="3.0.3",
                update_available=True,
            )
        )
        await db_session.flush()

        response = await admin_client.get(
            f"/servers/{test_server.id}/packages",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        packages = response.json()
        assert len(packages) == 1
        assert packages[0]["name"] == "openssl"
        assert packages[0]["update_available"] is True

    async def test_updates_only_filter(
        self, admin_client: AsyncClient, admin_token: str, test_server, db_session
    ):
        """The updates_only filter must return only packages with updates available."""
        from bastion.models import ServerPackage

        db_session.add(
            ServerPackage(
                server_id=test_server.id,
                package_name="curl",
                installed_version="7.88.0",
                available_version="7.88.0",
                update_available=False,
            )
        )
        db_session.add(
            ServerPackage(
                server_id=test_server.id,
                package_name="openssl",
                installed_version="3.0.2",
                available_version="3.0.3",
                update_available=True,
            )
        )
        await db_session.flush()

        response = await admin_client.get(
            f"/servers/{test_server.id}/packages?updates_only=true",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        packages = response.json()
        assert len(packages) == 1
        assert packages[0]["name"] == "openssl"
