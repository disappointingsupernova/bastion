"""Integration tests for JIT access requests — user submission and admin review."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestUserAccessRequests:
    """Tests for the user-facing /access-requests endpoints."""

    async def test_jit_disabled_user_cannot_submit(
        self, api_client: AsyncClient, user_token: str
    ):
        """A user without jit_access_enabled must receive 403."""
        response = await api_client.post(
            "/access-requests/",
            json={
                "server_hostname": "web01.example.com",
                "reason": "Need access for deployment work",
                "requested_duration_hours": 4,
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_jit_enabled_user_can_submit(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """A user with jit_access_enabled must be able to submit a request."""
        regular_user.jit_access_enabled = True
        await db_session.flush()

        response = await api_client.post(
            "/access-requests/",
            json={
                "server_hostname": test_server.hostname,
                "reason": "Need access for deployment work",
                "requested_duration_hours": 4,
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "pending"
        assert data["server_hostname"] == test_server.hostname

    async def test_duplicate_pending_request_rejected(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """Submitting a second pending request for the same server must return 409."""
        regular_user.jit_access_enabled = True
        await db_session.flush()

        payload = {
            "server_hostname": test_server.hostname,
            "reason": "Need access for deployment work",
            "requested_duration_hours": 4,
        }
        headers = {"Authorization": f"Bearer {user_token}"}
        await api_client.post("/access-requests/", json=payload, headers=headers)
        response = await api_client.post("/access-requests/", json=payload, headers=headers)
        assert response.status_code == 409

    async def test_nonexistent_server_returns_404(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        db_session,
    ):
        """Requesting access to a non-existent server must return 404."""
        regular_user.jit_access_enabled = True
        await db_session.flush()

        response = await api_client.post(
            "/access-requests/",
            json={
                "server_hostname": "nonexistent.example.com",
                "reason": "Need access for deployment work",
                "requested_duration_hours": 4,
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 404

    async def test_reason_too_short_returns_422(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """A reason shorter than 10 characters must return 422."""
        regular_user.jit_access_enabled = True
        await db_session.flush()

        response = await api_client.post(
            "/access-requests/",
            json={
                "server_hostname": test_server.hostname,
                "reason": "short",
                "requested_duration_hours": 4,
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 422

    async def test_duration_exceeds_max_returns_422(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """A duration exceeding 72 hours must return 422."""
        regular_user.jit_access_enabled = True
        await db_session.flush()

        response = await api_client.post(
            "/access-requests/",
            json={
                "server_hostname": test_server.hostname,
                "reason": "Need access for deployment work",
                "requested_duration_hours": 73,
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 422

    async def test_list_my_requests_empty(
        self, api_client: AsyncClient, user_token: str
    ):
        """A user with no requests must receive an empty list."""
        response = await api_client.get(
            "/access-requests/",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_list_my_requests_shows_own_only(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """A user must only see their own access requests."""
        regular_user.jit_access_enabled = True
        await db_session.flush()

        await api_client.post(
            "/access-requests/",
            json={
                "server_hostname": test_server.hostname,
                "reason": "Need access for deployment work",
                "requested_duration_hours": 4,
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )

        response = await api_client.get(
            "/access-requests/",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 200
        assert len(response.json()) == 1

    async def test_withdraw_pending_request(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """A user must be able to withdraw their own pending request."""
        regular_user.jit_access_enabled = True
        await db_session.flush()

        headers = {"Authorization": f"Bearer {user_token}"}
        create_resp = await api_client.post(
            "/access-requests/",
            json={
                "server_hostname": test_server.hostname,
                "reason": "Need access for deployment work",
                "requested_duration_hours": 4,
            },
            headers=headers,
        )
        request_id = create_resp.json()["id"]

        response = await api_client.delete(
            f"/access-requests/{request_id}", headers=headers
        )
        assert response.status_code == 204

    async def test_withdraw_nonexistent_request_returns_404(
        self, api_client: AsyncClient, user_token: str
    ):
        """Withdrawing a non-existent request must return 404."""
        response = await api_client.delete(
            "/access-requests/nonexistent-id",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 404


@pytest.mark.asyncio
class TestAdminAccessRequestReview:
    """Tests for the admin /access-requests review endpoints."""

    async def test_admin_can_list_all_requests(
        self,
        admin_client: AsyncClient,
        admin_token: str,
    ):
        """An admin must be able to list all access requests."""
        response = await admin_client.get(
            "/access-requests/",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    async def test_admin_can_approve_request(
        self,
        api_client: AsyncClient,
        admin_client: AsyncClient,
        user_token: str,
        admin_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """An admin must be able to approve a pending access request."""
        regular_user.jit_access_enabled = True
        await db_session.flush()

        create_resp = await api_client.post(
            "/access-requests/",
            json={
                "server_hostname": test_server.hostname,
                "reason": "Need access for deployment work",
                "requested_duration_hours": 4,
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        request_id = create_resp.json()["id"]

        response = await admin_client.post(
            f"/access-requests/{request_id}/review",
            json={"approved": True, "note": "Approved for deployment"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 204

    async def test_admin_can_deny_request(
        self,
        api_client: AsyncClient,
        admin_client: AsyncClient,
        user_token: str,
        admin_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """An admin must be able to deny a pending access request."""
        regular_user.jit_access_enabled = True
        await db_session.flush()

        create_resp = await api_client.post(
            "/access-requests/",
            json={
                "server_hostname": test_server.hostname,
                "reason": "Need access for deployment work",
                "requested_duration_hours": 4,
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        request_id = create_resp.json()["id"]

        response = await admin_client.post(
            f"/access-requests/{request_id}/review",
            json={"approved": False, "note": "Not required"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 204

    async def test_review_nonexistent_request_returns_404(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """Reviewing a non-existent request must return 404."""
        response = await admin_client.post(
            "/access-requests/nonexistent-id/review",
            json={"approved": True},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    async def test_non_admin_cannot_review(
        self, admin_client: AsyncClient, user_token: str
    ):
        """A non-admin must receive 403 when attempting to review a request."""
        response = await admin_client.post(
            "/access-requests/some-id/review",
            json={"approved": True},
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_approval_creates_server_access(
        self,
        api_client: AsyncClient,
        admin_client: AsyncClient,
        user_token: str,
        admin_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """Approving a request must create a ServerAccess record for the user."""
        from sqlalchemy import select

        from bastion.models import ServerAccess

        regular_user.jit_access_enabled = True
        await db_session.flush()

        create_resp = await api_client.post(
            "/access-requests/",
            json={
                "server_hostname": test_server.hostname,
                "reason": "Need access for deployment work",
                "requested_duration_hours": 4,
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        request_id = create_resp.json()["id"]

        await admin_client.post(
            f"/access-requests/{request_id}/review",
            json={"approved": True},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        result = await db_session.execute(
            select(ServerAccess).where(
                ServerAccess.user_id == regular_user.id,
                ServerAccess.server_id == test_server.id,
                ServerAccess.revoked_at.is_(None),
            )
        )
        assert result.scalar_one_or_none() is not None
