"""Integration tests for the health dashboard and IP allowlist enforcement."""

from __future__ import annotations

import json

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestHealthDashboard:
    """Tests for GET /health/dashboard."""

    async def test_admin_can_access_dashboard(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """An admin must receive a 200 response with the dashboard payload."""
        response = await admin_client.get(
            "/health/dashboard",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "active_sessions" in data
        assert "pending_anomaly_events" in data
        assert "certs_expiring_soon" in data
        assert "active_users" in data
        assert "cluster_nodes" in data
        assert "generated_at" in data

    async def test_auditor_can_access_dashboard(
        self, admin_client: AsyncClient, auditor_token: str
    ):
        """An auditor must also be able to access the dashboard."""
        response = await admin_client.get(
            "/health/dashboard",
            headers={"Authorization": f"Bearer {auditor_token}"},
        )
        assert response.status_code == 200

    async def test_regular_user_cannot_access_dashboard(
        self, admin_client: AsyncClient, user_token: str
    ):
        """A regular user must receive 403."""
        response = await admin_client.get(
            "/health/dashboard",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_unauthenticated_returns_401(self, admin_client: AsyncClient):
        """An unauthenticated request must return 401."""
        response = await admin_client.get("/health/dashboard")
        assert response.status_code == 401

    async def test_active_sessions_count_correct(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        db_session,
        regular_user,
        test_server,
    ):
        """The active_sessions count must reflect the actual number of active sessions."""
        from datetime import UTC, datetime

        from bastion.models import Session, SessionStatus

        db_session.add(Session(
            user_id=regular_user.id,
            server_id=test_server.id,
            status=SessionStatus.ACTIVE,
            started_at=datetime.now(tz=UTC),
        ))
        await db_session.flush()

        response = await admin_client.get(
            "/health/dashboard",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.json()["active_sessions"] == 1

    async def test_active_users_count_correct(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        admin_user,
        regular_user,
    ):
        """The active_users count must include all active non-deleted users."""
        response = await admin_client.get(
            "/health/dashboard",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        # admin_user + regular_user = 2
        assert response.json()["active_users"] >= 2

    async def test_cluster_nodes_empty_initially(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """With no registered nodes, cluster_nodes must be an empty list."""
        response = await admin_client.get(
            "/health/dashboard",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.json()["cluster_nodes"] == []

    async def test_cluster_node_alive_status(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        db_session,
    ):
        """A node with a recent heartbeat must be reported as alive."""
        from datetime import UTC, datetime

        from bastion.models import BastionNode

        node = BastionNode(
            node_id="test-node-1",
            version="0.1.0",
            last_heartbeat_at=datetime.now(tz=UTC),
        )
        db_session.add(node)
        await db_session.flush()

        response = await admin_client.get(
            "/health/dashboard",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        nodes = response.json()["cluster_nodes"]
        assert len(nodes) == 1
        assert nodes[0]["node_id"] == "test-node-1"
        assert nodes[0]["alive"] is True

    async def test_stale_node_reported_as_dead(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        db_session,
    ):
        """A node with a heartbeat older than 2 minutes must be reported as not alive."""
        from datetime import UTC, datetime, timedelta

        from bastion.models import BastionNode

        node = BastionNode(
            node_id="stale-node-1",
            version="0.1.0",
            last_heartbeat_at=datetime.now(tz=UTC) - timedelta(minutes=5),
        )
        db_session.add(node)
        await db_session.flush()

        response = await admin_client.get(
            "/health/dashboard",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        nodes = response.json()["cluster_nodes"]
        assert nodes[0]["alive"] is False


@pytest.mark.asyncio
class TestIpAllowlistEnforcement:
    """Integration tests for IP allowlist enforcement at login."""

    async def test_login_blocked_when_ip_not_in_allowlist(
        self, api_client: AsyncClient, regular_user, db_session
    ):
        """Login must be rejected when the source IP is not in the user's allowlist."""
        regular_user.ip_allowlist = json.dumps(["10.0.0.0/8"])
        await db_session.flush()

        # The test client uses "testclient" as the host, which won't match 10.0.0.0/8
        response = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        # Should be denied — 401 (same as invalid credentials to avoid enumeration)
        assert response.status_code == 401

    async def test_login_allowed_when_no_allowlist(
        self, api_client: AsyncClient, regular_user
    ):
        """Login must succeed when the user has no IP allowlist configured."""
        response = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        assert response.status_code == 200

    async def test_login_allowed_when_allowlist_empty(
        self, api_client: AsyncClient, regular_user, db_session
    ):
        """Login must succeed when the allowlist is an empty JSON array."""
        regular_user.ip_allowlist = "[]"
        await db_session.flush()

        response = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        assert response.status_code == 200


@pytest.mark.asyncio
class TestAccessExpiryEnforcement:
    """Integration tests for ServerAccess expires_at enforcement at session connect."""

    async def test_expired_access_grant_denied(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        server_access,
        db_session,
    ):
        """A session connect attempt with an expired access grant must return 403."""
        from datetime import UTC, datetime, timedelta

        server_access.expires_at = datetime.now(tz=UTC) - timedelta(hours=1)
        await db_session.flush()

        response = await api_client.post(
            "/sessions/connect",
            json={
                "hostname": test_server.hostname,
                "public_key": "ssh-ed25519 AAAA test",
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_valid_access_grant_not_denied_by_expiry(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        server_access,
        db_session,
    ):
        """A session connect with a future expires_at must not be denied by expiry logic."""
        from datetime import UTC, datetime, timedelta

        server_access.expires_at = datetime.now(tz=UTC) + timedelta(days=30)
        await db_session.flush()

        # Will fail for other reasons (no real SSH) but not 403 from expiry
        response = await api_client.post(
            "/sessions/connect",
            json={
                "hostname": test_server.hostname,
                "public_key": "ssh-ed25519 AAAA test",
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        # 403 specifically from expiry check must not occur
        if response.status_code == 403:
            assert "expired" not in response.json().get("detail", "").lower()
