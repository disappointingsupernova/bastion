"""Integration tests for the sessions API endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestListSessions:
    """Tests for GET /sessions/."""

    async def test_empty_session_list(self, api_client: AsyncClient, user_token: str):
        """A user with no sessions must receive an empty list."""
        response = await api_client.get(
            "/sessions/", headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_sessions_listed(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """A user's sessions must appear in the list."""
        from datetime import UTC, datetime

        from bastion.models import Session, SessionStatus

        session = Session(
            user_id=regular_user.id,
            server_id=test_server.id,
            status=SessionStatus.COMPLETED,
            started_at=datetime.now(tz=UTC),
        )
        db_session.add(session)
        await db_session.flush()

        response = await api_client.get(
            "/sessions/", headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 200
        sessions = response.json()
        assert len(sessions) == 1
        assert sessions[0]["server_hostname"] == "test.example.com"
        assert sessions[0]["status"] == "completed"

    async def test_user_only_sees_own_sessions(
        self,
        api_client: AsyncClient,
        user_token: str,
        admin_user,
        regular_user,
        test_server,
        db_session,
    ):
        """A user must only see their own sessions, not other users'."""
        from datetime import UTC, datetime

        from bastion.models import Session, SessionStatus

        # Session belonging to admin_user
        db_session.add(
            Session(
                user_id=admin_user.id,
                server_id=test_server.id,
                status=SessionStatus.COMPLETED,
                started_at=datetime.now(tz=UTC),
            )
        )
        await db_session.flush()

        response = await api_client.get(
            "/sessions/", headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_unauthenticated_list_rejected(self, api_client: AsyncClient):
        """An unauthenticated request must return 401."""
        response = await api_client.get("/sessions/")
        assert response.status_code == 401

    async def test_pagination_limit(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """The limit parameter must restrict the number of sessions returned."""
        from datetime import UTC, datetime, timedelta

        from bastion.models import Session, SessionStatus

        for i in range(5):
            db_session.add(
                Session(
                    user_id=regular_user.id,
                    server_id=test_server.id,
                    status=SessionStatus.COMPLETED,
                    # Stagger timestamps so ordering is deterministic
                    started_at=datetime.now(tz=UTC) - timedelta(minutes=i),
                )
            )
        await db_session.flush()

        response = await api_client.get(
            "/sessions/?limit=3", headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 200
        assert len(response.json()) == 3


@pytest.mark.asyncio
class TestTerminateSession:
    """Tests for DELETE /sessions/{id}."""

    async def test_user_can_terminate_own_active_session(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """A user must be able to terminate their own active session."""
        from datetime import UTC, datetime

        from bastion.models import Session, SessionStatus

        session = Session(
            user_id=regular_user.id,
            server_id=test_server.id,
            status=SessionStatus.ACTIVE,
            started_at=datetime.now(tz=UTC),
        )
        db_session.add(session)
        await db_session.flush()

        response = await api_client.delete(
            f"/sessions/{session.id}",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 204

    async def test_cannot_terminate_already_completed_session(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """Terminating a completed session must return 404."""
        from datetime import UTC, datetime

        from bastion.models import Session, SessionStatus

        session = Session(
            user_id=regular_user.id,
            server_id=test_server.id,
            status=SessionStatus.COMPLETED,
            started_at=datetime.now(tz=UTC),
        )
        db_session.add(session)
        await db_session.flush()

        response = await api_client.delete(
            f"/sessions/{session.id}",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 404

    async def test_cannot_terminate_another_users_session(
        self,
        api_client: AsyncClient,
        user_token: str,
        admin_user,
        test_server,
        db_session,
    ):
        """A user must not be able to terminate another user's session."""
        from datetime import UTC, datetime

        from bastion.models import Session, SessionStatus

        session = Session(
            user_id=admin_user.id,
            server_id=test_server.id,
            status=SessionStatus.ACTIVE,
            started_at=datetime.now(tz=UTC),
        )
        db_session.add(session)
        await db_session.flush()

        response = await api_client.delete(
            f"/sessions/{session.id}",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 404

    async def test_terminate_nonexistent_session_returns_404(
        self, api_client: AsyncClient, user_token: str
    ):
        """Terminating a non-existent session must return 404."""
        response = await api_client.delete(
            "/sessions/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 404


@pytest.mark.asyncio
class TestConnectSession:
    """Tests for POST /sessions/connect."""

    async def test_connect_without_access_denied(
        self,
        api_client: AsyncClient,
        user_token: str,
        test_server,
    ):
        """Connecting to a server without an access grant must return 403."""
        response = await api_client.post(
            "/sessions/connect",
            json={
                "hostname": "test.example.com",
                "public_key": "ssh-ed25519 AAAA test",
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_connect_to_nonexistent_server_returns_404(
        self,
        api_client: AsyncClient,
        user_token: str,
    ):
        """Connecting to a server that doesn't exist must return 404."""
        response = await api_client.post(
            "/sessions/connect",
            json={
                "hostname": "nonexistent.example.com",
                "public_key": "ssh-ed25519 AAAA test",
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 404

    async def test_connect_to_unreachable_server_returns_503(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        db_session,
    ):
        """Connecting to an unreachable server must return 503."""
        from bastion.models import OsFamily, Server, ServerAccess, ServerStatus

        server = Server(
            hostname="unreachable.example.com",
            os_family=OsFamily.DEBIAN,
            status=ServerStatus.UNREACHABLE,
        )
        db_session.add(server)
        await db_session.flush()

        db_session.add(ServerAccess(user_id=regular_user.id, server_id=server.id))
        await db_session.flush()

        response = await api_client.post(
            "/sessions/connect",
            json={
                "hostname": "unreachable.example.com",
                "public_key": "ssh-ed25519 AAAA test",
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 503

    async def test_connect_unauthenticated_returns_401(self, api_client: AsyncClient):
        """An unauthenticated connect request must return 401."""
        response = await api_client.post(
            "/sessions/connect",
            json={"hostname": "test.example.com", "public_key": "ssh-ed25519 AAAA test"},
        )
        assert response.status_code == 401
