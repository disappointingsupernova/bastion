"""Integration tests for admin sessions, health dashboard, groups, and compliance endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestHealthDashboard:
    """Tests for GET /health/dashboard."""

    async def test_dashboard_returns_200_for_admin(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """The health dashboard must return 200 for an admin user."""
        response = await admin_client.get(
            "/health/dashboard",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "bastion-admin"
        assert data["status"] == "ok"
        assert "active_sessions" in data
        assert "active_users" in data
        assert "cluster_nodes" in data

    async def test_dashboard_returns_200_for_auditor(
        self, admin_client: AsyncClient, auditor_token: str
    ):
        """The health dashboard must return 200 for an auditor user."""
        response = await admin_client.get(
            "/health/dashboard",
            headers={"Authorization": f"Bearer {auditor_token}"},
        )
        assert response.status_code == 200

    async def test_dashboard_returns_403_for_regular_user(
        self, admin_client: AsyncClient, user_token: str
    ):
        """The health dashboard must return 403 for a regular user."""
        response = await admin_client.get(
            "/health/dashboard",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_dashboard_counts_active_sessions(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """The dashboard must reflect the correct active session count."""
        from datetime import UTC, datetime

        from bastion.models import Session, SessionStatus

        db_session.add(
            Session(
                user_id=regular_user.id,
                server_id=test_server.id,
                status=SessionStatus.ACTIVE,
                started_at=datetime.now(tz=UTC),
            )
        )
        await db_session.flush()

        response = await admin_client.get(
            "/health/dashboard",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert response.json()["active_sessions"] == 1


@pytest.mark.asyncio
class TestAdminGroups:
    """Tests for the /groups/ admin endpoints."""

    async def test_create_group_returns_201(self, admin_client: AsyncClient, admin_token: str):
        """Creating a group must return 201 with the group data."""
        response = await admin_client.post(
            "/groups/",
            json={"name": "ops-team", "description": "Operations team"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "ops-team"
        assert "id" in data

    async def test_create_duplicate_group_returns_409(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """Creating a group with a duplicate name must return 409."""
        await admin_client.post(
            "/groups/",
            json={"name": "duplicate-group"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        response = await admin_client.post(
            "/groups/",
            json={"name": "duplicate-group"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 409

    async def test_list_groups_returns_200(self, admin_client: AsyncClient, admin_token: str):
        """Listing groups must return 200 with a list."""
        response = await admin_client.get(
            "/groups/",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    async def test_add_member_to_nonexistent_group_returns_404(
        self, admin_client: AsyncClient, admin_token: str, regular_user
    ):
        """Adding a member to a non-existent group must return 404."""
        response = await admin_client.post(
            f"/groups/nonexistent-id/members/{regular_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    async def test_add_nonexistent_user_to_group_returns_404(
        self, admin_client: AsyncClient, admin_token: str, db_session
    ):
        """Adding a non-existent user to a group must return 404."""
        from bastion.models import UserGroup

        group = UserGroup(name="test-group-404")
        db_session.add(group)
        await db_session.flush()

        response = await admin_client.post(
            f"/groups/{group.id}/members/nonexistent-user-id",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    async def test_add_member_then_duplicate_returns_409(
        self, admin_client: AsyncClient, admin_token: str, regular_user, db_session
    ):
        """Adding the same user to a group twice must return 409."""
        from bastion.models import UserGroup

        group = UserGroup(name="test-group-dup")
        db_session.add(group)
        await db_session.flush()

        await admin_client.post(
            f"/groups/{group.id}/members/{regular_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        response = await admin_client.post(
            f"/groups/{group.id}/members/{regular_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 409

    async def test_remove_member_from_group(
        self, admin_client: AsyncClient, admin_token: str, regular_user, db_session
    ):
        """Removing a member from a group must return 204."""
        from bastion.models import UserGroup, UserGroupMembership

        group = UserGroup(name="test-group-remove")
        db_session.add(group)
        await db_session.flush()

        db_session.add(UserGroupMembership(user_id=regular_user.id, group_id=group.id))
        await db_session.flush()

        response = await admin_client.delete(
            f"/groups/{group.id}/members/{regular_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 204

    async def test_remove_nonexistent_membership_returns_404(
        self, admin_client: AsyncClient, admin_token: str, regular_user, db_session
    ):
        """Removing a non-existent membership must return 404."""
        from bastion.models import UserGroup

        group = UserGroup(name="test-group-no-member")
        db_session.add(group)
        await db_session.flush()

        response = await admin_client.delete(
            f"/groups/{group.id}/members/{regular_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    async def test_grant_group_server_access_nonexistent_group_returns_404(
        self, admin_client: AsyncClient, admin_token: str, test_server
    ):
        """Granting server access to a non-existent group must return 404."""
        response = await admin_client.post(
            "/groups/nonexistent-id/servers",
            json={"server_id": test_server.id},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    async def test_grant_group_server_access_nonexistent_server_returns_404(
        self, admin_client: AsyncClient, admin_token: str, db_session
    ):
        """Granting access to a non-existent server must return 404."""
        from bastion.models import UserGroup

        group = UserGroup(name="test-group-srv")
        db_session.add(group)
        await db_session.flush()

        response = await admin_client.post(
            f"/groups/{group.id}/servers",
            json={"server_id": "nonexistent-server-id"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    async def test_grant_group_server_access_provisions_members(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """Granting server access to a group must provision all current members."""
        from sqlalchemy import select

        from bastion.models import ServerAccess, UserGroup, UserGroupMembership

        group = UserGroup(name="test-group-provision")
        db_session.add(group)
        await db_session.flush()

        db_session.add(UserGroupMembership(user_id=regular_user.id, group_id=group.id))
        await db_session.flush()

        response = await admin_client.post(
            f"/groups/{group.id}/servers",
            json={"server_id": test_server.id, "allow_sudo": False},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 201

        access_result = await db_session.execute(
            select(ServerAccess).where(
                ServerAccess.user_id == regular_user.id,
                ServerAccess.server_id == test_server.id,
            )
        )
        assert access_result.scalar_one_or_none() is not None


@pytest.mark.asyncio
class TestComplianceEndpoints:
    """Tests for the /compliance/ admin endpoints."""

    async def test_download_access_matrix_csv(self, admin_client: AsyncClient, admin_token: str):
        """Downloading the access_matrix report as CSV must return 200."""
        response = await admin_client.get(
            "/compliance/reports/access_matrix",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]

    async def test_download_sessions_report(self, admin_client: AsyncClient, admin_token: str):
        """Downloading the sessions report must return 200."""
        response = await admin_client.get(
            "/compliance/reports/sessions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200

    async def test_download_cert_history_report(self, admin_client: AsyncClient, admin_token: str):
        """Downloading the cert_history report must return 200."""
        response = await admin_client.get(
            "/compliance/reports/cert_history",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200

    async def test_download_failed_auth_report(self, admin_client: AsyncClient, admin_token: str):
        """Downloading the failed_auth report must return 200."""
        response = await admin_client.get(
            "/compliance/reports/failed_auth",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200

    async def test_unknown_report_type_returns_400(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """An unknown report type must return 400."""
        response = await admin_client.get(
            "/compliance/reports/unknown_type",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 400

    async def test_non_admin_cannot_download_report(
        self, admin_client: AsyncClient, user_token: str
    ):
        """A non-admin/auditor must receive 403 when downloading a report."""
        response = await admin_client.get(
            "/compliance/reports/access_matrix",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_email_report_unknown_type_returns_400(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """Emailing an unknown report type must return 400."""
        response = await admin_client.post(
            "/compliance/reports/email",
            json={
                "report_type": "unknown_type",
                "fmt": "csv",
                "recipient": "admin@example.com",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 400

    async def test_email_report_no_smtp_returns_503(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """Emailing a report without SMTP configured must return 503."""
        response = await admin_client.post(
            "/compliance/reports/email",
            json={
                "report_type": "access_matrix",
                "fmt": "csv",
                "recipient": "admin@example.com",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 503

    async def test_auditor_can_download_report(self, admin_client: AsyncClient, auditor_token: str):
        """An auditor must be able to download compliance reports."""
        response = await admin_client.get(
            "/compliance/reports/access_matrix",
            headers={"Authorization": f"Bearer {auditor_token}"},
        )
        assert response.status_code == 200


@pytest.mark.asyncio
class TestAdminSessionsExtended:
    """Extended tests for admin session endpoints."""

    async def test_playback_session_with_nonexistent_recording_file_returns_404(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """Playback of a session whose recording file does not exist on disk must return 404."""
        from datetime import UTC, datetime

        from bastion.models import Session, SessionStatus

        session = Session(
            user_id=regular_user.id,
            server_id=test_server.id,
            status=SessionStatus.COMPLETED,
            started_at=datetime.now(tz=UTC),
            recording_path="/nonexistent/path/recording.cast.age",
        )
        db_session.add(session)
        await db_session.flush()

        response = await admin_client.post(
            f"/sessions/{session.id}/playback",
            json={"age_identity": "AGE-SECRET-KEY-1fake"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    async def test_derived_playback_no_master_key_returns_501(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        db_session,
    ):
        """Derived playback without RECORDINGS_MASTER_KEY configured must return 501."""
        response = await admin_client.get(
            "/sessions/nonexistent-session-id/playback/derived",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 501
