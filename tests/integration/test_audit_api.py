"""Integration tests for the audit log endpoints including chain verification."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestAuditLogList:
    """Tests for GET /audit/."""

    async def test_admin_can_list_audit_logs(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """An admin must be able to list audit logs."""
        response = await admin_client.get(
            "/audit/", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    async def test_auditor_can_list_audit_logs(
        self, admin_client: AsyncClient, auditor_token: str
    ):
        """An auditor must be able to list audit logs."""
        response = await admin_client.get(
            "/audit/", headers={"Authorization": f"Bearer {auditor_token}"}
        )
        assert response.status_code == 200

    async def test_regular_user_cannot_list_audit_logs(
        self, admin_client: AsyncClient, user_token: str
    ):
        """A regular user must receive 403."""
        response = await admin_client.get(
            "/audit/", headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 403

    async def test_audit_entries_have_integrity_hash(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        db_session,
    ):
        """Audit log entries returned by the API must include an integrity_hash field."""
        from bastion.audit import audit

        await audit(db_session, "test.action", success=True)
        await db_session.flush()

        response = await admin_client.get(
            "/audit/", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        entries = response.json()
        assert len(entries) >= 1
        assert "integrity_hash" in entries[0]
        assert entries[0]["integrity_hash"] is not None

    async def test_filter_by_action(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        db_session,
    ):
        """Filtering by action must return only matching entries."""
        from bastion.audit import audit

        await audit(db_session, "auth.login", success=True)
        await audit(db_session, "admin.user.create", success=True)
        await db_session.flush()

        response = await admin_client.get(
            "/audit/",
            params={"action": "auth.login"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        entries = response.json()
        assert all("auth.login" in e["action"] for e in entries)

    async def test_filter_by_success(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        db_session,
    ):
        """Filtering by success=False must return only failed entries."""
        from bastion.audit import audit

        await audit(db_session, "auth.login", success=True)
        await audit(db_session, "auth.login", success=False)
        await db_session.flush()

        response = await admin_client.get(
            "/audit/",
            params={"success": False},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        entries = response.json()
        assert all(e["success"] is False for e in entries)

    async def test_limit_respected(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        db_session,
    ):
        """The limit parameter must cap the number of returned entries."""
        from bastion.audit import audit

        for i in range(10):
            await audit(db_session, f"action.{i}", success=True)
        await db_session.flush()

        response = await admin_client.get(
            "/audit/",
            params={"limit": 3},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert len(response.json()) <= 3


@pytest.mark.asyncio
class TestAuditChainVerification:
    """Tests for GET /audit/verify-chain."""

    async def test_empty_chain_is_valid(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """An empty audit log must report as valid."""
        response = await admin_client.get(
            "/audit/verify-chain",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["entries_checked"] == 0
        assert data["first_broken_entry_id"] is None

    async def test_valid_chain_reported_correctly(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        db_session,
    ):
        """A chain of valid entries must report as valid."""
        from bastion.audit import audit

        for i in range(5):
            await audit(db_session, f"action.{i}", success=True)
        await db_session.flush()

        response = await admin_client.get(
            "/audit/verify-chain",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["entries_checked"] == 5

    async def test_tampered_chain_detected(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        db_session,
    ):
        """A tampered entry must cause the chain verification to fail."""
        from sqlalchemy import select

        from bastion.audit import audit
        from bastion.models import AuditLog

        await audit(db_session, "action.one", success=True)
        e2 = await audit(db_session, "action.two", success=True)
        await audit(db_session, "action.three", success=True)

        # Tamper with the middle entry directly
        e2.action = "tampered"
        await db_session.flush()

        response = await admin_client.get(
            "/audit/verify-chain",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
        assert data["first_broken_entry_id"] == e2.id

    async def test_auditor_can_verify_chain(
        self, admin_client: AsyncClient, auditor_token: str
    ):
        """An auditor must be able to verify the audit chain."""
        response = await admin_client.get(
            "/audit/verify-chain",
            headers={"Authorization": f"Bearer {auditor_token}"},
        )
        assert response.status_code == 200

    async def test_regular_user_cannot_verify_chain(
        self, admin_client: AsyncClient, user_token: str
    ):
        """A regular user must receive 403."""
        response = await admin_client.get(
            "/audit/verify-chain",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403
