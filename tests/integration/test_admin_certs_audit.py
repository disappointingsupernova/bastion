"""Integration tests for the admin certificates and audit log endpoints."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestListCertificates:
    """Tests for GET /certificates/."""

    async def test_empty_list_when_no_certs(self, admin_client: AsyncClient, admin_token: str):
        """Certificate list must be empty when no certs have been issued."""
        response = await admin_client.get(
            "/certificates/", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_certs_listed(
        self, admin_client: AsyncClient, admin_token: str, regular_user, db_session
    ):
        """Issued certificates must appear in the list."""
        from bastion.models import CertStatus, SshCertificate

        db_session.add(
            SshCertificate(
                user_id=regular_user.id,
                serial=1,
                key_id="bastion-testuser-1",
                principals='["testuser"]',
                valid_after=datetime.now(tz=UTC),
                valid_before=datetime.now(tz=UTC) + timedelta(hours=8),
                status=CertStatus.ACTIVE,
            )
        )
        await db_session.flush()

        response = await admin_client.get(
            "/certificates/", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        certs = response.json()
        assert len(certs) == 1
        assert certs[0]["serial"] == 1
        assert certs[0]["status"] == "active"

    async def test_filter_by_user_id(
        self, admin_client: AsyncClient, admin_token: str, regular_user, admin_user, db_session
    ):
        """Filtering by user_id must return only that user's certificates."""
        from bastion.models import CertStatus, SshCertificate

        for i, uid in enumerate([regular_user.id, admin_user.id]):
            db_session.add(
                SshCertificate(
                    user_id=uid,
                    serial=i + 10,
                    key_id=f"key-{i}",
                    principals='["user"]',
                    valid_after=datetime.now(tz=UTC),
                    valid_before=datetime.now(tz=UTC) + timedelta(hours=8),
                    status=CertStatus.ACTIVE,
                )
            )
        await db_session.flush()

        response = await admin_client.get(
            f"/certificates/?user_id={regular_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        certs = response.json()
        assert len(certs) == 1
        assert certs[0]["user_id"] == regular_user.id

    async def test_filter_by_status(
        self, admin_client: AsyncClient, admin_token: str, regular_user, db_session
    ):
        """Filtering by cert_status must return only matching certificates."""
        from bastion.models import CertStatus, SshCertificate

        db_session.add(
            SshCertificate(
                user_id=regular_user.id,
                serial=20,
                key_id="active-key",
                principals='["user"]',
                valid_after=datetime.now(tz=UTC),
                valid_before=datetime.now(tz=UTC) + timedelta(hours=8),
                status=CertStatus.ACTIVE,
            )
        )
        db_session.add(
            SshCertificate(
                user_id=regular_user.id,
                serial=21,
                key_id="revoked-key",
                principals='["user"]',
                valid_after=datetime.now(tz=UTC),
                valid_before=datetime.now(tz=UTC) + timedelta(hours=8),
                status=CertStatus.REVOKED,
                revoked_at=datetime.now(tz=UTC),
                revocation_reason="Test revocation",
            )
        )
        await db_session.flush()

        response = await admin_client.get(
            "/certificates/?cert_status=revoked",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        certs = response.json()
        assert len(certs) == 1
        assert certs[0]["status"] == "revoked"

    async def test_auditor_can_list_certs(self, admin_client: AsyncClient, auditor_token: str):
        """An auditor must be able to list certificates."""
        response = await admin_client.get(
            "/certificates/", headers={"Authorization": f"Bearer {auditor_token}"}
        )
        assert response.status_code == 200

    async def test_regular_user_cannot_list_certs(self, admin_client: AsyncClient, user_token: str):
        """A regular user must not be able to list certificates via the admin API."""
        response = await admin_client.get(
            "/certificates/", headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 403


@pytest.mark.asyncio
class TestRevokeCertificate:
    """Tests for POST /certificates/{id}/revoke."""

    async def test_admin_can_revoke_cert(
        self, admin_client: AsyncClient, admin_token: str, regular_user, db_session
    ):
        """An admin must be able to revoke a certificate — KRL rebuild is mocked."""
        from unittest.mock import AsyncMock, patch

        from bastion.models import CertStatus, SshCertificate

        cert = SshCertificate(
            user_id=regular_user.id,
            serial=50,
            key_id="to-revoke",
            principals='["testuser"]',
            valid_after=datetime.now(tz=UTC),
            valid_before=datetime.now(tz=UTC) + timedelta(hours=8),
            status=CertStatus.ACTIVE,
        )
        db_session.add(cert)
        await db_session.flush()

        # Mock _rebuild_krl so the test doesn't require ssh-keygen or CA files on disk
        with patch("bastion.crypto.ca._rebuild_krl", new_callable=AsyncMock):
            response = await admin_client.post(
                f"/certificates/{cert.id}/revoke",
                json={"reason": "Compromised key"},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert response.status_code == 204

    async def test_revoke_nonexistent_cert_returns_404(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """Revoking a non-existent certificate must return 404."""
        response = await admin_client.post(
            "/certificates/00000000-0000-0000-0000-000000000000/revoke",
            json={"reason": "Test"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    async def test_non_admin_cannot_revoke(
        self, admin_client: AsyncClient, auditor_token: str, regular_user, db_session
    ):
        """An auditor must not be able to revoke a certificate."""
        from bastion.models import CertStatus, SshCertificate

        cert = SshCertificate(
            user_id=regular_user.id,
            serial=51,
            key_id="auditor-revoke-attempt",
            principals='["testuser"]',
            valid_after=datetime.now(tz=UTC),
            valid_before=datetime.now(tz=UTC) + timedelta(hours=8),
            status=CertStatus.ACTIVE,
        )
        db_session.add(cert)
        await db_session.flush()

        response = await admin_client.post(
            f"/certificates/{cert.id}/revoke",
            json={"reason": "Attempt"},
            headers={"Authorization": f"Bearer {auditor_token}"},
        )
        assert response.status_code == 403


@pytest.mark.asyncio
class TestAuditLog:
    """Tests for GET /audit/."""

    async def test_empty_audit_log(self, admin_client: AsyncClient, admin_token: str):
        """Audit log must be empty when no actions have been performed."""
        response = await admin_client.get(
            "/audit/", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_audit_entries_listed(
        self, admin_client: AsyncClient, admin_token: str, db_session
    ):
        """Audit entries must appear in the log."""
        from bastion.audit import audit

        await audit(db_session, "test.action", success=True, ip_address="1.2.3.4")
        await db_session.flush()

        response = await admin_client.get(
            "/audit/", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        entries = response.json()
        assert len(entries) == 1
        assert entries[0]["action"] == "test.action"
        assert entries[0]["success"] is True

    async def test_filter_by_action(self, admin_client: AsyncClient, admin_token: str, db_session):
        """Filtering by action must return only matching entries."""
        from bastion.audit import audit

        await audit(db_session, "auth.login", success=True)
        await audit(db_session, "server.connect", success=True)
        await db_session.flush()

        response = await admin_client.get(
            "/audit/?action=auth.login",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        entries = response.json()
        assert all(e["action"] == "auth.login" for e in entries)

    async def test_filter_failures_only(
        self, admin_client: AsyncClient, admin_token: str, db_session
    ):
        """Filtering by success=false must return only failed actions."""
        from bastion.audit import audit

        await audit(db_session, "auth.login", success=True)
        await audit(db_session, "auth.login", success=False)
        await db_session.flush()

        response = await admin_client.get(
            "/audit/?success=false",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        entries = response.json()
        assert all(e["success"] is False for e in entries)

    async def test_auditor_can_query_audit_log(self, admin_client: AsyncClient, auditor_token: str):
        """An auditor must be able to query the audit log."""
        response = await admin_client.get(
            "/audit/", headers={"Authorization": f"Bearer {auditor_token}"}
        )
        assert response.status_code == 200

    async def test_regular_user_cannot_query_audit_log(
        self, admin_client: AsyncClient, user_token: str
    ):
        """A regular user must not be able to query the audit log."""
        response = await admin_client.get(
            "/audit/", headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 403

    async def test_read_only_cannot_query_audit_log(
        self, admin_client: AsyncClient, read_only_token: str
    ):
        """A read-only user must not be able to query the audit log."""
        response = await admin_client.get(
            "/audit/", headers={"Authorization": f"Bearer {read_only_token}"}
        )
        assert response.status_code == 403
