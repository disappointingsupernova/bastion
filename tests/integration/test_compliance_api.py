"""Integration tests for the compliance report endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestComplianceReportDownload:
    """Tests for GET /compliance/reports/{report_type}."""

    async def test_admin_can_download_access_matrix_csv(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """An admin must be able to download the access matrix as CSV."""
        response = await admin_client.get(
            "/compliance/reports/access_matrix",
            params={"fmt": "csv"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        assert "access_matrix" in response.headers["content-disposition"]

    async def test_admin_can_download_sessions_report(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """An admin must be able to download the sessions report."""
        response = await admin_client.get(
            "/compliance/reports/sessions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200

    async def test_admin_can_download_cert_history(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """An admin must be able to download the certificate history report."""
        response = await admin_client.get(
            "/compliance/reports/cert_history",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200

    async def test_admin_can_download_failed_auth_report(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """An admin must be able to download the failed auth summary."""
        response = await admin_client.get(
            "/compliance/reports/failed_auth",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200

    async def test_auditor_can_download_reports(
        self, admin_client: AsyncClient, auditor_token: str
    ):
        """An auditor must be able to download compliance reports."""
        response = await admin_client.get(
            "/compliance/reports/access_matrix",
            headers={"Authorization": f"Bearer {auditor_token}"},
        )
        assert response.status_code == 200

    async def test_regular_user_cannot_download_reports(
        self, admin_client: AsyncClient, user_token: str
    ):
        """A regular user must receive 403."""
        response = await admin_client.get(
            "/compliance/reports/access_matrix",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_unknown_report_type_returns_400(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """An unknown report type must return 400."""
        response = await admin_client.get(
            "/compliance/reports/nonexistent_type",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 400

    async def test_csv_content_has_correct_headers_for_access_matrix(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        regular_user,
        test_server,
        server_access,
    ):
        """The access matrix CSV must contain the expected column headers."""
        response = await admin_client.get(
            "/compliance/reports/access_matrix",
            params={"fmt": "csv"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        content = response.content.decode()
        assert "username" in content
        assert "server" in content
        assert "sudo" in content

    async def test_days_parameter_respected(self, admin_client: AsyncClient, admin_token: str):
        """The days parameter must be accepted without error."""
        response = await admin_client.get(
            "/compliance/reports/sessions",
            params={"days": 7},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200

    async def test_unauthenticated_returns_401(self, admin_client: AsyncClient):
        """An unauthenticated request must return 401."""
        response = await admin_client.get("/compliance/reports/access_matrix")
        assert response.status_code == 401


@pytest.mark.asyncio
class TestComplianceReportEmail:
    """Tests for POST /compliance/reports/email."""

    async def test_missing_smtp_returns_503(self, admin_client: AsyncClient, admin_token: str):
        """When no email transport is configured, the endpoint must return 503."""
        response = await admin_client.post(
            "/compliance/reports/email",
            json={
                "report_type": "access_matrix",
                "fmt": "csv",
                "recipient": "admin@example.com",
                "days": 30,
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        # No SMTP configured in test environment
        assert response.status_code == 503

    async def test_unknown_report_type_returns_400(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """An unknown report type must return 400."""
        response = await admin_client.post(
            "/compliance/reports/email",
            json={
                "report_type": "bad_type",
                "fmt": "csv",
                "recipient": "admin@example.com",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 400

    async def test_invalid_email_returns_422(self, admin_client: AsyncClient, admin_token: str):
        """An invalid recipient email must return 422."""
        response = await admin_client.post(
            "/compliance/reports/email",
            json={
                "report_type": "access_matrix",
                "fmt": "csv",
                "recipient": "not-an-email",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 422
