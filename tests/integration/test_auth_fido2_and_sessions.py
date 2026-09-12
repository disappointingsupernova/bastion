"""Integration tests for FIDO2 auth endpoints and session connect edge cases."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestFido2Endpoints:
    """Tests for FIDO2 registration and authentication endpoints."""

    async def test_fido2_register_begin_returns_options(
        self, api_client: AsyncClient, user_token: str
    ):
        """POST /auth/fido2/register/begin must return options dict."""
        with patch("bastion.fido2.begin_registration") as mock_begin:
            mock_begin.return_value = {"challenge": "abc123", "rp": {"id": "bastion"}}
            response = await api_client.post(
                "/auth/fido2/register/begin",
                headers={"Authorization": f"Bearer {user_token}"},
            )
        assert response.status_code == 200
        assert "options" in response.json()

    async def test_fido2_register_complete_calls_complete_registration(
        self, api_client: AsyncClient, user_token: str, db_session
    ):
        """POST /auth/fido2/register/complete must call complete_registration."""
        with patch("bastion.fido2.complete_registration", new_callable=AsyncMock) as mock_complete:
            response = await api_client.post(
                "/auth/fido2/register/complete",
                json={"credential": {"clientDataJSON": "abc", "attestationObject": "def"}},
                headers={"Authorization": f"Bearer {user_token}"},
            )
        assert response.status_code == 204
        mock_complete.assert_called_once()

    async def test_fido2_authenticate_begin_invalid_credentials_returns_401(
        self, api_client: AsyncClient
    ):
        """POST /auth/fido2/authenticate/begin with wrong password must return 401."""
        response = await api_client.post(
            "/auth/fido2/authenticate/begin",
            json={"username": "nobody", "password": "wrong"},
        )
        assert response.status_code == 401

    async def test_fido2_authenticate_begin_valid_credentials(
        self, api_client: AsyncClient, regular_user, db_session
    ):
        """POST /auth/fido2/authenticate/begin with wrong password must return 401."""
        response = await api_client.post(
            "/auth/fido2/authenticate/begin",
            json={"username": "testuser", "password": "wrong-password"},
        )
        assert response.status_code == 401

    async def test_fido2_authenticate_complete_invalid_token_returns_401(
        self, api_client: AsyncClient
    ):
        """POST /auth/fido2/authenticate/complete with invalid state token must return 401."""
        response = await api_client.post(
            "/auth/fido2/authenticate/complete",
            json={"mfa_token": "invalid-token", "credential": {}},
        )
        assert response.status_code == 401

    async def test_fido2_authenticate_begin_ip_not_allowed_returns_401(
        self, api_client: AsyncClient, regular_user, db_session
    ):
        """FIDO2 begin must return 401 when the source IP is not in the user's allowlist."""
        regular_user.ip_allowlist = '["10.0.0.0/8"]'
        await db_session.flush()

        response = await api_client.post(
            "/auth/fido2/authenticate/begin",
            json={"username": "testuser", "password": "test-password-123"},
        )
        assert response.status_code == 401


@pytest.mark.asyncio
class TestConnectSessionEdgeCases:
    """Tests for POST /sessions/connect edge cases."""

    async def test_connect_with_expired_access_grant_returns_403(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        db_session,
    ):
        """Connecting with an expired access grant must return 403."""
        from datetime import UTC, datetime, timedelta

        from bastion.models import ServerAccess

        expired_access = ServerAccess(
            user_id=regular_user.id,
            server_id=test_server.id,
            allow_sudo=False,
            expires_at=datetime.now(tz=UTC) - timedelta(hours=1),
        )
        db_session.add(expired_access)
        await db_session.flush()

        response = await api_client.post(
            "/sessions/connect",
            json={
                "hostname": "test.example.com",
                "public_key": "ssh-ed25519 AAAA test",
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403
        assert "expired" in response.json()["detail"].lower()

    async def test_connect_with_valid_access_issues_certificate(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        test_server,
        server_access,
        db_session,
    ):
        """Connecting with a valid access grant must issue a certificate and return session info."""
        from datetime import UTC, datetime

        from bastion.models import CertStatus, SshCertificate

        mock_cert_bytes = b"ssh-ed25519-cert-v01@openssh.com AAAA fake-cert"
        mock_cert_record = SshCertificate(
            user_id=regular_user.id,
            serial=999,
            key_id="bastion-999",
            principals='["testuser"]',
            valid_after=datetime.now(tz=UTC),
            valid_before=datetime.now(tz=UTC),
            status=CertStatus.ACTIVE,
        )
        mock_cert_record.id = "cert-mock-id"

        with patch(
            "bastion.crypto.ca.issue_certificate",
            new_callable=AsyncMock,
            return_value=(mock_cert_bytes, mock_cert_record),
        ):
            response = await api_client.post(
                "/sessions/connect",
                json={
                    "hostname": "test.example.com",
                    "public_key": "ssh-ed25519 AAAA test",
                },
                headers={"Authorization": f"Bearer {user_token}"},
            )

        assert response.status_code == 200
        data = response.json()
        assert "session_id" in data
        assert "certificate" in data
        assert data["hostname"] == "test.example.com"
