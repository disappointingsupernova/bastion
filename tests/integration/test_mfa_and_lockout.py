"""Integration tests for TOTP MFA setup, MFA login flow, account lockout, and dual-approvals."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestTotpSetupAndVerify:
    """Tests for /auth/totp/setup and /auth/totp/verify."""

    async def test_totp_setup_returns_secret_and_uri(
        self, api_client: AsyncClient, user_token: str
    ):
        """TOTP setup must return a secret and provisioning URI."""
        response = await api_client.post(
            "/auth/totp/setup",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "secret" in data
        assert "uri" in data
        assert "otpauth://" in data["uri"]

    async def test_totp_verify_with_valid_code_activates_mfa(
        self,
        api_client: AsyncClient,
        user_token: str,
        regular_user,
        db_session,
    ):
        """Verifying a valid TOTP code must set mfa_enabled=True."""
        import pyotp

        from bastion.config import get_settings
        from bastion.crypto.encryption import decrypt_secret

        # Setup TOTP
        await api_client.post(
            "/auth/totp/setup",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        await db_session.refresh(regular_user)

        # Generate a valid code
        settings = get_settings()
        secret = decrypt_secret(regular_user.totp_secret, settings.secret_key)
        code = pyotp.TOTP(secret).now()

        response = await api_client.post(
            "/auth/totp/verify",
            json={"code": code},
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 204

        await db_session.refresh(regular_user)
        assert regular_user.mfa_enabled is True

    async def test_totp_verify_with_invalid_code_returns_400(
        self,
        api_client: AsyncClient,
        user_token: str,
    ):
        """An invalid TOTP code must return 400."""
        await api_client.post(
            "/auth/totp/setup",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        response = await api_client.post(
            "/auth/totp/verify",
            json={"code": "000000"},
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 400

    async def test_totp_verify_without_setup_returns_400(
        self, api_client: AsyncClient, user_token: str
    ):
        """Calling verify before setup must return 400."""
        response = await api_client.post(
            "/auth/totp/verify",
            json={"code": "123456"},
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 400


@pytest.mark.asyncio
class TestMfaLoginFlow:
    """Tests for the MFA-gated login flow."""

    async def test_totp_mfa_login_flow(
        self,
        api_client: AsyncClient,
        regular_user,
        db_session,
    ):
        """A user with TOTP MFA enabled must complete the two-step login flow."""
        import pyotp

        from bastion.config import get_settings
        from bastion.crypto.encryption import encrypt_secret
        from bastion.models import MfaMethod

        settings = get_settings()
        secret = pyotp.random_base32()
        regular_user.totp_secret = encrypt_secret(secret, settings.secret_key)
        regular_user.mfa_method = MfaMethod.TOTP
        regular_user.mfa_enabled = True
        await db_session.flush()

        # Step 1: password login returns mfa_token
        login_resp = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        assert login_resp.status_code == 200
        data = login_resp.json()
        assert data.get("mfa_required") is True
        mfa_token = data["mfa_token"]

        # Step 2: verify TOTP code
        code = pyotp.TOTP(secret).now()
        verify_resp = await api_client.post(
            "/auth/mfa/verify",
            json={"mfa_token": mfa_token, "code": code},
        )
        assert verify_resp.status_code == 200
        assert "access_token" in verify_resp.json()

    async def test_mfa_verify_with_wrong_code_returns_401(
        self,
        api_client: AsyncClient,
        regular_user,
        db_session,
    ):
        """An incorrect TOTP code at the MFA verify step must return 401."""
        import pyotp

        from bastion.config import get_settings
        from bastion.crypto.encryption import encrypt_secret
        from bastion.models import MfaMethod

        settings = get_settings()
        secret = pyotp.random_base32()
        regular_user.totp_secret = encrypt_secret(secret, settings.secret_key)
        regular_user.mfa_method = MfaMethod.TOTP
        regular_user.mfa_enabled = True
        await db_session.flush()

        login_resp = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        mfa_token = login_resp.json()["mfa_token"]

        verify_resp = await api_client.post(
            "/auth/mfa/verify",
            json={"mfa_token": mfa_token, "code": "000000"},
        )
        assert verify_resp.status_code == 401

    async def test_mfa_verify_fido2_method_returns_400(
        self,
        api_client: AsyncClient,
        regular_user,
        db_session,
    ):
        """Calling /auth/mfa/verify for a FIDO2 user must return 400 with guidance."""
        import time

        import jwt

        from bastion.config import get_settings
        from bastion.models import MfaMethod

        settings = get_settings()
        regular_user.mfa_method = MfaMethod.FIDO2
        regular_user.mfa_enabled = True
        await db_session.flush()

        mfa_token = jwt.encode(
            {"sub": regular_user.id, "type": "mfa_pending", "exp": int(time.time()) + 300},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )

        response = await api_client.post(
            "/auth/mfa/verify",
            json={"mfa_token": mfa_token, "code": "123456"},
        )
        assert response.status_code == 400
        assert "fido2" in response.json()["detail"].lower()

    async def test_expired_mfa_token_returns_401(self, api_client: AsyncClient):
        """An expired MFA token must return 401."""
        import time

        import jwt

        from bastion.config import get_settings

        settings = get_settings()
        expired_token = jwt.encode(
            {"sub": "some-id", "type": "mfa_pending", "exp": int(time.time()) - 10},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )

        response = await api_client.post(
            "/auth/mfa/verify",
            json={"mfa_token": expired_token, "code": "123456"},
        )
        assert response.status_code == 401


@pytest.mark.asyncio
class TestAccountLockout:
    """Tests for the account lockout mechanism."""

    async def test_account_locked_after_10_failures(
        self, api_client: AsyncClient, regular_user, db_session
    ):
        """After 10 failed logins the account must be locked and return 429."""
        for _ in range(10):
            await api_client.post(
                "/auth/login",
                json={"username": "testuser", "password": "wrong-password"},
            )

        response = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        assert response.status_code == 429

    async def test_failed_count_increments(self, api_client: AsyncClient, regular_user, db_session):
        """Each failed login must increment failed_login_count."""
        await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "wrong"},
        )
        await db_session.refresh(regular_user)
        assert regular_user.failed_login_count == 1

    async def test_successful_login_resets_failed_count(
        self, api_client: AsyncClient, regular_user, db_session
    ):
        """A successful login must reset failed_login_count to 0."""
        await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "wrong"},
        )
        await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        await db_session.refresh(regular_user)
        assert regular_user.failed_login_count == 0


@pytest.mark.asyncio
class TestDualApprovalAdminEndpoints:
    """Tests for the admin dual-approval router."""

    async def test_admin_can_list_dual_approvals(self, admin_client: AsyncClient, admin_token: str):
        """An admin must be able to list dual-approval requests."""
        response = await admin_client.get(
            "/dual-approvals/",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    async def test_non_admin_cannot_list_dual_approvals(
        self, admin_client: AsyncClient, user_token: str
    ):
        """A non-admin must receive 403."""
        response = await admin_client.get(
            "/dual-approvals/",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_review_nonexistent_request_returns_400(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """Reviewing a non-existent dual-approval request must return 400."""
        response = await admin_client.post(
            "/dual-approvals/nonexistent-id/review",
            json={"approved": True},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 400

    async def test_filter_by_status(
        self, admin_client: AsyncClient, admin_token: str, db_session, admin_user
    ):
        """Filtering by status must return only matching requests."""
        from bastion.dual_approval import create_dual_approval_request

        await create_dual_approval_request(
            db_session,
            initiated_by=admin_user,
            action_type="test.action",
            action_description="Test",
            action_payload={},
        )
        await db_session.flush()

        response = await admin_client.get(
            "/dual-approvals/",
            params={"req_status": "pending"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        results = response.json()
        assert all(r["status"] == "pending" for r in results)
