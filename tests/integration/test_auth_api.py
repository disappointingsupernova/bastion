"""Integration tests for the authentication API endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestLoginEndpoint:
    """Tests for POST /auth/login."""

    async def test_login_success_no_mfa(self, api_client: AsyncClient, regular_user, db_session):
        """Successful login without MFA must return access and refresh tokens."""
        response = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data.get("mfa_required") is None

    async def test_login_wrong_password(self, api_client: AsyncClient, regular_user):
        """Login with wrong password must return 401."""
        response = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "wrong-password"},
        )
        assert response.status_code == 401

    async def test_login_unknown_user(self, api_client: AsyncClient):
        """Login with unknown username must return 401."""
        response = await api_client.post(
            "/auth/login",
            json={"username": "nobody", "password": "password"},
        )
        assert response.status_code == 401

    async def test_login_suspended_user(self, api_client: AsyncClient, regular_user, db_session):
        """Login with a suspended account must return 403."""
        from bastion.models import UserStatus

        regular_user.status = UserStatus.SUSPENDED
        await db_session.flush()

        response = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        assert response.status_code == 403


@pytest.mark.asyncio
class TestTokenRefresh:
    """Tests for POST /auth/refresh."""

    async def test_refresh_returns_new_access_token(self, api_client: AsyncClient, regular_user):
        """A valid refresh token must return a new access token."""
        from bastion.auth import create_refresh_token

        refresh = create_refresh_token(regular_user.id)

        response = await api_client.post(
            "/auth/refresh",
            json={"refresh_token": refresh},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()

    async def test_invalid_refresh_token_rejected(self, api_client: AsyncClient):
        """An invalid refresh token must return 401."""
        response = await api_client.post(
            "/auth/refresh",
            json={"refresh_token": "not-a-valid-token"},
        )
        assert response.status_code == 401

    async def test_access_token_rejected_as_refresh(self, api_client: AsyncClient, regular_user):
        """An access token must not be accepted as a refresh token."""
        from bastion.auth import create_access_token

        access = create_access_token(
            regular_user.id, regular_user.username, regular_user.role.value
        )

        response = await api_client.post(
            "/auth/refresh",
            json={"refresh_token": access},
        )
        assert response.status_code == 401


@pytest.mark.asyncio
class TestHealthEndpoint:
    """Tests for GET /health."""

    async def test_health_returns_ok(self, api_client: AsyncClient):
        """Health endpoint must return 200 without authentication."""
        response = await api_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_health_does_not_require_auth(self, api_client: AsyncClient):
        """Health endpoint must not require an Authorization header."""
        response = await api_client.get("/health")
        assert response.status_code == 200


@pytest.mark.asyncio
class TestMfaLoginFlow:
    """Tests for the MFA-gated login flow."""

    async def test_totp_mfa_login_two_step_flow(
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

        login_resp = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        assert login_resp.status_code == 200
        data = login_resp.json()
        assert data.get("mfa_required") is True
        mfa_token = data["mfa_token"]

        code = pyotp.TOTP(secret).now()
        verify_resp = await api_client.post(
            "/auth/mfa/verify",
            json={"mfa_token": mfa_token, "code": code},
        )
        assert verify_resp.status_code == 200
        assert "access_token" in verify_resp.json()

    async def test_email_mfa_login_returns_mfa_token(
        self,
        api_client: AsyncClient,
        regular_user,
        db_session,
    ):
        """A user with email MFA enabled must receive an mfa_token on login."""
        from bastion.models import MfaMethod

        regular_user.mfa_method = MfaMethod.EMAIL
        regular_user.mfa_enabled = True
        await db_session.flush()

        response = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        assert response.status_code == 200
        assert response.json().get("mfa_required") is True

    async def test_email_mfa_verify_valid_code_issues_tokens(
        self,
        api_client: AsyncClient,
        regular_user,
        db_session,
    ):
        """A valid email MFA code must complete the login and return tokens."""
        import time

        import jwt

        from bastion.auth import create_email_mfa_code
        from bastion.config import get_settings
        from bastion.models import MfaMethod

        regular_user.mfa_method = MfaMethod.EMAIL
        regular_user.mfa_enabled = True
        await db_session.flush()

        settings = get_settings()
        mfa_token = jwt.encode(
            {"sub": regular_user.id, "type": "mfa_pending", "exp": int(time.time()) + 300},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        code = await create_email_mfa_code(db_session, regular_user.id)
        await db_session.flush()

        response = await api_client.post(
            "/auth/mfa/verify",
            json={"mfa_token": mfa_token, "code": code},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()

    async def test_mfa_verify_wrong_totp_code_returns_401(
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

    async def test_mfa_verify_fido2_method_redirects_to_fido2_endpoint(
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

    async def test_mfa_verify_wrong_token_type_returns_401(self, api_client: AsyncClient):
        """A token with type != mfa_pending must return 401."""
        import time

        import jwt

        from bastion.config import get_settings

        settings = get_settings()
        wrong_token = jwt.encode(
            {"sub": "some-id", "type": "access", "exp": int(time.time()) + 300},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        response = await api_client.post(
            "/auth/mfa/verify",
            json={"mfa_token": wrong_token, "code": "123456"},
        )
        assert response.status_code == 401

    async def test_mfa_verify_deleted_user_returns_401(
        self,
        api_client: AsyncClient,
        regular_user,
        db_session,
    ):
        """MFA verify for a deleted user must return 401."""
        import time
        from datetime import UTC, datetime

        import jwt

        from bastion.config import get_settings
        from bastion.models import UserStatus

        settings = get_settings()
        mfa_token = jwt.encode(
            {"sub": regular_user.id, "type": "mfa_pending", "exp": int(time.time()) + 300},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        regular_user.status = UserStatus.DELETED
        regular_user.deleted_at = datetime.now(tz=UTC)
        await db_session.flush()

        response = await api_client.post(
            "/auth/mfa/verify",
            json={"mfa_token": mfa_token, "code": "123456"},
        )
        assert response.status_code == 401


@pytest.mark.asyncio
class TestAccountLockout:
    """Tests for the account lockout mechanism."""

    async def test_account_locked_after_10_failed_logins(
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

    async def test_failed_login_increments_counter(
        self, api_client: AsyncClient, regular_user, db_session
    ):
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

    async def test_pre_locked_account_returns_429(
        self,
        api_client: AsyncClient,
        regular_user,
        db_session,
    ):
        """An account with locked_until in the future must return 429 immediately."""
        from datetime import UTC, datetime, timedelta

        regular_user.locked_until = datetime.now(tz=UTC) + timedelta(minutes=15)
        await db_session.flush()

        response = await api_client.post(
            "/auth/login",
            json={"username": "testuser", "password": "test-password-123"},
        )
        assert response.status_code == 429


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
        assert "otpauth://" in data["uri"]

    async def test_totp_verify_valid_code_activates_mfa(
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

        await api_client.post(
            "/auth/totp/setup",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        await db_session.refresh(regular_user)

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

    async def test_totp_verify_invalid_code_returns_400(
        self, api_client: AsyncClient, user_token: str
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
        """Calling /auth/totp/verify before /auth/totp/setup must return 400."""
        response = await api_client.post(
            "/auth/totp/verify",
            json={"code": "123456"},
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 400


@pytest.mark.asyncio
class TestProtectedEndpoints:
    """Tests that protected endpoints reject unauthenticated requests."""

    async def test_sessions_requires_auth(self, api_client: AsyncClient):
        """GET /sessions/ must return 401 without a token."""
        response = await api_client.get("/sessions/")
        assert response.status_code == 401

    async def test_cert_issue_requires_auth(self, api_client: AsyncClient):
        """POST /auth/cert/issue must return 401 without a token."""
        response = await api_client.post(
            "/auth/cert/issue",
            json={"public_key": "ssh-ed25519 AAAA test"},
        )
        assert response.status_code == 401
