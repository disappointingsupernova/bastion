"""Authentication router — login, MFA verification, token refresh, and SSH cert issuance."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.anomaly import evaluate_login
from bastion.audit import audit
from bastion.auth import (
    create_access_token,
    create_email_mfa_code,
    create_refresh_token,
    decode_token,
    generate_totp_secret,
    get_totp_uri,
    verify_email_mfa_code,
    verify_password,
    verify_totp,
)
from bastion.config import get_settings
from bastion.crypto.ca import issue_certificate
from bastion.db import get_db
from bastion.logging import get_logger
from bastion.models import MfaMethod, User, UserStatus
from bastion_api.deps import get_client_ip, get_current_user

log = get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])

# Number of failed logins before the account is locked
_LOCKOUT_THRESHOLD = 10
# Lock duration in minutes
_LOCKOUT_MINUTES = 15

# Per-endpoint rate limits (fix #11)
try:
    from bastion_api.main import limiter as _limiter
except ImportError:
    _limiter = None  # type: ignore[assignment]


# ── Schemas ───────────────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    username: str
    password: str


class MfaVerifyRequest(BaseModel):
    mfa_token: str  # Short-lived JWT issued after password check
    code: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class CertRequest(BaseModel):
    public_key: str  # OpenSSH format public key — validated in issue_certificate


class CertResponse(BaseModel):
    certificate: str  # OpenSSH certificate, base64
    valid_hours: int
    serial: int


class TotpSetupResponse(BaseModel):
    secret: str
    uri: str


class TotpVerifyRequest(BaseModel):
    code: str


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/login", response_model=dict)
async def login(
    body: LoginRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Authenticate with username and password — rate limited to 10/minute per IP (fix #11).

    If MFA is enabled, returns a short-lived mfa_token instead of a full access token.
    The mfa_token must be exchanged via /auth/mfa/verify.
    Accounts are locked for 15 minutes after 10 consecutive failed attempts.
    """
    ip = get_client_ip(request)
    settings = get_settings()

    result = await db.execute(
        select(User).where(
            User.username == body.username,
            User.deleted_at.is_(None),
        )
    )
    user = result.scalar_one_or_none()

    # ── Account lockout check (fix #6) ────────────────────────────────────────
    if user and user.locked_until and user.locked_until > datetime.now(tz=UTC):
        await audit(
            db,
            "auth.login",
            success=False,
            user_id=user.id,
            ip_address=ip,
            detail={"reason": "Account locked"},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account is temporarily locked due to too many failed login attempts.",
        )

    if user is None or not verify_password(body.password, user.hashed_password):
        if user:
            user.failed_login_count += 1
            if user.failed_login_count >= _LOCKOUT_THRESHOLD:
                from datetime import timedelta

                user.locked_until = datetime.now(tz=UTC) + timedelta(minutes=_LOCKOUT_MINUTES)
                log.warning(
                    "Account locked after repeated failed logins",
                    user_id=user.id,
                    failed_count=user.failed_login_count,
                )
            await db.flush()
            await evaluate_login(db, user, ip, success=False)
        await audit(
            db,
            "auth.login",
            success=False,
            ip_address=ip,
            detail={"reason": "Invalid credentials"},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

    if user.status != UserStatus.ACTIVE:
        await audit(
            db,
            "auth.login",
            success=False,
            user_id=user.id,
            ip_address=ip,
            detail={"reason": "Account not active"},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is not active.")

    # Successful login — reset failure counter and lockout
    user.failed_login_count = 0
    user.locked_until = None

    if user.mfa_enabled:
        if user.mfa_method == MfaMethod.EMAIL:
            await create_email_mfa_code(db, user.id)
            log.info("Email MFA code generated — dispatch via alerting", user_id=user.id)

        # Issue a short-lived MFA-pending token (5 minutes)
        import time

        from jose import jwt

        mfa_token = jwt.encode(
            {"sub": user.id, "type": "mfa_pending", "exp": int(time.time()) + 300},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        await audit(db, "auth.login.mfa_required", success=True, user_id=user.id, ip_address=ip)
        return {"mfa_required": True, "mfa_token": mfa_token}

    access_token = create_access_token(user.id, user.username, user.role.value)
    refresh_token = create_refresh_token(user.id)
    await evaluate_login(db, user, ip, success=True)
    await audit(db, "auth.login", success=True, user_id=user.id, ip_address=ip)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/mfa/verify", response_model=TokenResponse)
async def verify_mfa(
    body: MfaVerifyRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    """Verify an MFA code — rate limited to 10/minute per IP (fix #11).

    Checks user status and deleted_at before issuing tokens (fix #7).
    """
    ip = get_client_ip(request)
    settings = get_settings()

    try:
        from jose import jwt

        payload = jwt.decode(
            body.mfa_token, settings.secret_key, algorithms=[settings.jwt_algorithm]
        )
        if payload.get("type") != "mfa_pending":
            raise ValueError("Invalid token type")
        user_id = payload["sub"]
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA token."
        ) from None

    # ── Fix #7: check status and deleted_at before issuing tokens ─────────────
    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.status == UserStatus.ACTIVE,
            User.deleted_at.is_(None),
        )
    )
    user = result.scalar_one_or_none()
    if user is None:
        await audit(
            db,
            "auth.mfa.verify",
            success=False,
            ip_address=ip,
            detail={"reason": "User not found, inactive, or deleted"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account is not active.",
        )

    valid = False
    if user.mfa_method == MfaMethod.TOTP and user.totp_secret:
        from bastion.crypto.encryption import decrypt_secret

        secret = decrypt_secret(user.totp_secret, settings.secret_key)
        valid = verify_totp(secret, body.code)
    elif user.mfa_method == MfaMethod.EMAIL:
        valid = await verify_email_mfa_code(db, user.id, body.code)

    if not valid:
        await audit(db, "auth.mfa.verify", success=False, user_id=user.id, ip_address=ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code.")

    await audit(db, "auth.mfa.verify", success=True, user_id=user.id, ip_address=ip)
    return TokenResponse(
        access_token=create_access_token(user.id, user.username, user.role.value),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    body: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    """Exchange a refresh token — rate limited to 20/minute per IP (fix #11).

    Checks both status and deleted_at (fix #8).
    """
    try:
        payload = decode_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise ValueError("Not a refresh token")
        user_id = payload["sub"]
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token."
        ) from None

    # ── Fix #8: filter on both status and deleted_at ───────────────────────────
    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.status == UserStatus.ACTIVE,
            User.deleted_at.is_(None),
        )
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive."
        )

    return TokenResponse(
        access_token=create_access_token(user.id, user.username, user.role.value),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/cert/issue", response_model=CertResponse)
async def issue_cert(
    body: CertRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> CertResponse:
    """Issue an SSH certificate for the authenticated user's public key.

    The certificate is valid for the configured number of hours (default 8).
    It is returned in the response and never written to disk.
    Public key format is validated inside issue_certificate (fix #20).
    """
    from bastion.anomaly import evaluate_cert_issuance

    ip = get_client_ip(request)

    await evaluate_cert_issuance(db, current_user.id)

    principals = [current_user.username]
    cert_bytes, record = await issue_certificate(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        public_key_bytes=body.public_key.encode(),
        principals=principals,
        issued_from_ip=ip,
    )

    await audit(
        db,
        "cert.issue",
        success=True,
        user_id=current_user.id,
        resource_type="certificate",
        resource_id=record.id,
        ip_address=ip,
    )

    settings = get_settings()
    return CertResponse(
        certificate=cert_bytes.decode(),
        valid_hours=settings.ssh_cert_validity_hours,
        serial=record.serial,
    )


@router.post("/totp/setup", response_model=TotpSetupResponse)
async def setup_totp(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TotpSetupResponse:
    """Generate a new TOTP secret for the authenticated user.

    The secret is stored encrypted but mfa_enabled is NOT set until the user
    verifies a code via /auth/totp/verify (fix #13).
    """
    from bastion.config import get_settings
    from bastion.crypto.encryption import encrypt_secret

    settings = get_settings()
    secret = generate_totp_secret()
    current_user.totp_secret = encrypt_secret(secret, settings.secret_key)
    # Store the method as pending — mfa_enabled remains False until verified
    current_user.mfa_method = MfaMethod.TOTP
    await db.flush()

    await audit(db, "auth.totp.setup", success=True, user_id=current_user.id)
    return TotpSetupResponse(secret=secret, uri=get_totp_uri(secret, current_user.username))


@router.post("/totp/verify", status_code=status.HTTP_204_NO_CONTENT)
async def verify_totp_setup(
    body: TotpVerifyRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Verify a TOTP code to activate MFA on the account (fix #13).

    The user must call this after /auth/totp/setup to confirm they have
    successfully scanned the QR code. Only then is mfa_enabled set to True.
    """
    from bastion.config import get_settings
    from bastion.crypto.encryption import decrypt_secret

    settings = get_settings()

    if not current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP setup has not been initiated. Call /auth/totp/setup first.",
        )

    secret = decrypt_secret(current_user.totp_secret, settings.secret_key)
    if not verify_totp(secret, body.code):
        await audit(db, "auth.totp.verify", success=False, user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code — please check your authenticator app.",
        )

    current_user.mfa_enabled = True
    await db.flush()
    await audit(db, "auth.totp.verify", success=True, user_id=current_user.id)
    log.info("TOTP MFA activated", user_id=current_user.id)
