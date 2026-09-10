"""Authentication — JWT tokens, password hashing, TOTP, and email MFA codes."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

import bcrypt
import pyotp
from jose import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.config import get_settings
from bastion.logging import get_logger
from bastion.models import MfaCode, User, UserStatus

log = get_logger(__name__)

BCRYPT_ROUNDS = 12


# ── Password hashing ──────────────────────────────────────────────────────────


def hash_password(plaintext: str) -> str:
    """Hash a plaintext password using bcrypt with a cost factor of 12."""
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()


def verify_password(plaintext: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(plaintext.encode(), hashed.encode())


# ── JWT ───────────────────────────────────────────────────────────────────────


def create_access_token(user_id: str, username: str, role: str) -> str:
    """Issue a signed JWT access token for the given user."""
    settings = get_settings()
    expire = datetime.now(tz=UTC) + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": expire,
        "iat": datetime.now(tz=UTC),
        "type": "access",
    }
    token: str = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token


def create_refresh_token(user_id: str) -> str:
    """Issue a signed JWT refresh token for the given user."""
    settings = get_settings()
    expire = datetime.now(tz=UTC) + timedelta(days=settings.jwt_refresh_token_expire_days)
    payload = {
        "sub": user_id,
        "exp": expire,
        "iat": datetime.now(tz=UTC),
        "type": "refresh",
    }
    token: str = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token


def decode_token(token: str) -> dict:  # type: ignore[type-arg]
    """Decode and validate a JWT token. Raises JWTError on failure."""
    settings = get_settings()
    result: dict = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    return result


# ── TOTP ──────────────────────────────────────────────────────────────────────


def generate_totp_secret() -> str:
    """Generate a new TOTP secret key."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    """Return the otpauth:// URI for QR code generation."""
    settings = get_settings()
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=settings.totp_issuer,
    )


def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code against the given secret. Allows a 30-second window."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


# ── Email MFA codes ───────────────────────────────────────────────────────────


def _hash_code(code: str, user_id: str) -> str:
    """Hash an MFA code keyed to the user_id using HMAC-SHA256.

    Keying the hash to user_id means a precomputed table of all 900,000
    possible 6-digit codes cannot be used across users (fix #12).
    """
    return hmac.new(
        user_id.encode(),
        code.encode(),
        digestmod="sha256",
    ).hexdigest()


async def create_email_mfa_code(db: AsyncSession, user_id: str) -> str:
    """Generate a 6-digit email MFA code, store its HMAC, and return the plaintext code."""
    settings = get_settings()
    code = str(secrets.randbelow(900_000) + 100_000)  # 100000–999999
    expires_at = datetime.now(tz=UTC) + timedelta(minutes=settings.mfa_email_code_expire_minutes)
    entry = MfaCode(
        user_id=user_id,
        code_hash=_hash_code(code, user_id),
        expires_at=expires_at,
    )
    db.add(entry)
    await db.flush()
    log.debug("Email MFA code created", user_id=user_id)
    return code


async def verify_email_mfa_code(db: AsyncSession, user_id: str, code: str) -> bool:
    """Verify an email MFA code. Marks it as used on success. Returns True if valid."""
    now = datetime.now(tz=UTC)
    result = await db.execute(
        select(MfaCode).where(
            MfaCode.user_id == user_id,
            MfaCode.code_hash == _hash_code(code, user_id),
            MfaCode.used == False,  # noqa: E712
            MfaCode.expires_at > now,
        )
    )
    entry = result.scalar_one_or_none()
    if entry is None:
        log.warning("Invalid or expired email MFA code", user_id=user_id)
        return False

    entry.used = True
    await db.flush()
    log.info("Email MFA code verified successfully", user_id=user_id)
    return True


# ── User lookup ───────────────────────────────────────────────────────────────


async def get_active_user(db: AsyncSession, user_id: str) -> User | None:
    """Fetch an active, non-deleted user by ID."""
    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.status == UserStatus.ACTIVE,
            User.deleted_at.is_(None),
        )
    )
    return result.scalar_one_or_none()
