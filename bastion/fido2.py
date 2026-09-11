"""FIDO2 / WebAuthn MFA — phishing-resistant hardware key authentication.

Credentials are stored encrypted in the user's fido2_credentials column as a
JSON list of credential dicts. The challenge state is passed as a short-lived
signed JWT so no server-side session storage is required.
"""

from __future__ import annotations

import json
import time
from typing import Any

import jwt
from fastapi import HTTPException, status
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationObject,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.crypto.encryption import decrypt_secret, encrypt_secret
from bastion.logging import get_logger
from bastion.models import MfaMethod, User, UserStatus

log = get_logger(__name__)

_RP_ID = "bastion"
_RP_NAME = "Bastion SSH"
_CHALLENGE_TOKEN_EXPIRE = 300  # 5 minutes


def _server() -> Fido2Server:
    """Return a configured Fido2Server instance."""
    rp = PublicKeyCredentialRpEntity(id=_RP_ID, name=_RP_NAME)
    return Fido2Server(rp)


def _load_credentials(user: User, secret_key: str) -> list[dict[str, Any]]:
    """Decrypt and deserialise stored FIDO2 credentials for a user."""
    if not user.fido2_credentials:
        return []
    try:
        return json.loads(decrypt_secret(user.fido2_credentials, secret_key))
    except Exception:
        log.error("Failed to decrypt FIDO2 credentials", user_id=user.id)
        return []


def _save_credentials(user: User, creds: list[dict[str, Any]], secret_key: str) -> None:
    """Serialise and encrypt FIDO2 credentials for storage."""
    user.fido2_credentials = encrypt_secret(json.dumps(creds), secret_key)


def begin_registration(user_id: str, username: str) -> dict[str, Any]:
    """Generate PublicKeyCredentialCreationOptions for a new FIDO2 credential."""
    server = _server()
    user_entity = PublicKeyCredentialUserEntity(
        id=user_id.encode(),
        name=username,
        display_name=username,
    )
    options, _ = server.register_begin(user_entity, user_verification="preferred")
    # Convert to JSON-serialisable dict
    return dict(options)


async def complete_registration(
    db: AsyncSession,
    user: User,
    credential_response: dict[str, Any],
    secret_key: str,
) -> None:
    """Verify the attestation response and store the new credential."""
    server = _server()
    try:
        client_data = CollectedClientData(credential_response["clientDataJSON"])
        att_obj = AttestationObject(credential_response["attestationObject"])
        auth_data = server.register_complete(None, client_data, att_obj)
    except Exception as exc:
        log.warning("FIDO2 registration failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="FIDO2 registration failed — invalid attestation.",
        ) from exc

    creds = _load_credentials(user, secret_key)
    creds.append(
        {
            "credential_id": auth_data.credential_data.credential_id.hex(),
            "public_key": auth_data.credential_data.public_key.__class__.__name__,
            "sign_count": auth_data.counter,
        }
    )
    _save_credentials(user, creds, secret_key)
    user.mfa_method = MfaMethod.FIDO2
    user.mfa_enabled = True
    await db.flush()
    log.info("FIDO2 credential registered", user_id=user.id)


async def begin_authentication(
    db: AsyncSession,
    user: User,
    secret_key: str,
) -> tuple[dict[str, Any], str]:
    """Generate PublicKeyCredentialRequestOptions and a signed state token.

    Returns (options_dict, state_token). The state_token encodes the challenge
    and user_id and must be passed back to complete_authentication.
    """
    creds = _load_credentials(user, secret_key)
    if not creds:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No FIDO2 credentials registered for this account.",
        )

    server = _server()
    options, state = server.authenticate_begin(user_verification="preferred")

    state_token = jwt.encode(
        {
            "sub": user.id,
            "type": "fido2_pending",
            "state": json.dumps(state),
            "exp": int(time.time()) + _CHALLENGE_TOKEN_EXPIRE,
        },
        secret_key,
        algorithm="HS256",
    )
    return dict(options), state_token


async def complete_authentication(
    db: AsyncSession,
    state_token: str,
    credential_response: dict[str, Any],
    secret_key: str,
) -> User:
    """Verify the assertion response and return the authenticated user."""
    try:
        payload = jwt.decode(state_token, secret_key, algorithms=["HS256"])
        if payload.get("type") != "fido2_pending":
            raise ValueError("Invalid token type")
        user_id = payload["sub"]
        state = json.loads(payload["state"])
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired FIDO2 state token.",
        ) from exc

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
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
        )

    creds = _load_credentials(user, secret_key)
    server = _server()

    try:
        client_data = CollectedClientData(credential_response["clientDataJSON"])
        auth_data = AuthenticatorData(credential_response["authenticatorData"])
        signature = bytes.fromhex(credential_response["signature"])
        credential_id = bytes.fromhex(credential_response["credentialId"])

        server.authenticate_complete(
            state,
            [bytes.fromhex(c["credential_id"]) for c in creds],
            credential_id,
            client_data,
            auth_data,
            signature,
        )
    except Exception as exc:
        log.warning("FIDO2 authentication failed", user_id=user_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="FIDO2 authentication failed.",
        ) from exc

    # Update sign count
    for cred in creds:
        if cred["credential_id"] == credential_id.hex():
            cred["sign_count"] = auth_data.counter
    _save_credentials(user, creds, secret_key)
    await db.flush()

    log.info("FIDO2 authentication successful", user_id=user.id)
    return user
