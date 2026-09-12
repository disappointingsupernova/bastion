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
        result: list[dict[str, Any]] = json.loads(
            decrypt_secret(user.fido2_credentials, secret_key)
        )
        return result
    except Exception:
        log.error("Failed to decrypt FIDO2 credentials", user_id=user.id)
        return []


def _save_credentials(user: User, creds: list[dict[str, Any]], secret_key: str) -> None:
    """Serialise and encrypt FIDO2 credentials for storage."""
    user.fido2_credentials = encrypt_secret(json.dumps(creds), secret_key)


def begin_registration(user_id: str, username: str, secret_key: str) -> tuple[dict[str, Any], str]:
    """Generate PublicKeyCredentialCreationOptions for a new FIDO2 credential.

    Returns (options_dict, state_token). The state_token encodes the challenge
    and must be passed back to complete_registration to verify attestation binding.
    """
    server = _server()
    user_entity = PublicKeyCredentialUserEntity(
        id=user_id.encode(),
        name=username,
        display_name=username,
    )
    options, state = server.register_begin(user_entity, user_verification="preferred")  # type: ignore[arg-type]
    state_token = jwt.encode(
        {
            "sub": user_id,
            "type": "fido2_reg_pending",
            "state": json.dumps(state),
            "exp": int(time.time()) + _CHALLENGE_TOKEN_EXPIRE,
        },
        secret_key,
        algorithm="HS256",
    )
    return dict(options), state_token  # type: ignore[return-value]


async def complete_registration(
    db: AsyncSession,
    user: User,
    credential_response: dict[str, Any],
    secret_key: str,
    state_token: str,
) -> None:
    """Verify the attestation response and store the new credential.

    The state_token issued by begin_registration is required to verify that the
    attestation response corresponds to the challenge that was issued — preventing
    replay of any valid attestation response.
    """
    try:
        payload = jwt.decode(state_token, secret_key, algorithms=["HS256"])
        if payload.get("type") != "fido2_reg_pending":
            raise ValueError("Invalid token type — expected fido2_reg_pending")
        state = json.loads(payload["state"])
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired FIDO2 registration state token — please restart registration.",
        ) from exc

    server = _server()
    try:
        client_data = CollectedClientData(credential_response["clientDataJSON"])
        att_obj = AttestationObject(credential_response["attestationObject"])
        auth_data = server.register_complete(state, client_data, att_obj)  # type: ignore[call-arg,arg-type]
    except Exception as exc:
        log.warning("FIDO2 registration failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="FIDO2 registration failed — invalid or replayed attestation response.",
        ) from exc

    creds = _load_credentials(user, secret_key)
    creds.append(
        {
            "credential_id": auth_data.credential_data.credential_id.hex(),  # type: ignore[union-attr]
            "public_key": auth_data.credential_data.public_key.__class__.__name__,  # type: ignore[union-attr]
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
    # Pass existing credentials so the authenticator receives allowCredentials
    # guidance on which credential to use.
    fido2_creds = [{"type": "public-key", "id": bytes.fromhex(c["credential_id"])} for c in creds]
    options, state = server.authenticate_begin(fido2_creds, user_verification="preferred")  # type: ignore[arg-type]

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

        server.authenticate_complete(  # type: ignore[call-arg,arg-type,misc]
            state,
            [bytes.fromhex(c["credential_id"]) for c in creds],  # type: ignore[arg-type,misc]
            credential_id,  # type: ignore[arg-type]
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

    # Validate sign count to detect cloned authenticators (required by WebAuthn spec).
    # A sign count of 0 from the authenticator means the device does not support
    # counters — skip validation in that case only.
    for cred in creds:
        if cred["credential_id"] == credential_id.hex():
            stored_count = cred.get("sign_count", 0)
            new_count = auth_data.counter
            if new_count != 0 and new_count <= stored_count:
                log.error(
                    "FIDO2 sign count did not increase — possible cloned authenticator",
                    user_id=user_id,
                    stored_count=stored_count,
                    received_count=new_count,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=(
                        "FIDO2 authentication rejected — sign count did not increase. "
                        "Your authenticator may be cloned. Contact your administrator."
                    ),
                )
            cred["sign_count"] = new_count
            break
    _save_credentials(user, creds, secret_key)
    await db.flush()

    log.info("FIDO2 authentication successful", user_id=user.id)
    return user
