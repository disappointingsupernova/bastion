"""Admin certificates router — list and revoke SSH certificates."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.audit import audit
from bastion.crypto.ca import issue_host_certificate, revoke_certificate
from bastion.db import get_db
from bastion.logging import get_logger
from bastion.models import CertStatus, SshCertificate, User, UserRole
from bastion_api.deps import require_role

log = get_logger(__name__)
router = APIRouter(prefix="/certificates", tags=["Certificates"])

_admin = require_role(UserRole.ADMIN)
_admin_or_auditor = require_role(UserRole.ADMIN, UserRole.AUDITOR, UserRole.READ_ONLY)


class CertSummary(BaseModel):
    id: str
    user_id: str
    serial: int
    key_id: str
    principals: str
    valid_after: datetime
    valid_before: datetime
    status: str
    revoked_at: datetime | None
    revocation_reason: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class RevokeRequest(BaseModel):
    reason: str


class HostCertRequest(BaseModel):
    hostname: str
    host_public_key: str  # OpenSSH format host public key
    validity_hours: int | None = None


class HostCertResponse(BaseModel):
    certificate: str
    hostname: str


@router.post("/host", response_model=HostCertResponse)
async def issue_host_cert(
    body: HostCertRequest,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> HostCertResponse:
    """Issue an SSH host certificate for a managed server.

    Host certificates allow servers to prove their identity using the Bastion CA,
    eliminating the known_hosts problem on first connect.
    The certificate is returned in the response and never written to disk.
    """
    try:
        cert_bytes = await issue_host_certificate(
            db=db,
            server_hostname=body.hostname,
            host_public_key_bytes=body.host_public_key.encode(),
            validity_hours=body.validity_hours,
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    await audit(
        db,
        "admin.cert.host.issue",
        success=True,
        user_id=current_user.id,
        resource_type="server",
        detail={"hostname": body.hostname},
    )
    log.info("Host certificate issued", hostname=body.hostname, issued_by=current_user.username)
    return HostCertResponse(certificate=cert_bytes.decode(), hostname=body.hostname)


@router.get("/", response_model=list[CertSummary])
async def list_certificates(
    current_user: Annotated[User, Depends(_admin_or_auditor)],
    db: Annotated[AsyncSession, Depends(get_db)],
    user_id: str | None = None,
    cert_status: CertStatus | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[CertSummary]:
    """List SSH certificates, optionally filtered by user or status."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    query = select(SshCertificate)
    if user_id:
        query = query.where(SshCertificate.user_id == user_id)
    if cert_status:
        query = query.where(SshCertificate.status == cert_status)
    query = query.order_by(SshCertificate.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    return [CertSummary.model_validate(c) for c in result.scalars().all()]


@router.post("/{cert_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_cert(
    cert_id: str,
    body: RevokeRequest,
    current_user: Annotated[User, Depends(_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Revoke an SSH certificate and rebuild the KRL."""
    try:
        await revoke_certificate(db, cert_id, body.reason, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    await audit(
        db,
        "admin.cert.revoke",
        success=True,
        user_id=current_user.id,
        resource_type="certificate",
        resource_id=cert_id,
        detail={"reason": body.reason},
    )
    log.info("Certificate revoked via admin API", cert_id=cert_id, revoked_by=current_user.username)
