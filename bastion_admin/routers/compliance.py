"""Admin compliance router — generate and deliver compliance reports."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.audit import audit
from bastion.compliance import build_report, email_report
from bastion.db import get_db
from bastion.logging import get_logger
from bastion.models import User, UserRole
from bastion_api.deps import require_role

log = get_logger(__name__)
router = APIRouter(prefix="/compliance", tags=["Compliance"])

_admin_or_auditor = require_role(UserRole.ADMIN, UserRole.AUDITOR)

_REPORT_TYPES = {"access_matrix", "sessions", "cert_history", "failed_auth"}


class EmailReportRequest(BaseModel):
    report_type: str
    fmt: Literal["csv", "pdf"] = "csv"
    recipient: EmailStr
    days: int = 30


@router.get("/reports/{report_type}")
async def download_report(
    report_type: str,
    current_user: Annotated[User, Depends(_admin_or_auditor)],
    db: Annotated[AsyncSession, Depends(get_db)],
    fmt: Literal["csv", "pdf"] = "csv",
    days: int = 30,
) -> Response:
    """Generate and download a compliance report.

    report_type: access_matrix | sessions | cert_history | failed_auth
    fmt: csv | pdf
    days: lookback window in days (default 30, ignored for access_matrix)
    """
    if report_type not in _REPORT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown report type. Valid types: {sorted(_REPORT_TYPES)}",
        )

    try:
        content, filename = await build_report(db, report_type, fmt, days)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    await audit(
        db,
        "admin.compliance.report.download",
        success=True,
        user_id=current_user.id,
        detail={"report_type": report_type, "fmt": fmt, "days": days},
    )

    media_type = "application/pdf" if fmt == "pdf" else "text/csv"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/reports/email", status_code=status.HTTP_202_ACCEPTED)
async def email_report_endpoint(
    body: EmailReportRequest,
    current_user: Annotated[User, Depends(_admin_or_auditor)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Generate a compliance report and deliver it by email."""
    if body.report_type not in _REPORT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown report type. Valid types: {sorted(_REPORT_TYPES)}",
        )

    try:
        await email_report(db, body.report_type, body.fmt, body.recipient, body.days)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    await audit(
        db,
        "admin.compliance.report.email",
        success=True,
        user_id=current_user.id,
        detail={"report_type": body.report_type, "fmt": body.fmt, "recipient": body.recipient},
    )
    return {"message": f"Report queued for delivery to {body.recipient}."}
