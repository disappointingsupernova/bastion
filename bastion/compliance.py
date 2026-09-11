"""Compliance report generation — user access matrix, session summaries, cert history, failed auth.

Supports CSV and PDF output. Reports can be delivered by email via the configured
SMTP/SES channel. PDF generation uses reportlab if available, falling back to CSV.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.logging import get_logger
from bastion.models import (
    AuditLog,
    Server,
    ServerAccess,
    Session,
    SshCertificate,
    User,
    UserStatus,
)

log = get_logger(__name__)

ReportFormat = Literal["csv", "pdf"]


async def generate_access_matrix(db: AsyncSession) -> list[dict]:
    """Return the user-server access matrix as a list of row dicts."""
    result = await db.execute(
        select(User.username, Server.hostname, ServerAccess.allow_sudo, ServerAccess.expires_at)
        .join(ServerAccess, User.id == ServerAccess.user_id)
        .join(Server, Server.id == ServerAccess.server_id)
        .where(
            ServerAccess.revoked_at.is_(None),
            User.deleted_at.is_(None),
            Server.deleted_at.is_(None),
        )
        .order_by(User.username, Server.hostname)
    )
    return [
        {
            "username": row[0],
            "server": row[1],
            "sudo": "yes" if row[2] else "no",
            "expires_at": row[3].isoformat() if row[3] else "never",
        }
        for row in result.all()
    ]


async def generate_sessions_report(
    db: AsyncSession, days: int = 30
) -> list[dict]:
    """Return session counts per server per period."""
    since = datetime.now(tz=UTC) - timedelta(days=days)
    result = await db.execute(
        select(
            Server.hostname,
            func.count(Session.id).label("session_count"),
            func.sum(Session.bytes_sent + Session.bytes_received).label("total_bytes"),
        )
        .join(Session, Session.server_id == Server.id)
        .where(Session.started_at >= since)
        .group_by(Server.hostname)
        .order_by(func.count(Session.id).desc())
    )
    return [
        {
            "server": row[0],
            "session_count": row[1],
            "total_bytes": row[2] or 0,
        }
        for row in result.all()
    ]


async def generate_cert_history(
    db: AsyncSession, days: int = 30
) -> list[dict]:
    """Return certificate issuance history for the period."""
    since = datetime.now(tz=UTC) - timedelta(days=days)
    result = await db.execute(
        select(User.username, SshCertificate.serial, SshCertificate.status,
               SshCertificate.valid_after, SshCertificate.valid_before,
               SshCertificate.issued_from_ip)
        .join(User, User.id == SshCertificate.user_id)
        .where(SshCertificate.created_at >= since)
        .order_by(SshCertificate.created_at.desc())
    )
    return [
        {
            "username": row[0],
            "serial": row[1],
            "status": row[2],
            "valid_after": row[3].isoformat() if row[3] else "",
            "valid_before": row[4].isoformat() if row[4] else "",
            "issued_from_ip": row[5] or "",
        }
        for row in result.all()
    ]


async def generate_failed_auth_summary(
    db: AsyncSession, days: int = 30
) -> list[dict]:
    """Return failed authentication summary grouped by username."""
    since = datetime.now(tz=UTC) - timedelta(days=days)
    result = await db.execute(
        select(
            AuditLog.user_id,
            User.username,
            func.count(AuditLog.id).label("failed_count"),
        )
        .outerjoin(User, User.id == AuditLog.user_id)
        .where(
            AuditLog.action == "auth.login",
            AuditLog.success == False,  # noqa: E712
            AuditLog.created_at >= since,
        )
        .group_by(AuditLog.user_id, User.username)
        .order_by(func.count(AuditLog.id).desc())
    )
    return [
        {"user_id": row[0] or "", "username": row[1] or "unknown", "failed_count": row[2]}
        for row in result.all()
    ]


def _rows_to_csv(rows: list[dict]) -> bytes:
    """Serialise a list of dicts to CSV bytes."""
    if not rows:
        return b""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue().encode()


def _rows_to_pdf(title: str, rows: list[dict]) -> bytes:
    """Serialise a list of dicts to a simple PDF using reportlab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
    except ImportError:
        log.warning("reportlab not installed — falling back to CSV for PDF report")
        return _rows_to_csv(rows)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4))
    if not rows:
        doc.build([])
        return buf.getvalue()

    headers = list(rows[0].keys())
    data = [headers] + [[str(r.get(h, "")) for h in headers] for r in rows]
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
    ]))
    doc.build([table])
    return buf.getvalue()


async def build_report(
    db: AsyncSession,
    report_type: str,
    fmt: ReportFormat = "csv",
    days: int = 30,
) -> tuple[bytes, str]:
    """Build a compliance report and return (content_bytes, filename).

    report_type: one of access_matrix, sessions, cert_history, failed_auth
    """
    generators = {
        "access_matrix": (generate_access_matrix, {}),
        "sessions": (generate_sessions_report, {"days": days}),
        "cert_history": (generate_cert_history, {"days": days}),
        "failed_auth": (generate_failed_auth_summary, {"days": days}),
    }
    if report_type not in generators:
        raise ValueError(f"Unknown report type: {report_type!r}")

    fn, kwargs = generators[report_type]
    rows = await fn(db, **kwargs)  # type: ignore[call-arg]

    ts = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
    if fmt == "pdf":
        content = _rows_to_pdf(report_type.replace("_", " ").title(), rows)
        filename = f"bastion_{report_type}_{ts}.pdf"
        mime = "application/pdf"
    else:
        content = _rows_to_csv(rows)
        filename = f"bastion_{report_type}_{ts}.csv"
        mime = "text/csv"

    log.info("Compliance report generated", report_type=report_type, fmt=fmt, rows=len(rows))
    return content, filename


async def email_report(
    db: AsyncSession,
    report_type: str,
    fmt: ReportFormat,
    recipient: str,
    days: int = 30,
) -> None:
    """Generate a compliance report and deliver it by email."""
    import email.mime.base
    import email.mime.multipart
    import email.mime.text

    import aiosmtplib

    from bastion.config import get_settings

    settings = get_settings()
    if not settings.smtp_host and not settings.ses_region:
        raise RuntimeError("No email transport configured (SMTP_HOST or SES_REGION required).")

    content, filename = await build_report(db, report_type, fmt, days)
    mime = "application/pdf" if fmt == "pdf" else "text/csv"

    msg = email.mime.multipart.MIMEMultipart()
    msg["Subject"] = f"[Bastion] Compliance report: {report_type} ({fmt.upper()})"
    msg["From"] = settings.smtp_from_address or settings.ses_from_address or "bastion@localhost"
    msg["To"] = recipient
    msg.attach(email.mime.text.MIMEText(
        f"Please find the {report_type} compliance report attached.\n\nGenerated: {datetime.now(tz=UTC).isoformat()}"
    ))

    attachment = email.mime.base.MIMEBase(*mime.split("/"))
    attachment.set_payload(content)
    import email.encoders
    email.encoders.encode_base64(attachment)
    attachment.add_header("Content-Disposition", "attachment", filename=filename)
    msg.attach(attachment)

    if settings.smtp_host:
        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password,
            use_tls=settings.smtp_use_tls,
        )
        log.info("Compliance report emailed", report_type=report_type, recipient=recipient)
