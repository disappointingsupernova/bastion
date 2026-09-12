"""Unit tests for compliance — PDF generation, cert history, and email_report."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest

from bastion.compliance import (
    _rows_to_pdf,
    build_report,
    email_report,
    generate_cert_history,
)
from bastion.models import (
    CertStatus,
    SshCertificate,
    User,
    UserRole,
    UserStatus,
)


def _make_user(username: str) -> User:
    return User(
        username=username,
        email=f"{username}@example.com",
        hashed_password="x",
        role=UserRole.USER,
        status=UserStatus.ACTIVE,
    )


class TestRowsToPdf:
    """Tests for _rows_to_pdf."""

    def test_empty_rows_returns_bytes(self):
        """_rows_to_pdf with empty rows must return bytes."""
        result = _rows_to_pdf("Test Report", [])
        assert isinstance(result, bytes)

    def test_non_empty_rows_returns_bytes(self):
        """_rows_to_pdf with data must return non-empty bytes."""
        rows = [{"username": "alice", "server": "web01"}]
        result = _rows_to_pdf("Access Matrix", rows)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_falls_back_to_csv_when_reportlab_missing(self):
        """_rows_to_pdf must fall back to CSV when reportlab is not installed."""
        import builtins

        rows = [{"username": "alice", "server": "web01"}]
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name.startswith("reportlab"):
                raise ImportError("No module named 'reportlab'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = _rows_to_pdf("Test", rows)

        # Falls back to CSV bytes
        assert isinstance(result, bytes)


@pytest.mark.asyncio
class TestGenerateCertHistory:
    """Tests for generate_cert_history."""

    async def test_empty_db_returns_empty_list(self, db_session):
        """With no certificates, the history must be empty."""
        result = await generate_cert_history(db_session)
        assert result == []

    async def test_cert_within_window_appears(self, db_session):
        """A certificate issued within the days window must appear in the history."""
        user = _make_user("alice")
        db_session.add(user)
        await db_session.flush()

        now = datetime.now(tz=UTC)
        cert = SshCertificate(
            user_id=user.id,
            serial=1,
            key_id="bastion-1",
            principals='["alice"]',
            valid_after=now,
            valid_before=now + timedelta(hours=8),
            status=CertStatus.ACTIVE,
            issued_from_ip="1.2.3.4",
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        db_session.add(cert)
        await db_session.flush()

        result = await generate_cert_history(db_session, days=30)
        assert len(result) == 1
        assert result[0]["username"] == "alice"
        assert result[0]["serial"] == 1
        assert result[0]["issued_from_ip"] == "1.2.3.4"

    async def test_cert_outside_window_excluded(self, db_session):
        """A certificate issued outside the days window must be excluded."""
        user = _make_user("bob")
        db_session.add(user)
        await db_session.flush()

        old_time = datetime.now(tz=UTC) - timedelta(days=60)
        cert = SshCertificate(
            user_id=user.id,
            serial=2,
            key_id="bastion-2",
            principals='["bob"]',
            valid_after=old_time,
            valid_before=old_time + timedelta(hours=8),
            status=CertStatus.ACTIVE,
            created_at=old_time,
            updated_at=old_time,
        )
        db_session.add(cert)
        await db_session.flush()

        result = await generate_cert_history(db_session, days=30)
        assert result == []

    async def test_cert_with_no_ip_shows_empty_string(self, db_session):
        """A certificate with no issued_from_ip must show an empty string."""
        user = _make_user("carol")
        db_session.add(user)
        await db_session.flush()

        now = datetime.now(tz=UTC)
        cert = SshCertificate(
            user_id=user.id,
            serial=3,
            key_id="bastion-3",
            principals='["carol"]',
            valid_after=now,
            valid_before=now + timedelta(hours=8),
            status=CertStatus.ACTIVE,
            issued_from_ip=None,
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        db_session.add(cert)
        await db_session.flush()

        result = await generate_cert_history(db_session, days=30)
        assert result[0]["issued_from_ip"] == ""


@pytest.mark.asyncio
class TestBuildReportPdf:
    """Tests for build_report with PDF format."""

    async def test_pdf_format_returns_pdf_filename(self, db_session):
        """A PDF report must return a .pdf filename."""
        content, filename = await build_report(db_session, "access_matrix", fmt="pdf")
        assert filename.endswith(".pdf")
        assert "access_matrix" in filename

    async def test_pdf_format_returns_bytes(self, db_session):
        """A PDF report must return bytes."""
        content, filename = await build_report(db_session, "access_matrix", fmt="pdf")
        assert isinstance(content, bytes)


@pytest.mark.asyncio
class TestEmailReport:
    """Tests for email_report."""

    async def test_raises_when_no_email_transport_configured(self, db_session):
        """email_report must raise RuntimeError when neither SMTP nor SES is configured."""
        with patch("bastion.config.get_settings") as mock_settings:
            s = mock_settings.return_value
            s.smtp_host = None
            s.ses_region = None
            s.smtp_from_address = None
            s.ses_from_address = None
            s.smtp_port = 587
            s.smtp_username = None
            s.smtp_password = None
            s.smtp_use_tls = False

            with pytest.raises(RuntimeError, match="No email transport configured"):
                await email_report(db_session, "access_matrix", "csv", "admin@example.com")

    async def test_sends_via_smtp_when_configured(self, db_session):
        """email_report must call aiosmtplib.send when SMTP is configured."""
        with patch("bastion.config.get_settings") as mock_settings:
            s = mock_settings.return_value
            s.smtp_host = "smtp.example.com"
            s.ses_region = None
            s.smtp_from_address = "from@example.com"
            s.ses_from_address = None
            s.smtp_port = 587
            s.smtp_username = "user"
            s.smtp_password = "pass"
            s.smtp_use_tls = True

            with patch("aiosmtplib.send", new_callable=AsyncMock) as mock_send:
                await email_report(db_session, "access_matrix", "csv", "admin@example.com")
                mock_send.assert_called_once()
