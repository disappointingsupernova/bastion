"""Unit tests for alerting channel send functions — SMTP, SES, syslog TCP, PagerDuty, Pushover."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bastion.alerting import (
    _send,
    _send_pagerduty,
    _send_pushover,
    _send_ses,
    _send_smtp,
    _send_syslog,
    _send_webhook,
)
from bastion.models import AlertChannel, AlertSeverity


@pytest.mark.asyncio
class TestSendSmtp:
    """Tests for _send_smtp."""

    async def test_skips_when_incomplete_config(self):
        """_send_smtp must skip silently when host or addresses are missing."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            s = MagicMock()
            s.smtp_host = None
            s.smtp_port = 587
            s.smtp_username = None
            s.smtp_password = None
            s.smtp_from_address = None
            s.smtp_use_tls = False
            mock_settings.return_value = s
            # Must not raise
            await _send_smtp("subject", "body", AlertSeverity.WARNING, {})

    async def test_skips_when_no_to_address(self):
        """_send_smtp must skip when to_address is not in config."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            s = MagicMock()
            s.smtp_host = "smtp.example.com"
            s.smtp_port = 587
            s.smtp_username = "user"
            s.smtp_password = "pass"
            s.smtp_from_address = "from@example.com"
            s.smtp_use_tls = True
            mock_settings.return_value = s
            # No to_address in config dict
            await _send_smtp("subject", "body", AlertSeverity.WARNING, {})

    async def test_sends_when_fully_configured(self):
        """_send_smtp must call aiosmtplib.send when fully configured."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            s = MagicMock()
            s.smtp_host = "smtp.example.com"
            s.smtp_port = 587
            s.smtp_username = "user"
            s.smtp_password = "pass"
            s.smtp_from_address = "from@example.com"
            s.smtp_use_tls = True
            mock_settings.return_value = s

            with patch("aiosmtplib.send", new_callable=AsyncMock) as mock_send:
                await _send_smtp(
                    "subject",
                    "body",
                    AlertSeverity.CRITICAL,
                    {"to_address": "to@example.com"},
                )
                mock_send.assert_called_once()


@pytest.mark.asyncio
class TestSendSes:
    """Tests for _send_ses."""

    async def test_skips_when_incomplete_config(self):
        """_send_ses must skip silently when region or addresses are missing."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            s = MagicMock()
            s.ses_region = None
            s.ses_from_address = None
            mock_settings.return_value = s
            await _send_ses("subject", "body", AlertSeverity.WARNING, {})

    async def test_sends_when_fully_configured(self):
        """_send_ses must call boto3 send_email when fully configured."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            s = MagicMock()
            s.ses_region = "eu-west-1"
            s.ses_from_address = "from@example.com"
            mock_settings.return_value = s

            mock_boto_client = MagicMock()
            with patch("boto3.client", return_value=mock_boto_client):
                await _send_ses(
                    "subject",
                    "body",
                    AlertSeverity.CRITICAL,
                    {"to_address": "to@example.com"},
                )
                mock_boto_client.send_email.assert_called_once()


@pytest.mark.asyncio
class TestSendPagerduty:
    """Tests for _send_pagerduty."""

    async def test_sends_when_key_configured(self):
        """_send_pagerduty must POST to PagerDuty when integration key is set."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            mock_settings.return_value.pagerduty_integration_key = "test-key-123"

            with patch("bastion.alerting.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock()
                mock_client_cls.return_value = mock_client

                await _send_pagerduty("subject", "body", AlertSeverity.CRITICAL, {})
                mock_client.post.assert_called_once()
                call_args = mock_client.post.call_args
                assert "pagerduty.com" in call_args[0][0]

    async def test_severity_mapping_critical(self):
        """_send_pagerduty must map 'critical' severity correctly."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            mock_settings.return_value.pagerduty_integration_key = "key"

            posted_payload: dict = {}

            async def capture(url, json, timeout):
                posted_payload.update(json)

            with patch("bastion.alerting.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(side_effect=capture)
                mock_client_cls.return_value = mock_client

                await _send_pagerduty("subject", "body", AlertSeverity.CRITICAL, {})

            assert posted_payload["payload"]["severity"] == "critical"


@pytest.mark.asyncio
class TestSendPushover:
    """Tests for _send_pushover."""

    async def test_sends_when_fully_configured(self):
        """_send_pushover must POST to Pushover when app_token and user_key are set."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            s = MagicMock()
            s.pushover_app_token = "app-token"
            s.pushover_user_key = "user-key"
            mock_settings.return_value = s

            with patch("bastion.alerting.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock()
                mock_client_cls.return_value = mock_client

                await _send_pushover("subject", "body", AlertSeverity.CRITICAL, {})
                mock_client.post.assert_called_once()

    async def test_critical_severity_sets_priority_1(self):
        """_send_pushover must set priority=1 for critical severity."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            s = MagicMock()
            s.pushover_app_token = "app-token"
            s.pushover_user_key = "user-key"
            mock_settings.return_value = s

            posted_data: dict = {}

            async def capture(url, data, timeout):
                posted_data.update(data)

            with patch("bastion.alerting.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(side_effect=capture)
                mock_client_cls.return_value = mock_client

                await _send_pushover("subject", "body", AlertSeverity.CRITICAL, {})

            assert posted_data["priority"] == 1


@pytest.mark.asyncio
class TestSendSyslogTcp:
    """Tests for _send_syslog with TCP protocol."""

    async def test_sends_tcp_message(self):
        """_send_syslog must use socket.create_connection for TCP protocol."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            s = MagicMock()
            s.syslog_host = "siem.example.com"
            s.syslog_port = 601
            s.syslog_protocol = "tcp"
            s.syslog_facility = 16
            mock_settings.return_value = s

            mock_sock = MagicMock()
            mock_sock.__enter__ = MagicMock(return_value=mock_sock)
            mock_sock.__exit__ = MagicMock(return_value=False)

            with patch("socket.create_connection", return_value=mock_sock):
                await _send_syslog("subject", "body", AlertSeverity.WARNING, {})
                mock_sock.sendall.assert_called_once()
                sent_bytes = mock_sock.sendall.call_args[0][0]
                assert b"bastion" in sent_bytes


@pytest.mark.asyncio
class TestSendWebhookNoSecret:
    """Tests for _send_webhook without a secret."""

    async def test_sends_without_signature_when_no_secret(self):
        """_send_webhook must not include X-Bastion-Signature when no secret is set."""
        posted_headers: dict = {}

        async def capture(url, content, headers, timeout):
            posted_headers.update(headers)

        with patch("bastion.alerting.get_settings") as mock_settings:
            s = MagicMock()
            s.webhook_url = "https://example.com/hook"
            s.webhook_secret = None
            mock_settings.return_value = s

            with patch("bastion.alerting.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(side_effect=capture)
                mock_client_cls.return_value = mock_client

                await _send_webhook("subject", "body", AlertSeverity.INFO, {})

        assert "X-Bastion-Signature" not in posted_headers


@pytest.mark.asyncio
class TestSendRouter:
    """Tests for the _send routing function."""

    async def test_unknown_channel_does_nothing(self):
        """_send with an unrecognised channel must not raise."""
        # Create a fake channel value not in the handlers dict
        fake_channel = MagicMock()
        fake_channel.__hash__ = lambda self: hash("unknown_channel")
        # Must not raise
        await _send(fake_channel, "subject", "body", AlertSeverity.INFO, {})

    async def test_routes_to_slack_handler(self):
        """_send must route AlertChannel.SLACK to _send_slack."""
        with patch("bastion.alerting._send_slack", new_callable=AsyncMock) as mock_slack:
            await _send(AlertChannel.SLACK, "subject", "body", AlertSeverity.INFO, {})
            mock_slack.assert_called_once()
