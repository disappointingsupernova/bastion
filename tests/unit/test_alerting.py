"""Unit tests for the alerting module — dispatch routing and channel skip logic."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bastion.alerting import (
    _send_pagerduty,
    _send_pushover,
    _send_slack,
    _send_syslog,
    _send_webhook,
    dispatch_alert,
)
from bastion.models import AlertChannel, AlertConfig, AlertSeverity


def _make_config(
    channel: AlertChannel,
    enabled: bool = True,
    min_severity: AlertSeverity = AlertSeverity.INFO,
    config_json: str | None = None,
) -> AlertConfig:
    return AlertConfig(
        channel=channel,
        enabled=enabled,
        min_severity=min_severity,
        config_json=config_json,
    )


@pytest.mark.asyncio
class TestDispatchAlert:
    """Tests for dispatch_alert routing and severity filtering."""

    async def test_no_enabled_channels_does_nothing(self, db_session):
        """With no enabled alert configs, dispatch_alert must complete silently."""
        await dispatch_alert(db_session, "Test subject", "Test body")

    async def test_disabled_channel_skipped(self, db_session):
        """A disabled channel must not be called."""
        config = _make_config(AlertChannel.SLACK, enabled=False)
        db_session.add(config)
        await db_session.flush()

        with patch("bastion.alerting._send_slack", new_callable=AsyncMock) as mock_send:
            await dispatch_alert(db_session, "subject", "body")
            mock_send.assert_not_called()

    async def test_severity_below_threshold_skipped(self, db_session):
        """An alert with severity below the channel's min_severity must be skipped."""
        config = _make_config(AlertChannel.SLACK, min_severity=AlertSeverity.CRITICAL)
        db_session.add(config)
        await db_session.flush()

        with patch("bastion.alerting._send_slack", new_callable=AsyncMock) as mock_send:
            await dispatch_alert(db_session, "subject", "body", severity=AlertSeverity.WARNING)
            mock_send.assert_not_called()

    async def test_severity_meets_threshold_dispatched(self, db_session):
        """An alert meeting the channel's min_severity must be dispatched."""
        config = _make_config(AlertChannel.SLACK, min_severity=AlertSeverity.WARNING)
        db_session.add(config)
        await db_session.flush()

        with patch("bastion.alerting._send_slack", new_callable=AsyncMock) as mock_send:
            await dispatch_alert(db_session, "subject", "body", severity=AlertSeverity.CRITICAL)
            mock_send.assert_called_once()

    async def test_channel_exception_does_not_propagate(self, db_session):
        """An exception in a channel handler must be caught and logged, not raised."""
        config = _make_config(AlertChannel.SLACK)
        db_session.add(config)
        await db_session.flush()

        with patch(
            "bastion.alerting._send_slack",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Slack down"),
        ):
            # Must not raise
            await dispatch_alert(db_session, "subject", "body")

    async def test_config_json_parsed_and_passed(self, db_session):
        """config_json must be parsed and passed to the channel handler."""
        import json

        config = _make_config(
            AlertChannel.WEBHOOK,
            config_json=json.dumps({"url": "https://example.com/hook"}),
        )
        db_session.add(config)
        await db_session.flush()

        captured: dict = {}

        async def capture_webhook(subject, body, severity, cfg):
            captured.update(cfg)

        with patch("bastion.alerting._send_webhook", side_effect=capture_webhook):
            await dispatch_alert(db_session, "subject", "body")

        assert captured.get("url") == "https://example.com/hook"

    async def test_multiple_channels_all_called(self, db_session):
        """Multiple enabled channels must all be dispatched."""
        db_session.add(_make_config(AlertChannel.SLACK))
        db_session.add(_make_config(AlertChannel.WEBHOOK))
        await db_session.flush()

        with (
            patch("bastion.alerting._send_slack", new_callable=AsyncMock) as mock_slack,
            patch("bastion.alerting._send_webhook", new_callable=AsyncMock) as mock_webhook,
        ):
            await dispatch_alert(db_session, "subject", "body")
            mock_slack.assert_called_once()
            mock_webhook.assert_called_once()


@pytest.mark.asyncio
class TestChannelSkipLogic:
    """Tests for individual channel handlers when configuration is missing."""

    async def test_slack_skips_when_no_url(self):
        """_send_slack must skip silently when no webhook URL is configured."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            mock_settings.return_value.slack_webhook_url = None
            # Must not raise
            await _send_slack("subject", "body", AlertSeverity.WARNING, {})

    async def test_pagerduty_skips_when_no_key(self):
        """_send_pagerduty must skip silently when no integration key is configured."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            mock_settings.return_value.pagerduty_integration_key = None
            await _send_pagerduty("subject", "body", AlertSeverity.WARNING, {})

    async def test_pushover_skips_when_incomplete(self):
        """_send_pushover must skip when app_token or user_key is missing."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            mock_settings.return_value.pushover_app_token = None
            mock_settings.return_value.pushover_user_key = None
            await _send_pushover("subject", "body", AlertSeverity.WARNING, {})

    async def test_webhook_skips_when_no_url(self):
        """_send_webhook must skip silently when no URL is configured."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            mock_settings.return_value.webhook_url = None
            mock_settings.return_value.webhook_secret = None
            await _send_webhook("subject", "body", AlertSeverity.WARNING, {})

    async def test_syslog_skips_when_no_host(self):
        """_send_syslog must skip silently when no host is configured."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            mock_settings.return_value.syslog_host = None
            await _send_syslog("subject", "body", AlertSeverity.WARNING, {})

    async def test_slack_sends_when_url_configured(self):
        """_send_slack must POST to the webhook URL when configured."""
        with patch("bastion.alerting.get_settings") as mock_settings:
            mock_settings.return_value.slack_webhook_url = "https://hooks.slack.com/test"
            with patch("bastion.alerting.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock()
                mock_client_cls.return_value = mock_client
                await _send_slack("subject", "body", AlertSeverity.WARNING, {})
                mock_client.post.assert_called_once()

    async def test_webhook_includes_hmac_signature_when_secret_set(self):
        """_send_webhook must include X-Bastion-Signature header when secret is configured."""
        posted_headers = {}

        async def capture_post(url, content, headers, timeout):
            posted_headers.update(headers)

        with patch("bastion.alerting.get_settings") as mock_settings:
            mock_settings.return_value.webhook_url = "https://example.com/hook"
            mock_settings.return_value.webhook_secret = "my-secret"
            with patch("bastion.alerting.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(side_effect=capture_post)
                mock_client_cls.return_value = mock_client
                await _send_webhook("subject", "body", AlertSeverity.WARNING, {})
                assert "X-Bastion-Signature" in posted_headers
                assert posted_headers["X-Bastion-Signature"].startswith("sha256=")

    async def test_syslog_sends_udp_message(self):
        """_send_syslog must send a UDP datagram when protocol is udp."""
        import socket as _socket

        with patch("bastion.alerting.get_settings") as mock_settings:
            mock_settings.return_value.syslog_host = "siem.example.com"
            mock_settings.return_value.syslog_port = 514
            mock_settings.return_value.syslog_protocol = "udp"
            mock_settings.return_value.syslog_facility = 16
            # Patch socket inside the function's local import
            mock_sock = MagicMock()
            mock_sock.__enter__ = MagicMock(return_value=mock_sock)
            mock_sock.__exit__ = MagicMock(return_value=False)
            with patch("socket.socket", return_value=mock_sock):
                await _send_syslog("subject", "body", AlertSeverity.WARNING, {})
                mock_sock.sendto.assert_called_once()
                args = mock_sock.sendto.call_args[0]
                assert b"bastion" in args[0]
                assert args[1] == ("siem.example.com", 514)
