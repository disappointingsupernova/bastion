"""Alerting module — dispatches notifications via SMTP, SES, Slack, PagerDuty, and Pushover."""

from __future__ import annotations

import json

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.config import get_settings
from bastion.logging import get_logger
from bastion.models import AlertChannel, AlertConfig, AlertSeverity

log = get_logger(__name__)


async def dispatch_alert(
    db: AsyncSession,
    subject: str,
    body: str,
    severity: AlertSeverity = AlertSeverity.WARNING,
) -> None:
    """Dispatch an alert to all enabled channels that meet the severity threshold."""
    result = await db.execute(
        select(AlertConfig).where(AlertConfig.enabled == True)  # noqa: E712
    )
    configs = result.scalars().all()

    severity_order = [AlertSeverity.INFO, AlertSeverity.WARNING, AlertSeverity.CRITICAL]

    for config in configs:
        if severity_order.index(severity) < severity_order.index(config.min_severity):
            continue
        try:
            from bastion.config import get_settings
            from bastion.crypto.encryption import decrypt_secret

            settings = get_settings()
            if config.config_json:
                try:
                    channel_config = json.loads(
                        decrypt_secret(config.config_json, settings.secret_key)
                    )
                except Exception:
                    # Fall back to treating as unencrypted JSON for backwards compatibility
                    # with records created before encryption was enforced.
                    channel_config = json.loads(config.config_json)
            else:
                channel_config = {}
            await _send(config.channel, subject, body, severity, channel_config)
        except Exception as exc:
            log.error(
                "Alert dispatch failed",
                channel=config.channel,
                error=str(exc),
            )


async def _send(
    channel: AlertChannel,
    subject: str,
    body: str,
    severity: AlertSeverity,
    config: dict,
) -> None:
    """Route an alert to the appropriate channel handler."""
    handlers = {
        AlertChannel.EMAIL: _send_smtp,
        AlertChannel.SES: _send_ses,
        AlertChannel.SLACK: _send_slack,
        AlertChannel.PAGERDUTY: _send_pagerduty,
        AlertChannel.PUSHOVER: _send_pushover,
        AlertChannel.WEBHOOK: _send_webhook,
        AlertChannel.SYSLOG: _send_syslog,
    }
    handler = handlers.get(channel)
    if handler:
        await handler(subject, body, severity, config)
        log.info("Alert dispatched", channel=channel, subject=subject, severity=severity)


async def _send_smtp(subject: str, body: str, severity: AlertSeverity, config: dict) -> None:
    """Send an alert via SMTP."""
    from email.mime.text import MIMEText

    import aiosmtplib

    settings = get_settings()
    host = config.get("host") or settings.smtp_host
    port = config.get("port") or settings.smtp_port
    username = config.get("username") or settings.smtp_username
    password = config.get("password") or settings.smtp_password
    from_addr = config.get("from_address") or settings.smtp_from_address
    to_addr = config.get("to_address")

    if not all([host, from_addr, to_addr]):
        log.warning("SMTP alert skipped — incomplete configuration")
        return

    assert isinstance(from_addr, str)
    assert isinstance(to_addr, str)
    msg = MIMEText(body)
    msg["Subject"] = f"[Bastion {severity.upper()}] {subject}"
    msg["From"] = from_addr
    msg["To"] = to_addr

    await aiosmtplib.send(
        msg,
        hostname=host,
        port=port,
        username=username,
        password=password,
        use_tls=settings.smtp_use_tls,
    )


async def _send_ses(subject: str, body: str, severity: AlertSeverity, config: dict) -> None:
    """Send an alert via AWS SES."""
    import boto3

    settings = get_settings()
    region = config.get("region") or settings.ses_region
    from_addr = config.get("from_address") or settings.ses_from_address
    to_addr = config.get("to_address")

    if not all([region, from_addr, to_addr]):
        log.warning("SES alert skipped — incomplete configuration")
        return

    client = boto3.client("ses", region_name=region)
    client.send_email(
        Source=from_addr,
        Destination={"ToAddresses": [to_addr]},
        Message={
            "Subject": {"Data": f"[Bastion {severity.upper()}] {subject}"},
            "Body": {"Text": {"Data": body}},
        },
    )


async def _send_slack(subject: str, body: str, severity: AlertSeverity, config: dict) -> None:
    """Send an alert to a Slack webhook."""
    settings = get_settings()
    webhook_url = config.get("webhook_url") or settings.slack_webhook_url
    if not webhook_url:
        log.warning("Slack alert skipped — no webhook URL configured")
        return

    emoji = {"info": ":information_source:", "warning": ":warning:", "critical": ":rotating_light:"}
    payload = {"text": f"{emoji.get(severity, '')} *[{severity.upper()}] {subject}*\n{body}"}
    async with httpx.AsyncClient() as client:
        await client.post(webhook_url, json=payload, timeout=10)


async def _send_pagerduty(subject: str, body: str, severity: AlertSeverity, config: dict) -> None:
    """Send an alert to PagerDuty via the Events API v2."""
    settings = get_settings()
    key = config.get("integration_key") or settings.pagerduty_integration_key
    if not key:
        log.warning("PagerDuty alert skipped — no integration key configured")
        return

    pd_severity = {"info": "info", "warning": "warning", "critical": "critical"}.get(
        severity, "warning"
    )
    payload = {
        "routing_key": key,
        "event_action": "trigger",
        "payload": {
            "summary": subject,
            "severity": pd_severity,
            "source": "bastion",
            "custom_details": {"body": body},
        },
    }
    async with httpx.AsyncClient() as client:
        await client.post("https://events.pagerduty.com/v2/enqueue", json=payload, timeout=10)


async def _send_pushover(subject: str, body: str, severity: AlertSeverity, config: dict) -> None:
    """Send an alert via Pushover."""
    settings = get_settings()
    app_token = config.get("app_token") or settings.pushover_app_token
    user_key = config.get("user_key") or settings.pushover_user_key
    if not all([app_token, user_key]):
        log.warning("Pushover alert skipped — incomplete configuration")
        return

    priority = {"info": 0, "warning": 0, "critical": 1}.get(severity, 0)
    async with httpx.AsyncClient() as client:
        await client.post(
            "https://api.pushover.net/1/messages.json",
            data={
                "token": app_token,
                "user": user_key,
                "title": f"[Bastion] {subject}",
                "message": body,
                "priority": priority,
            },
            timeout=10,
        )


async def _send_webhook(subject: str, body: str, severity: AlertSeverity, config: dict) -> None:
    """Send an alert to a generic outbound webhook with HMAC-SHA256 signature."""
    import hmac as _hmac
    import time

    settings = get_settings()
    url = config.get("url") or settings.webhook_url
    if not url:
        log.warning("Webhook alert skipped — no URL configured")
        return

    payload = {
        "subject": subject,
        "body": body,
        "severity": severity,
        "timestamp": int(time.time()),
        "source": "bastion",
    }
    payload_bytes = json.dumps(payload).encode()

    headers: dict[str, str] = {"Content-Type": "application/json"}
    secret = config.get("secret") or settings.webhook_secret
    if secret:
        sig = _hmac.new(secret.encode(), payload_bytes, digestmod="sha256").hexdigest()
        headers["X-Bastion-Signature"] = f"sha256={sig}"

    async with httpx.AsyncClient() as client:
        await client.post(url, content=payload_bytes, headers=headers, timeout=10)


async def _send_syslog(subject: str, body: str, severity: AlertSeverity, config: dict) -> None:
    """Forward an alert to a remote syslog endpoint (RFC 5424)."""
    import socket
    import time

    settings = get_settings()
    host = config.get("host") or settings.syslog_host
    if not host:
        log.warning("Syslog alert skipped — no host configured")
        return

    port = int(config.get("port") or settings.syslog_port)
    protocol = config.get("protocol") or settings.syslog_protocol
    facility = int(config.get("facility") or settings.syslog_facility)

    severity_map = {"info": 6, "warning": 4, "critical": 2}
    sev_num = severity_map.get(severity, 5)
    pri = facility * 8 + sev_num

    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    message = f"<{pri}>1 {ts} bastion bastion - - - {subject}: {body}"
    msg_bytes = message.encode("utf-8")[:1024]

    if protocol == "tcp":
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(msg_bytes + b"\n")
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(msg_bytes, (host, port))
