"""Celery tasks for notifications, KRL distribution, database backup, and baseline maintenance."""

from __future__ import annotations

import asyncio

from bastion.logging import get_logger
from workers.celery_app import app

log = get_logger(__name__)


# ── SSH public key rotation reminders ─────────────────────────────────────────


@app.task(name="workers.tasks.notifications.check_ssh_key_age", bind=True)
def check_ssh_key_age(self) -> None:
    """Alert users and admins when SSH public keys exceed the configured age threshold."""
    asyncio.run(_check_ssh_key_age())


async def _check_ssh_key_age() -> None:
    """Async implementation of SSH key age check."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from bastion.alerting import dispatch_alert
    from bastion.config import get_settings
    from bastion.db import get_db_session
    from bastion.models import AlertSeverity, User, UserStatus

    settings = get_settings()
    max_age_days = settings.ssh_key_max_age_days
    if not max_age_days:
        return

    threshold = datetime.now(tz=UTC) - timedelta(days=max_age_days)

    async with get_db_session() as db:
        result = await db.execute(
            select(User).where(
                User.status == UserStatus.ACTIVE,
                User.deleted_at.is_(None),
                User.ssh_public_key.is_not(None),
                User.ssh_public_key_updated_at < threshold,
            )
        )
        stale_users = result.scalars().all()

        for user in stale_users:
            days_old = (datetime.now(tz=UTC) - user.ssh_public_key_updated_at).days  # type: ignore[operator]
            await dispatch_alert(
                db,
                subject=f"SSH public key rotation required — {user.username}",
                body=(
                    f"User {user.username} ({user.email}) has not rotated their SSH public key "
                    f"in {days_old} days (threshold: {max_age_days} days).\n\n"
                    f"Please ask them to generate a new key and update their profile."
                ),
                severity=AlertSeverity.WARNING,
            )
            log.info("SSH key rotation reminder sent", user_id=user.id, days_old=days_old)

    if stale_users:
        log.info("SSH key rotation reminders dispatched", count=len(stale_users))


# ── Certificate expiry notifications ──────────────────────────────────────────


@app.task(name="workers.tasks.notifications.notify_cert_expiry", bind=True)
def notify_cert_expiry(self) -> None:
    """Warn users and admins when active certificates are approaching expiry."""
    asyncio.run(_notify_cert_expiry())


async def _notify_cert_expiry() -> None:
    """Async implementation of certificate expiry notification."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from bastion.alerting import dispatch_alert
    from bastion.config import get_settings
    from bastion.db import get_db_session
    from bastion.models import AlertSeverity, CertStatus, SshCertificate, User

    settings = get_settings()
    warn_minutes = settings.cert_expiry_warn_minutes
    if not warn_minutes:
        return

    now = datetime.now(tz=UTC)
    warn_before = now + timedelta(minutes=warn_minutes)

    async with get_db_session() as db:
        result = await db.execute(
            select(SshCertificate, User.username, User.email)
            .join(User, User.id == SshCertificate.user_id)
            .where(
                SshCertificate.status == CertStatus.ACTIVE,
                SshCertificate.valid_before <= warn_before,
                SshCertificate.valid_before > now,
            )
        )
        expiring = result.all()

        for cert, username, email in expiring:
            minutes_left = int((cert.valid_before - now).total_seconds() / 60)
            await dispatch_alert(
                db,
                subject=f"SSH certificate expiring soon — {username}",
                body=(
                    f"Certificate serial {cert.serial} for user {username} ({email}) "
                    f"expires in {minutes_left} minutes.\n\n"
                    f"The user should re-authenticate to obtain a new certificate."
                ),
                severity=AlertSeverity.WARNING,
            )
            log.info(
                "Certificate expiry notification sent", cert_id=cert.id, minutes_left=minutes_left
            )


# ── Automatic KRL distribution ────────────────────────────────────────────────


@app.task(name="workers.tasks.notifications.distribute_krl", bind=True, max_retries=3)
def distribute_krl(self) -> None:
    """Push the current KRL to all managed servers and verify delivery."""
    asyncio.run(_distribute_krl())


async def _distribute_krl() -> None:
    """Async implementation of KRL distribution to all managed servers."""
    import asyncssh
    from sqlalchemy import select

    from bastion.config import get_settings
    from bastion.db import get_db_session
    from bastion.models import Server, ServerStatus

    settings = get_settings()
    krl_path = settings.krl_path
    if not krl_path.exists():
        log.warning("KRL file not found — skipping distribution", path=str(krl_path))
        return

    krl_bytes = krl_path.read_bytes()

    async with get_db_session() as db:
        result = await db.execute(
            select(Server).where(
                Server.status == ServerStatus.ACTIVE,
                Server.deleted_at.is_(None),
                Server.hardening_applied == True,  # noqa: E712
            )
        )
        servers = result.scalars().all()

    success_count = 0
    failure_count = 0

    ca_pub_key_text = krl_path.parent.joinpath("bastion_ca.pub").read_text().strip()
    known_hosts = asyncssh.SSHKnownHosts(f"@cert-authority * {ca_pub_key_text}\n")
    host_key_path = str(settings.ca_key_path.parent / "bastion_host_key")

    for server in servers:
        try:
            async with asyncssh.connect(
                server.hostname,
                port=server.ssh_port,
                known_hosts=known_hosts,
                username="bastion",
                client_keys=[host_key_path],
            ) as conn:
                await conn.run(
                    "cat > /etc/ssh/bastion_krl && chmod 644 /etc/ssh/bastion_krl",
                    input=krl_bytes,
                    check=True,
                )
                # Verify the KRL was written correctly
                result_check = await conn.run(
                    "wc -c < /etc/ssh/bastion_krl",
                    check=True,
                )
                stdout_raw = result_check.stdout
                stdout_text = (
                    stdout_raw.decode() if isinstance(stdout_raw, bytes) else (stdout_raw or "")
                )
                remote_size = int(stdout_text.strip())
                if remote_size != len(krl_bytes):
                    raise RuntimeError(
                        f"KRL size mismatch: expected {len(krl_bytes)}, got {remote_size}"
                    )
            success_count += 1
            log.info("KRL distributed to server", hostname=server.hostname)
        except Exception as exc:
            failure_count += 1
            log.error("KRL distribution failed", hostname=server.hostname, error=str(exc))

    log.info(
        "KRL distribution complete",
        total=len(servers),
        success=success_count,
        failed=failure_count,
    )
    if failure_count > 0:
        log.warning(
            "KRL distribution had failures — some servers may have stale KRL", failed=failure_count
        )


# ── Database backup ───────────────────────────────────────────────────────────


@app.task(name="workers.tasks.notifications.backup_database", bind=True, max_retries=2)
def backup_database(self) -> None:
    """Snapshot the database and optionally upload to S3."""
    asyncio.run(_backup_database())


async def _backup_database() -> None:
    """Async implementation of database backup."""
    import shutil
    import sqlite3 as _sqlite3
    import subprocess
    import tempfile
    from datetime import UTC, datetime
    from pathlib import Path

    from bastion.config import DatabaseBackend, StorageBackend, get_settings

    settings = get_settings()
    ts = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")

    with tempfile.TemporaryDirectory(prefix="bastion-backup-") as tmpdir:
        tmp = Path(tmpdir)

        if settings.db_backend == DatabaseBackend.SQLITE:
            db_path = settings.bastion_root / "data" / "bastion.db"
            backup_file = tmp / f"bastion_{ts}.db"
            # Use Python's sqlite3 online backup API — no external binary required
            src = _sqlite3.connect(str(db_path))
            dst = _sqlite3.connect(str(backup_file))
            try:
                src.backup(dst)
            finally:
                dst.close()
                src.close()
        else:
            backup_file = tmp / f"bastion_{ts}.sql.gz"
            # Parse the DB URL to extract credentials without exposing them on the
            # command line (visible in ps aux). Credentials are passed via environment
            # variables which are not visible to other processes.
            from urllib.parse import urlparse

            parsed = urlparse(settings.db_url)
            pg_env = {
                **__import__("os").environ,
                "PGPASSWORD": parsed.password or "",
            }
            pg_args = ["pg_dump", f"--file={backup_file}", "--compress=9"]
            if parsed.hostname:
                pg_args += ["--host", parsed.hostname]
            if parsed.port:
                pg_args += ["--port", str(parsed.port)]
            if parsed.username:
                pg_args += ["--username", parsed.username]
            if parsed.path and parsed.path.lstrip("/"):
                pg_args.append(parsed.path.lstrip("/"))
            result = subprocess.run(
                pg_args,
                capture_output=True,
                timeout=300,
                env=pg_env,
            )
            if result.returncode != 0:
                stderr_out = result.stderr
                msg = stderr_out.decode() if isinstance(stderr_out, bytes) else (stderr_out or "")
                raise RuntimeError(f"pg_dump failed: {msg}")

        if settings.recordings_storage == StorageBackend.S3 and settings.recordings_s3_bucket:
            import boto3

            s3_key = f"bastion/backups/{backup_file.name}"
            boto3.client("s3").upload_file(str(backup_file), settings.recordings_s3_bucket, s3_key)
            log.info(
                "Database backup uploaded to S3", key=s3_key, bucket=settings.recordings_s3_bucket
            )
        else:
            backup_dir = settings.bastion_root / "data" / "backups"
            backup_dir.mkdir(exist_ok=True)
            shutil.copy2(str(backup_file), str(backup_dir / backup_file.name))
            log.info("Database backup saved locally", path=str(backup_dir / backup_file.name))


# ── Anomaly baseline maintenance ──────────────────────────────────────────────


@app.task(name="workers.tasks.notifications.refresh_anomaly_baselines", bind=True)
def refresh_anomaly_baselines(self) -> None:
    """Refresh anomaly baselines for all active users on a rolling schedule."""
    asyncio.run(_refresh_baselines())


async def _refresh_baselines() -> None:
    """Async implementation of baseline refresh."""
    from sqlalchemy import select

    from bastion.anomaly import update_baseline
    from bastion.db import get_db_session
    from bastion.models import User, UserStatus

    async with get_db_session() as db:
        result = await db.execute(
            select(User).where(User.status == UserStatus.ACTIVE, User.deleted_at.is_(None))
        )
        users = result.scalars().all()
        for user in users:
            await update_baseline(db, user.id)

    log.info("Anomaly baselines refreshed", user_count=len(users))


# ── Cluster node heartbeat ────────────────────────────────────────────────────


@app.task(name="workers.tasks.notifications.node_heartbeat", bind=True)
def node_heartbeat(self) -> None:
    """Register this node's heartbeat in the cluster registry."""
    asyncio.run(_node_heartbeat())


async def _node_heartbeat() -> None:
    """Async implementation of node heartbeat."""
    import json
    import os
    from datetime import UTC, datetime

    from sqlalchemy import select

    from bastion.config import get_settings
    from bastion.db import get_db_session
    from bastion.models import BastionNode

    settings = get_settings()

    try:
        import importlib.metadata

        version = importlib.metadata.version("bastion")
    except Exception:
        version = "unknown"

    load_metrics = json.dumps(
        {
            "load_avg": os.getloadavg() if hasattr(os, "getloadavg") else None,
        }
    )

    async with get_db_session() as db:
        result = await db.execute(
            select(BastionNode).where(BastionNode.node_id == settings.node_id)
        )
        node = result.scalar_one_or_none()
        if node is None:
            node = BastionNode(node_id=settings.node_id)
            db.add(node)

        node.version = version
        node.last_heartbeat_at = datetime.now(tz=UTC)
        node.load_metrics = load_metrics
        await db.flush()

    log.debug("Node heartbeat recorded", node_id=settings.node_id)
