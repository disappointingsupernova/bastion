"""Celery tasks for offloading session recordings to S3 or NFS."""

from __future__ import annotations

import asyncio
from pathlib import Path

from bastion.logging import get_logger
from workers.celery_app import app

log = get_logger(__name__)


@app.task(name="workers.tasks.recordings.offload_recording", bind=True, max_retries=3)
def offload_recording(self, session_id: str) -> None:
    """Offload a completed session recording to the configured remote storage."""
    asyncio.run(_offload(session_id))


async def _offload(session_id: str) -> None:
    """Async implementation of recording offload."""
    import boto3
    from sqlalchemy import select

    from bastion.config import StorageBackend, get_settings
    from bastion.db import get_db_session
    from bastion.models import Session

    settings = get_settings()

    async with get_db_session() as db:
        result = await db.execute(select(Session).where(Session.id == session_id))
        session = result.scalar_one_or_none()

    if session is None or not session.recording_path:
        log.warning(
            "Recording offload skipped — session or recording not found", session_id=session_id
        )
        return

    recording_path = Path(session.recording_path)
    if not recording_path.exists():
        log.warning("Recording file not found on disk", path=str(recording_path))
        return

    if settings.recordings_storage == StorageBackend.S3:
        if not settings.recordings_s3_bucket:
            log.error("S3 offload configured but no bucket name set")
            return

        s3_key = f"{settings.recordings_s3_prefix}{recording_path.name}"
        s3 = boto3.client("s3")
        s3.upload_file(str(recording_path), settings.recordings_s3_bucket, s3_key)

        async with get_db_session() as db:
            result = await db.execute(select(Session).where(Session.id == session_id))
            s = result.scalar_one_or_none()
            if s:
                s.recording_path = f"s3://{settings.recordings_s3_bucket}/{s3_key}"

        recording_path.unlink(missing_ok=True)
        log.info(
            "Recording offloaded to S3",
            session_id=session_id,
            bucket=settings.recordings_s3_bucket,
            key=s3_key,
        )
    else:
        log.debug("Recording storage is local — no offload required", session_id=session_id)
