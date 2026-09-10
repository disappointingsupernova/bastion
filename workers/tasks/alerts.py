"""Celery tasks for dispatching pending anomaly alerts."""

from __future__ import annotations

import asyncio
import json

from workers.celery_app import app
from bastion.logging import get_logger

log = get_logger(__name__)


@app.task(name="workers.tasks.alerts.dispatch_pending_anomaly_alerts", bind=True)
def dispatch_pending_anomaly_alerts(self) -> None:
    """Dispatch alerts for all unalerted anomaly events."""
    asyncio.run(_dispatch_pending())


async def _dispatch_pending() -> None:
    """Async implementation of anomaly alert dispatch."""
    from bastion.db import get_db_session
    from bastion.models import AnomalyEvent, AlertSeverity
    from bastion.alerting import dispatch_alert
    from bastion.config import get_settings
    from sqlalchemy import select

    settings = get_settings()

    async with get_db_session() as db:
        result = await db.execute(
            select(AnomalyEvent).where(AnomalyEvent.alerted == False)  # noqa: E712
        )
        events = result.scalars().all()

        for event in events:
            detail = json.loads(event.detail) if event.detail else {}
            factors = detail.get("factors", [])
            source_ip = detail.get("source_ip", "unknown")

            severity = (
                AlertSeverity.CRITICAL
                if event.score >= 80
                else AlertSeverity.WARNING
            )

            body_lines = [
                f"Anomaly score: {event.score}/100",
                f"Event type: {event.event_type}",
                f"Source IP: {source_ip}",
                "",
                "Contributing factors:",
            ] + [f"  - {f}" for f in factors]

            await dispatch_alert(
                db,
                subject=f"Anomaly detected — score {event.score}/100",
                body="\n".join(body_lines),
                severity=severity,
            )
            event.alerted = True
            log.info("Anomaly alert dispatched", event_id=event.id, score=event.score)
