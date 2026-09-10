"""Celery application configuration for background task processing."""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from bastion.config import get_settings

settings = get_settings()

app = Celery(
    "bastion",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "workers.tasks.alerts",
        "workers.tasks.certificates",
        "workers.tasks.packages",
        "workers.tasks.recordings",
        "workers.tasks.connectivity",
    ],
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "check-server-connectivity": {
            "task": "workers.tasks.connectivity.check_all_servers",
            "schedule": crontab(minute="*/5"),
        },
        "check-package-updates": {
            "task": "workers.tasks.packages.check_all_servers",
            "schedule": crontab(
                minute="0",
                hour=f"*/{settings.package_check_interval_hours}",
            ),
        },
        "expire-certificates": {
            "task": "workers.tasks.certificates.expire_old_certificates",
            "schedule": crontab(minute="*/15"),
        },
        "dispatch-anomaly-alerts": {
            "task": "workers.tasks.alerts.dispatch_pending_anomaly_alerts",
            "schedule": crontab(minute="*/2"),
        },
    },
)
