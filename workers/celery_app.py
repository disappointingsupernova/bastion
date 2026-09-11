"""Celery application configuration for background task processing."""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from bastion.config import get_settings
from bastion.logging import get_logger

log = get_logger(__name__)
settings = get_settings()

# Strip credentials from the Redis URL before logging (fix #30)
_redis_url_safe = (
    settings.redis_url.split("@")[-1] if "@" in settings.redis_url else settings.redis_url
)
log.info("Celery broker configured", broker=f"redis://{_redis_url_safe}")

app = Celery(
    "bastion",
    broker=settings.redis_url,
    # Fix #16: task results are disabled — provisioning output, error details,
    # and hostnames must not be stored in Redis (no encryption at rest).
    # Tasks use audit logs for outcome tracking instead.
    backend=None,
    include=[
        "workers.tasks.alerts",
        "workers.tasks.certificates",
        "workers.tasks.packages",
        "workers.tasks.recordings",
        "workers.tasks.connectivity",
        "workers.tasks.access_requests",
    ],
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=False,  # Requires result backend — disabled
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    # Explicitly disable result storage
    task_ignore_result=True,
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
        "expire-jit-access": {
            "task": "workers.tasks.access_requests.expire_jit_access",
            "schedule": crontab(minute="*/5"),
        },
    },
)
