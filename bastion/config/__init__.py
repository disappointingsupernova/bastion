"""Central configuration for the Bastion service, loaded from environment variables or a .env file."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseBackend(StrEnum):
    SQLITE = "sqlite"
    POSTGRES = "postgres"


class StorageBackend(StrEnum):
    LOCAL = "local"
    S3 = "s3"
    NFS = "nfs"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="/opt/bastion/.env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Core ──────────────────────────────────────────────────────────────────
    bastion_root: Path = Path("/opt/bastion")
    secret_key: str  # Used for JWT signing — must be set in .env
    environment: str = "production"
    ha_mode: bool = False
    node_id: str = "node-1"

    # ── Database ──────────────────────────────────────────────────────────────
    db_backend: DatabaseBackend = DatabaseBackend.SQLITE
    db_url: str = "sqlite+aiosqlite:////opt/bastion/data/bastion.db"

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Unix sockets ──────────────────────────────────────────────────────────
    bastion_api_socket: Path = Path("/opt/bastion/run/bastion-api.sock")
    bastion_admin_socket: Path = Path("/opt/bastion/run/bastion-admin.sock")

    # ── JWT ───────────────────────────────────────────────────────────────────
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60
    jwt_refresh_token_expire_days: int = 7

    # ── SSH CA ────────────────────────────────────────────────────────────────
    ca_key_path: Path = Path("/opt/bastion/ca/bastion_ca")
    ssh_cert_validity_hours: int = 8
    krl_path: Path = Path("/opt/bastion/ca/krl")

    # ── Session recordings ────────────────────────────────────────────────────
    recordings_enabled: bool = True
    recordings_path: Path = Path("/opt/bastion/recordings")
    recordings_storage: StorageBackend = StorageBackend.LOCAL
    recordings_s3_bucket: str | None = None
    recordings_s3_prefix: str = "bastion/recordings/"
    recordings_age_public_key: str | None = None  # age public key for encryption

    # ── Alerting ──────────────────────────────────────────────────────────────
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_address: str | None = None
    smtp_use_tls: bool = True

    ses_region: str | None = None
    ses_from_address: str | None = None

    slack_webhook_url: str | None = None
    pagerduty_integration_key: str | None = None
    pushover_app_token: str | None = None
    pushover_user_key: str | None = None

    # ── 2FA ───────────────────────────────────────────────────────────────────
    totp_issuer: str = "Bastion"
    mfa_email_code_expire_minutes: int = 10

    # ── Rate limiting ─────────────────────────────────────────────────────────
    rate_limit_auth_per_minute: int = 10

    # ── Anomaly detection ─────────────────────────────────────────────────────
    anomaly_score_alert_threshold: int = 70  # 0–100 heuristic score

    # ── Package checks ────────────────────────────────────────────────────────
    package_check_interval_hours: int = 6

    # ── Excluded system users (cannot be bastion users) ───────────────────────
    excluded_system_users: list[str] = [
        "root",
        "ubuntu",
        "debian",
        "ec2-user",
        "admin",
        "nobody",
        "daemon",
        "bin",
        "sys",
        "sync",
        "games",
        "man",
        "lp",
        "mail",
        "news",
        "uucp",
        "proxy",
        "www-data",
        "backup",
        "list",
        "irc",
        "gnats",
        "systemd-network",
        "systemd-resolve",
        "messagebus",
        "sshd",
        "bastion",
    ]

    @field_validator("bastion_root", "ca_key_path", "krl_path", "recordings_path", mode="before")
    @classmethod
    def coerce_path(cls, v: str | Path) -> Path:
        """Coerce string values to Path objects."""
        return Path(v)

    @property
    def is_sqlite(self) -> bool:
        """Return True if the configured database backend is SQLite."""
        return self.db_backend == DatabaseBackend.SQLITE

    @property
    def is_ha(self) -> bool:
        """Return True if HA mode is enabled."""
        return self.ha_mode


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the cached Settings instance, creating it on first call."""
    global _settings
    if _settings is None:
        _settings = Settings()  # type: ignore[call-arg]  # secret_key loaded from env/.env
    return _settings
