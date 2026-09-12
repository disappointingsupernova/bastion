"""Central configuration for the Bastion service, loaded from environment variables or a .env file."""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
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
    # jwt_algorithm is intentionally hardcoded — allowing it to be set via
    # environment would permit an attacker to set it to 'none' or an asymmetric
    # algorithm to forge tokens.
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60
    jwt_refresh_token_expire_days: int = 7

    @field_validator("jwt_algorithm", mode="after")
    @classmethod
    def _lock_jwt_algorithm(cls, v: str) -> str:
        """Reject any attempt to override the JWT algorithm via configuration."""
        if v != "HS256":
            raise ValueError(
                "JWT algorithm must be HS256 — configuring a different algorithm is not permitted."
            )
        return v

    @field_validator("secret_key", mode="after")
    @classmethod
    def _validate_secret_key(cls, v: str) -> str:
        """Reject SECRET_KEY values shorter than 32 bytes at startup."""
        if len(v.encode()) < 32:
            raise ValueError(
                "SECRET_KEY must be at least 32 bytes — "
                'generate one with: python3 -c "import secrets; print(secrets.token_hex(64))"'
            )
        return v

    # ── SSH CA ────────────────────────────────────────────────────────────────
    ca_key_path: Path = Path("/opt/bastion/ca/bastion_ca")
    ca_key_passphrase: str | None = None  # Passphrase for the encrypted CA private key
    ssh_cert_validity_hours: int = 8
    krl_path: Path = Path("/opt/bastion/ca/krl")

    # ── Session recordings ────────────────────────────────────────────────────
    recordings_enabled: bool = True
    recordings_path: Path = Path("/opt/bastion/recordings")
    recordings_storage: StorageBackend = StorageBackend.LOCAL
    recordings_s3_bucket: str | None = None
    recordings_s3_prefix: str = "bastion/recordings/"
    recordings_age_public_key: str | None = None  # age public key for encryption
    # Master key for deriving per-admin decrypt keys (HMAC-SHA256 derivation)
    # Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
    recordings_master_key: str | None = None

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

    # Dual approval — when True, privileged actions require a second admin
    # to confirm within dual_approval_window_minutes. When only one admin
    # exists, the initiator must re-verify with TOTP + email instead.
    dual_approval_required: bool = False
    dual_approval_window_minutes: int = 30

    # ── Package checks ────────────────────────────────────────────────────────
    package_check_interval_hours: int = 6

    # ── SSH key rotation reminders ────────────────────────────────────────────
    ssh_key_max_age_days: int | None = 365

    # ── Certificate expiry warnings ───────────────────────────────────────────
    cert_expiry_warn_minutes: int = 60

    # ── LDAP / Active Directory ───────────────────────────────────────────────
    ldap_url: str | None = None
    ldap_bind_dn: str | None = None
    ldap_bind_password: str | None = None
    ldap_user_base_dn: str | None = None
    ldap_user_filter: str = "(objectClass=person)"
    ldap_username_attr: str = "sAMAccountName"
    ldap_email_attr: str = "mail"
    ldap_sync_interval_hours: int = 6

    # ── SIEM / syslog forwarding ──────────────────────────────────────────────
    syslog_host: str | None = None
    syslog_port: int = 514
    syslog_protocol: str = "udp"  # udp or tcp
    syslog_facility: int = 16  # local0

    # ── Webhook notifications ─────────────────────────────────────────────────
    webhook_url: str | None = None
    webhook_secret: str | None = None  # HMAC-SHA256 signing secret for webhook payloads

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


# Remove the unused module-level _settings variable — the singleton is
# managed entirely by the lru_cache on get_settings().
@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached Settings instance.

    lru_cache provides thread-safe singleton semantics — the function is called
    at most once regardless of concurrent callers (fix #22).
    """
    return Settings()  # type: ignore[call-arg]  # secret_key loaded from env/.env
