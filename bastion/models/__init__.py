"""ORM models for the Bastion service."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from bastion.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


# ── Enumerations ──────────────────────────────────────────────────────────────


class UserRole(StrEnum):
    ADMIN = "admin"
    USER = "user"
    AUDITOR = "auditor"
    READ_ONLY = "read_only"


class UserStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class ServerStatus(StrEnum):
    ACTIVE = "active"
    UNREACHABLE = "unreachable"
    MAINTENANCE = "maintenance"
    DELETED = "deleted"


class SessionStatus(StrEnum):
    ACTIVE = "active"
    COMPLETED = "completed"
    TERMINATED = "terminated"
    REVOKED = "revoked"


class CertStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AlertChannel(StrEnum):
    EMAIL = "email"
    SES = "ses"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    PUSHOVER = "pushover"
    WEBHOOK = "webhook"
    SYSLOG = "syslog"


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class MfaMethod(StrEnum):
    TOTP = "totp"
    EMAIL = "email"
    FIDO2 = "fido2"


class DualApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class AccessRequestStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"


class OsFamily(StrEnum):
    DEBIAN = "debian"
    RHEL = "rhel"
    UNKNOWN = "unknown"


# ── Mixins ────────────────────────────────────────────────────────────────────


class TimestampMixin:
    """Adds created_at and updated_at columns to a model."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


# ── Models ────────────────────────────────────────────────────────────────────


class User(TimestampMixin, Base):
    """A Bastion user account."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(String(32), nullable=False, default=UserRole.USER)
    status: Mapped[UserStatus] = mapped_column(
        String(32), nullable=False, default=UserStatus.ACTIVE
    )
    mfa_method: Mapped[MfaMethod | None] = mapped_column(String(16))
    totp_secret: Mapped[str | None] = mapped_column(String(255))  # Encrypted at rest
    fido2_credentials: Mapped[str | None] = mapped_column(Text)  # JSON list of FIDO2 credential dicts, encrypted
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    unix_uid: Mapped[int | None] = mapped_column(Integer)
    ssh_public_key: Mapped[str | None] = mapped_column(Text)
    ssh_public_key_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_ip: Mapped[str | None] = mapped_column(String(45))
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # When True, this user may submit just-in-time access requests
    jit_access_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # JSON array of CIDR strings — if non-null, logins are restricted to these ranges
    ip_allowlist: Mapped[str | None] = mapped_column(Text)

    certificates: Mapped[list[SshCertificate]] = relationship(back_populates="user")
    sessions: Mapped[list[Session]] = relationship(back_populates="user")
    server_access: Mapped[list[ServerAccess]] = relationship(back_populates="user")
    audit_logs: Mapped[list[AuditLog]] = relationship(back_populates="user")
    mfa_codes: Mapped[list[MfaCode]] = relationship(back_populates="user")


class Server(TimestampMixin, Base):
    """A remote server managed by Bastion."""

    __tablename__ = "servers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    display_name: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    ssh_port: Mapped[int] = mapped_column(Integer, default=22, nullable=False)
    os_family: Mapped[OsFamily] = mapped_column(
        String(32), default=OsFamily.UNKNOWN, nullable=False
    )
    os_version: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[ServerStatus] = mapped_column(
        String(32), default=ServerStatus.ACTIVE, nullable=False
    )
    tags: Mapped[str | None] = mapped_column(Text)  # JSON array of tag strings
    environment: Mapped[str | None] = mapped_column(String(64))  # e.g. production, staging, dev
    notes: Mapped[str | None] = mapped_column(Text)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Proxy jump support
    proxy_jump_server_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("servers.id"), nullable=True
    )
    # SSH hardening applied
    hardening_applied: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # JSON array of CIDR strings — if non-null, only these source IPs may connect
    ip_allowlist: Mapped[str | None] = mapped_column(Text)
    # Privileged session controls (JSON object)
    session_policy: Mapped[str | None] = mapped_column(Text)

    proxy_jump_server: Mapped[Server | None] = relationship("Server", remote_side="Server.id")
    sessions: Mapped[list[Session]] = relationship(back_populates="server")
    server_access: Mapped[list[ServerAccess]] = relationship(back_populates="server")
    packages: Mapped[list[ServerPackage]] = relationship(back_populates="server")


class ServerAccess(TimestampMixin, Base):
    """Grants a user access to a specific server, with optional sudo."""

    __tablename__ = "server_access"
    __table_args__ = (UniqueConstraint("user_id", "server_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    server_id: Mapped[str] = mapped_column(String(36), ForeignKey("servers.id"), nullable=False)
    allow_sudo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    remote_username: Mapped[str | None] = mapped_column(String(64))  # Unix account on remote
    provisioned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    provisioned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="server_access")
    server: Mapped[Server] = relationship(back_populates="server_access")


class SshCertificate(TimestampMixin, Base):
    """An SSH certificate issued by the Bastion CA."""

    __tablename__ = "ssh_certificates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    serial: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    key_id: Mapped[str] = mapped_column(String(255), nullable=False)
    principals: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    valid_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[CertStatus] = mapped_column(
        String(32), default=CertStatus.ACTIVE, nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(255))
    issued_from_ip: Mapped[str | None] = mapped_column(String(45))

    user: Mapped[User] = relationship(back_populates="certificates")


class Session(TimestampMixin, Base):
    """An SSH session proxied through the Bastion."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    server_id: Mapped[str] = mapped_column(String(36), ForeignKey("servers.id"), nullable=False)
    certificate_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("ssh_certificates.id")
    )
    status: Mapped[SessionStatus] = mapped_column(
        String(32), default=SessionStatus.ACTIVE, nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_ip: Mapped[str | None] = mapped_column(String(45))
    remote_username: Mapped[str | None] = mapped_column(String(64))
    recording_path: Mapped[str | None] = mapped_column(String(512))
    recording_encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    bytes_sent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    bytes_received: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    termination_reason: Mapped[str | None] = mapped_column(String(255))

    user: Mapped[User] = relationship(back_populates="sessions")
    server: Mapped[Server] = relationship(back_populates="sessions")


class AuditLog(TimestampMixin, Base):
    """Immutable audit log entry for every action in the system."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    seq: Mapped[int | None] = mapped_column(Integer, autoincrement=True, nullable=True, unique=True, index=True, server_default=None)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(36))
    detail: Mapped[str | None] = mapped_column(Text)  # JSON
    ip_address: Mapped[str | None] = mapped_column(String(45))
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    node_id: Mapped[str | None] = mapped_column(String(64))
    # HMAC-SHA256 of the entry content, chained to the previous entry's HMAC
    integrity_hash: Mapped[str | None] = mapped_column(String(64))

    user: Mapped[User | None] = relationship(back_populates="audit_logs")


class MfaCode(TimestampMixin, Base):
    """A time-limited email MFA code."""

    __tablename__ = "mfa_codes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped[User] = relationship(back_populates="mfa_codes")


class AnomalyEvent(TimestampMixin, Base):
    """A detected anomaly event with a heuristic risk score."""

    __tablename__ = "anomaly_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    server_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("servers.id"), nullable=True
    )
    session_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("sessions.id"), nullable=True
    )
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False)  # 0–100
    detail: Mapped[str | None] = mapped_column(Text)  # JSON
    alerted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class AlertConfig(TimestampMixin, Base):
    """Alert channel configuration stored in the database."""

    __tablename__ = "alert_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    channel: Mapped[AlertChannel] = mapped_column(String(32), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    config_json: Mapped[str | None] = mapped_column(Text)  # Encrypted JSON of channel config
    min_severity: Mapped[AlertSeverity] = mapped_column(
        String(32), default=AlertSeverity.WARNING, nullable=False
    )


class SystemSetting(TimestampMixin, Base):
    """Key-value store for system-wide settings managed via the admin API."""

    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(String(512))
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class ServerPackage(TimestampMixin, Base):
    """A package tracked on a remote server."""

    __tablename__ = "server_packages"
    __table_args__ = (UniqueConstraint("server_id", "package_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    server_id: Mapped[str] = mapped_column(String(36), ForeignKey("servers.id"), nullable=False)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    installed_version: Mapped[str | None] = mapped_column(String(128))
    available_version: Mapped[str | None] = mapped_column(String(128))
    update_available: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    server: Mapped[Server] = relationship(back_populates="packages")


class CertSerial(Base):
    """Monotonically increasing certificate serial number counter."""

    __tablename__ = "cert_serials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)


class AccessRequest(TimestampMixin, Base):
    """A just-in-time request for temporary access to a server.

    Users with jit_access_enabled=True on their account can submit requests.
    Admins approve or deny. Approved access auto-revokes at expires_at.
    """

    __tablename__ = "access_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    server_id: Mapped[str] = mapped_column(String(36), ForeignKey("servers.id"), nullable=False)
    reason: Mapped[str] = mapped_column(String(1024), nullable=False)
    allow_sudo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    requested_duration_hours: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[AccessRequestStatus] = mapped_column(
        String(32), default=AccessRequestStatus.PENDING, nullable=False, index=True
    )
    reviewed_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_note: Mapped[str | None] = mapped_column(String(512))
    # The ServerAccess record created on approval — null until approved
    server_access_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("server_access.id"), nullable=True
    )

    user: Mapped[User] = relationship(foreign_keys=[user_id])
    server: Mapped[Server] = relationship()
    reviewer: Mapped[User | None] = relationship(foreign_keys=[reviewed_by_user_id])


class DualApprovalRequest(TimestampMixin, Base):
    """A pending privileged operation requiring a second admin to confirm.

    When dual_approval_required=True in settings, actions such as granting sudo,
    revoking a certificate, or deleting a user are held here until a second admin
    approves within the configured window.

    When only one admin exists, the initiating admin must re-authenticate with
    TOTP + email before the action proceeds (single-admin fallback).
    """

    __tablename__ = "dual_approval_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    # The admin who initiated the action
    initiated_by_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )
    # Human-readable description of the action
    action_description: Mapped[str] = mapped_column(String(512), nullable=False)
    # Serialised action payload (JSON) — replayed on approval
    action_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    action_payload: Mapped[str] = mapped_column(Text, nullable=False)  # JSON
    status: Mapped[DualApprovalStatus] = mapped_column(
        String(32), default=DualApprovalStatus.PENDING, nullable=False, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # The second admin who approved or rejected
    reviewed_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_note: Mapped[str | None] = mapped_column(String(512))
    # For single-admin fallback: MFA verification token
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    initiator: Mapped[User] = relationship(foreign_keys=[initiated_by_user_id])
    reviewer: Mapped[User | None] = relationship(foreign_keys=[reviewed_by_user_id])


# ── User groups ───────────────────────────────────────────────────────────────


class UserGroup(TimestampMixin, Base):
    """A named group of users. Access grants can target a group rather than individual users."""

    __tablename__ = "user_groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(512))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    memberships: Mapped[list[UserGroupMembership]] = relationship(back_populates="group")


class UserGroupMembership(TimestampMixin, Base):
    """Association between a user and a group."""

    __tablename__ = "user_group_memberships"
    __table_args__ = (UniqueConstraint("user_id", "group_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    group_id: Mapped[str] = mapped_column(String(36), ForeignKey("user_groups.id"), nullable=False)

    user: Mapped[User] = relationship()
    group: Mapped[UserGroup] = relationship(back_populates="memberships")


class GroupServerAccess(TimestampMixin, Base):
    """Grants a group access to a server. Membership changes auto-provision/deprovision."""

    __tablename__ = "group_server_access"
    __table_args__ = (UniqueConstraint("group_id", "server_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    group_id: Mapped[str] = mapped_column(String(36), ForeignKey("user_groups.id"), nullable=False)
    server_id: Mapped[str] = mapped_column(String(36), ForeignKey("servers.id"), nullable=False)
    allow_sudo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    remote_username: Mapped[str | None] = mapped_column(String(64))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    group: Mapped[UserGroup] = relationship()
    server: Mapped[Server] = relationship()


# ── Anomaly baseline ──────────────────────────────────────────────────────────


class AnomalyBaseline(TimestampMixin, Base):
    """Rolling per-user baseline statistics for anomaly detection."""

    __tablename__ = "anomaly_baselines"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False, unique=True, index=True
    )
    # JSON: list of UTC hours (0–23) seen in successful logins over the rolling window
    typical_hours: Mapped[str | None] = mapped_column(Text)
    # JSON: list of source IPs seen in successful logins
    known_ips: Mapped[str | None] = mapped_column(Text)
    # Average session duration in seconds over the rolling window
    avg_session_duration_seconds: Mapped[float | None] = mapped_column()
    # Average bytes transferred per session
    avg_session_bytes: Mapped[float | None] = mapped_column()
    # Number of samples used to compute the baseline
    sample_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship()


# ── Recording decrypt log ─────────────────────────────────────────────────────


class RecordingDecryptLog(TimestampMixin, Base):
    """Audit trail for recording decryption events — tracks who decrypted what and when."""

    __tablename__ = "recording_decrypt_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), nullable=False, index=True
    )
    admin_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False, index=True
    )
    # Fingerprint of the admin-derived key used (not the key itself)
    key_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    admin: Mapped[User] = relationship()


# ── Bastion cluster nodes ─────────────────────────────────────────────────────


class BastionNode(TimestampMixin, Base):
    """Registry of Bastion cluster nodes in HA mode."""

    __tablename__ = "bastion_nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    node_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    version: Mapped[str | None] = mapped_column(String(64))
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # JSON: load metrics snapshot
    load_metrics: Mapped[str | None] = mapped_column(Text)
