"""Initial schema — create all Bastion tables.

Revision ID: 0001
Revises:
Create Date: 2024-01-15 12:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all tables for the initial Bastion schema."""

    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("mfa_method", sa.String(16), nullable=True),
        sa.Column("totp_secret", sa.String(255), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("unix_uid", sa.Integer(), nullable=True),
        sa.Column("ssh_public_key", sa.Text(), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_ip", sa.String(45), nullable=True),
        sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_table(
        "servers",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False, unique=True, index=True),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("ssh_port", sa.Integer(), nullable=False, server_default="22"),
        sa.Column("os_family", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("os_version", sa.String(128), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("tags", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "proxy_jump_server_id", sa.String(36), sa.ForeignKey("servers.id"), nullable=True
        ),
        sa.Column("hardening_applied", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_table(
        "server_access",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("server_id", sa.String(36), sa.ForeignKey("servers.id"), nullable=False),
        sa.Column("allow_sudo", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("remote_username", sa.String(64), nullable=True),
        sa.Column("provisioned", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("provisioned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("user_id", "server_id"),
    )

    op.create_table(
        "cert_serials",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
    )

    op.create_table(
        "ssh_certificates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("serial", sa.Integer(), nullable=False, unique=True),
        sa.Column("key_id", sa.String(255), nullable=False),
        sa.Column("principals", sa.Text(), nullable=False),
        sa.Column("valid_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(255), nullable=True),
        sa.Column("issued_from_ip", sa.String(45), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_table(
        "sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("server_id", sa.String(36), sa.ForeignKey("servers.id"), nullable=False),
        sa.Column(
            "certificate_id", sa.String(36), sa.ForeignKey("ssh_certificates.id"), nullable=True
        ),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column(
            "started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("remote_username", sa.String(64), nullable=True),
        sa.Column("recording_path", sa.String(512), nullable=True),
        sa.Column("recording_encrypted", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("bytes_sent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("bytes_received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("termination_reason", sa.String(255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("action", sa.String(128), nullable=False, index=True),
        sa.Column("resource_type", sa.String(64), nullable=True),
        sa.Column("resource_id", sa.String(36), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("node_id", sa.String(64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_table(
        "mfa_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("code_hash", sa.String(255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_table(
        "anomaly_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("server_id", sa.String(36), sa.ForeignKey("servers.id"), nullable=True),
        sa.Column("session_id", sa.String(36), sa.ForeignKey("sessions.id"), nullable=True),
        sa.Column("event_type", sa.String(128), nullable=False, index=True),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("alerted", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("resolved", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_table(
        "alert_configs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("channel", sa.String(32), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("config_json", sa.Text(), nullable=True),
        sa.Column("min_severity", sa.String(32), nullable=False, server_default="warning"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_table(
        "system_settings",
        sa.Column("key", sa.String(128), primary_key=True),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("description", sa.String(512), nullable=True),
        sa.Column("encrypted", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_table(
        "server_packages",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("server_id", sa.String(36), sa.ForeignKey("servers.id"), nullable=False),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("installed_version", sa.String(128), nullable=True),
        sa.Column("available_version", sa.String(128), nullable=True),
        sa.Column("update_available", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("server_id", "package_name"),
    )


def downgrade() -> None:
    """Drop all Bastion tables."""
    op.drop_table("server_packages")
    op.drop_table("system_settings")
    op.drop_table("alert_configs")
    op.drop_table("anomaly_events")
    op.drop_table("mfa_codes")
    op.drop_table("audit_logs")
    op.drop_table("sessions")
    op.drop_table("ssh_certificates")
    op.drop_table("cert_serials")
    op.drop_table("server_access")
    op.drop_table("servers")
    op.drop_table("users")
