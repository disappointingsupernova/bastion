# Changelog

All notable changes to Bastion are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Bastion adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Initial public release

---

## [0.1.0] — 2026-09-10

### Added
- SSH Certificate Authority — Ed25519 CA, 8-hour certificate issuance, KRL-based revocation
- User-facing API (`bastion-api`) over Unix socket — authentication, MFA, cert issuance, session management
- Admin API (`bastion-admin`) over Unix socket — user lifecycle, server onboarding, access grants, audit queries
- `bastion` CLI — `login`, `connect`, `sessions`, `cert` commands
- `bastion-admin` CLI — `user`, `server`, `access`, `cert`, `audit`, `packages` commands
- Two-factor authentication — TOTP and email-based MFA codes
- SSH proxy — sits in the middle of every connection, records sessions in asciinema v2 format
- Session recording encryption with `age` (X25519 asymmetric encryption)
- Session recording offload to S3 or NFS
- Remote server provisioning — Unix account creation, SSH hardening, sudo configuration
- Package update management — scan and apply updates on remote servers (Debian and RHEL)
- Server reboot management
- Proxy jump support for servers behind edge hosts
- Heuristic anomaly detection — scores login events, sessions, and certificate issuance
- Multi-channel alerting — SMTP, AWS SES, Slack, PagerDuty, Pushover
- Full audit trail — every action logged to the database before and after execution
- Celery background workers — connectivity checks, package scans, cert expiry, alert dispatch, recording offload
- SQLAlchemy ORM with SQLite (default) and PostgreSQL (HA mode) support
- Alembic database migrations
- High-availability mode — stateless nodes sharing a PostgreSQL database
- Idempotent `install.sh` and `update.sh` scripts for Ubuntu
- Systemd service units for all four services
- SSH hardening applied to both the bastion host and remote servers
- User roles — `admin`, `user`, `auditor`, `read_only`
- Soft-delete pattern for users and servers
- Structured logging with `structlog`
- Rate limiting on all authentication endpoints

[Unreleased]: https://github.com/disappointingsupernova/bastion/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/disappointingsupernova/bastion/releases/tag/v0.1.0
