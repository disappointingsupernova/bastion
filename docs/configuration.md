# Configuration

All configuration is loaded from `/opt/bastion/.env`. The file is owned by the `bastion` system user with mode `600` — no other user can read it.

Settings can also be provided as environment variables, which take precedence over the `.env` file.

---

## Core Settings

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | — | **Required.** Used for JWT signing and Fernet key derivation. Generate with `python3 -c "import secrets; print(secrets.token_hex(64))"`. Never change after first use — doing so invalidates all tokens and encrypted secrets. |
| `ENVIRONMENT` | `production` | Set to `development` for human-readable logs and SQLAlchemy query echo. |
| `HA_MODE` | `false` | Enable high-availability mode. Requires a shared PostgreSQL database. |
| `NODE_ID` | `node-1` | Unique identifier for this node. Used in audit logs. |

---

## Database

| Variable | Default | Description |
|---|---|---|
| `DB_BACKEND` | `sqlite` | Database backend. `sqlite` for single-node, `postgres` for HA. |
| `DB_URL` | `sqlite+aiosqlite:////opt/bastion/data/bastion.db` | Full SQLAlchemy async database URL. For PostgreSQL: `postgresql+asyncpg://user:pass@host/dbname` |

### SQLite (default, single-node)

No additional configuration required. The database file is created automatically at `/opt/bastion/data/bastion.db`.

### PostgreSQL (HA mode)

```env
DB_BACKEND=postgres
DB_URL=postgresql+asyncpg://bastion:strongpassword@db-host:5432/bastion
HA_MODE=true
```

---

## Redis

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL. Used as the Celery broker and result backend. |

---

## Unix Sockets

| Variable | Default | Description |
|---|---|---|
| `BASTION_API_SOCKET` | `/opt/bastion/run/bastion-api.sock` | Path to the user-facing API Unix socket. |
| `BASTION_ADMIN_SOCKET` | `/opt/bastion/run/bastion-admin.sock` | Path to the admin API Unix socket. |

These should not need to be changed in normal operation.

---

## JWT Tokens

| Variable | Default | Description |
|---|---|---|
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm. |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Access token lifetime in minutes. |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime in days. |

---

## SSH Certificate Authority

| Variable | Default | Description |
|---|---|---|
| `CA_KEY_PATH` | `/opt/bastion/ca/bastion_ca` | Path to the Ed25519 CA private key. Must be readable only by the `bastion` user. |
| `SSH_CERT_VALIDITY_HOURS` | `8` | How long issued SSH certificates are valid for. |
| `KRL_PATH` | `/opt/bastion/ca/krl` | Path to the Key Revocation List file. |

---

## Session Recordings

| Variable | Default | Description |
|---|---|---|
| `RECORDINGS_ENABLED` | `true` | Enable or disable session recording entirely. |
| `RECORDINGS_PATH` | `/opt/bastion/recordings` | Local directory for recording files. |
| `RECORDINGS_STORAGE` | `local` | Storage backend: `local`, `s3`, or `nfs`. |
| `RECORDINGS_S3_BUCKET` | — | S3 bucket name. Required when `RECORDINGS_STORAGE=s3`. |
| `RECORDINGS_S3_PREFIX` | `bastion/recordings/` | Key prefix for S3 objects. |
| `RECORDINGS_AGE_PUBLIC_KEY` | — | `age` public key for asymmetric recording encryption. If set, all recordings are encrypted on completion and the plaintext is securely deleted. Generate with `age-keygen`. |

### Generating an age keypair

```bash
age-keygen -o bastion-recordings.key
# Outputs the public key to stdout, private key to bastion-recordings.key
```

Set `RECORDINGS_AGE_PUBLIC_KEY` to the public key (the `age1...` string). Store the private key (`bastion-recordings.key`) securely offline — it is required to decrypt recordings.

---

## Two-Factor Authentication

| Variable | Default | Description |
|---|---|---|
| `TOTP_ISSUER` | `Bastion` | Issuer name shown in authenticator apps. |
| `MFA_EMAIL_CODE_EXPIRE_MINUTES` | `10` | How long email MFA codes are valid for. |

---

## Rate Limiting

| Variable | Default | Description |
|---|---|---|
| `RATE_LIMIT_AUTH_PER_MINUTE` | `10` | Maximum authentication attempts per minute per IP address. |

---

## Anomaly Detection

| Variable | Default | Description |
|---|---|---|
| `ANOMALY_SCORE_ALERT_THRESHOLD` | `70` | Heuristic score (0–100) at which an anomaly event triggers an alert. Lower values are more sensitive. |

See [anomaly.md](anomaly.md) for details on how scores are calculated.

---

## Alerting — SMTP

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | — | SMTP server hostname. |
| `SMTP_PORT` | `587` | SMTP server port. |
| `SMTP_USERNAME` | — | SMTP authentication username. |
| `SMTP_PASSWORD` | — | SMTP authentication password. |
| `SMTP_FROM_ADDRESS` | — | Sender address for alert emails. |
| `SMTP_USE_TLS` | `true` | Use STARTTLS. |

---

## Alerting — AWS SES

| Variable | Default | Description |
|---|---|---|
| `SES_REGION` | — | AWS region for SES (e.g. `eu-west-1`). |
| `SES_FROM_ADDRESS` | — | Verified sender address in SES. |

SES uses the standard AWS credential chain (`~/.aws/credentials`, instance profile, environment variables).

---

## Alerting — Slack

| Variable | Default | Description |
|---|---|---|
| `SLACK_WEBHOOK_URL` | — | Incoming webhook URL from your Slack app configuration. |

---

## Alerting — PagerDuty

| Variable | Default | Description |
|---|---|---|
| `PAGERDUTY_INTEGRATION_KEY` | — | Events API v2 integration key from your PagerDuty service. |

---

## Alerting — Pushover

| Variable | Default | Description |
|---|---|---|
| `PUSHOVER_APP_TOKEN` | — | Application token from your Pushover app. |
| `PUSHOVER_USER_KEY` | — | User or group key to deliver notifications to. |

---

## Package Checks

| Variable | Default | Description |
|---|---|---|
| `PACKAGE_CHECK_INTERVAL_HOURS` | `6` | How often the Celery beat scheduler triggers package update checks on remote servers. |

---

## Excluded System Users

| Variable | Default | Description |
|---|---|---|
| `EXCLUDED_SYSTEM_USERS` | See below | JSON array of usernames that cannot be created as Bastion users. |

Default excluded users:
```
root, ubuntu, debian, ec2-user, admin, nobody, daemon, bin, sys, sync,
games, man, lp, mail, news, uucp, proxy, www-data, backup, list, irc,
gnats, systemd-network, systemd-resolve, messagebus, sshd, bastion
```

---

## Example `.env` File

```env
# ── Core ──────────────────────────────────────────────────────────────────────
SECRET_KEY=your-64-byte-hex-secret-here
ENVIRONMENT=production
HA_MODE=false
NODE_ID=node-1

# ── Database ──────────────────────────────────────────────────────────────────
DB_BACKEND=sqlite
DB_URL=sqlite+aiosqlite:////opt/bastion/data/bastion.db

# ── Redis ─────────────────────────────────────────────────────────────────────
REDIS_URL=redis://localhost:6379/0

# ── SSH CA ────────────────────────────────────────────────────────────────────
SSH_CERT_VALIDITY_HOURS=8

# ── Session recordings ────────────────────────────────────────────────────────
RECORDINGS_ENABLED=true
RECORDINGS_STORAGE=local
RECORDINGS_AGE_PUBLIC_KEY=age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# ── 2FA ───────────────────────────────────────────────────────────────────────
TOTP_ISSUER=Bastion

# ── Anomaly detection ─────────────────────────────────────────────────────────
ANOMALY_SCORE_ALERT_THRESHOLD=70

# ── Alerting — SMTP ───────────────────────────────────────────────────────────
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=alerts@example.com
SMTP_PASSWORD=smtp-password
SMTP_FROM_ADDRESS=bastion-alerts@example.com
SMTP_USE_TLS=true

# ── Alerting — Slack ──────────────────────────────────────────────────────────
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
```
