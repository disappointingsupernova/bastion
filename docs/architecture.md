# Architecture

This document describes the system design, component responsibilities, and data flow of the Bastion service.

---

## System Overview

Bastion is a self-hosted SSH bastion/jumphost service. It runs on a dedicated Ubuntu server and acts as the single point of entry for all SSH connections to managed remote servers. Every connection is proxied through the bastion, recorded, and audited.

The system is split into two API services, a shared library, a CLI tool, and a set of background workers. All communication between the CLI and the APIs happens over Unix sockets — no TCP ports are exposed.

---

## High-Level Architecture

```mermaid
graph TB
    subgraph Bastion Host
        U[User via SSH] -->|runs| CLI[bastion CLI]
        A[Admin via SSH] -->|runs| ACLI[bastion-admin CLI]

        CLI -->|HTTP over Unix socket| BAPI[bastion-api\nFastAPI / uvicorn]
        ACLI -->|HTTP over Unix socket| AAPI[bastion-admin\nFastAPI / uvicorn]

        BAPI --> LIB[Shared Library\nbastion/]
        AAPI --> LIB

        LIB --> DB[(SQLite / PostgreSQL)]
        LIB --> REDIS[(Redis)]
        LIB --> CA[CA Keys\n/opt/bastion/ca/]

        BAPI -->|queues tasks| WORKER[Celery Workers]
        AAPI -->|queues tasks| WORKER
        WORKER --> REDIS
        WORKER --> DB

        BEAT[Celery Beat] -->|schedules| WORKER
    end

    BAPI -->|SSH proxy| R1[Remote Server 1]
    BAPI -->|SSH proxy + jump| JUMP[Jump Host] --> R2[Remote Server 2]
```

---

## Component Responsibilities

### `bastion-api`

The user-facing API service. Listens on `/opt/bastion/run/bastion-api.sock`. Only members of the `bastion-users` group can reach this socket.

| Responsibility | Detail |
|---|---|
| Authentication | Password verification, JWT issuance, MFA flow (TOTP, email, FIDO2) |
| Certificate issuance | Signs user public keys with the CA, returns cert in response |
| Session management | Creates session records, initiates SSH proxy connections |
| Anomaly evaluation | Scores every login and session for suspicious behaviour |
| JIT access requests | Users submit and withdraw time-limited access requests |

### `bastion-admin`

The administrative API service. Listens on `/opt/bastion/run/bastion-admin.sock`. Only members of the `bastion` group (administrators) can reach this socket.

| Responsibility | Detail |
|---|---|
| User lifecycle | Create, update, suspend, soft-delete users; bulk CSV import; LDAP sync |
| Server management | Onboard servers, configure proxy jumps, session policies, IP allowlists |
| Access control | Grant and revoke per-user and per-group access with optional sudo |
| Certificate management | Revoke certs by ID, rebuild KRL, issue host certificates |
| Audit queries | Read-only access to the full audit trail; integrity chain verification |
| Package management | View available updates, queue update tasks |
| Provisioning | Queue user provisioning and SSH hardening tasks |
| Session management | List all sessions, forcibly terminate, live tail, playback recordings |
| Compliance | Generate and email access matrix, session, cert history, and failed auth reports |
| User groups | Create groups, manage membership, grant group server access |
| Dual approval | Review pending privileged action requests |
| JIT access | Approve or deny just-in-time access requests |
| Health dashboard | Service metrics, storage, active sessions, cluster node status |

### `bastion-worker`

Celery worker processes. Handle all background and long-running tasks.

| Task | Schedule |
|---|---|
| Connectivity checks | Every 5 minutes |
| Package update scans | Every N hours (configurable via `PACKAGE_CHECK_INTERVAL_HOURS`) |
| Certificate expiry marking | Every 15 minutes |
| Anomaly alert dispatch | Every 2 minutes |
| JIT access expiry | Every 5 minutes |
| SSH key age reminders | Daily at 08:00 UTC |
| Certificate expiry warnings | Every 15 minutes |
| KRL distribution | Every 30 minutes |
| Database backup | Daily at 02:00 UTC |
| Anomaly baseline refresh | Every 6 hours |
| Node heartbeat | Every minute |

### `bastion-beat`

Celery beat scheduler. Triggers periodic tasks on the configured intervals. Stores its schedule in `/opt/bastion/data/celerybeat-schedule`. Only one node should run `bastion-beat` in HA deployments.

### Shared Library (`bastion/`)

All business logic lives here. Both API services and the workers import from this library.

```
bastion/
├── config/         Settings — pydantic-settings, loaded from .env
├── db/             Async SQLAlchemy engine and session management
├── models/         ORM models for all entities
├── crypto/
│   ├── ca.py       SSH CA — key generation, cert issuance, KRL
│   └── encryption.py  age encryption, Fernet secrets at rest
├── audit/          Audit log writer with HMAC integrity chain
├── auth.py         JWT, bcrypt, TOTP, email MFA
├── fido2.py        FIDO2 / WebAuthn hardware key authentication
├── anomaly.py      Heuristic anomaly scoring with per-user baselines
├── alerting.py     Multi-channel alert dispatch
├── proxy.py        SSH proxy and asciinema session recording
├── provisioning.py Remote server provisioning over SSH
├── recordings.py   Live session tailing and recording playback
├── session_kill.py Redis pub/sub session termination
├── ip_allowlist.py CIDR-based IP allowlist enforcement
├── compliance.py   Compliance report generation (CSV/PDF)
├── dual_approval.py Dual-approval workflow for privileged actions
└── client.py       Synchronous admin API client (for IaC/Ansible)
```

---

## Data Flow — User Login and Connection

```mermaid
sequenceDiagram
    actor User
    participant CLI as bastion CLI
    participant API as bastion-api
    participant DB as Database
    participant CA as SSH CA
    participant Remote as Remote Server

    User->>CLI: bastion login
    CLI->>API: POST /auth/login
    API->>DB: Verify password hash
    API->>DB: Write audit log (attempt)
    alt MFA enabled
        API-->>CLI: mfa_token
        CLI->>User: Prompt for MFA code
        User->>CLI: TOTP / email / FIDO2
        CLI->>API: POST /auth/mfa/verify or /auth/fido2/authenticate/complete
        API->>DB: Verify code / credential
    end
    API->>DB: Write audit log (success)
    API-->>CLI: access_token + refresh_token
    CLI->>CLI: Save token to ~/.bastion/token

    User->>CLI: bastion connect server1.example.com
    CLI->>API: POST /sessions/connect
    API->>DB: Check server exists and is reachable
    API->>DB: Check user has access grant (and it has not expired)
    API->>CA: Issue SSH certificate (8h validity)
    API->>DB: Create session record
    API->>DB: Write audit log
    API-->>CLI: certificate + connection details
    CLI->>CLI: Write cert to tmpdir
    CLI->>Remote: exec ssh with cert
    Remote->>Remote: Verify cert against CA public key
    Remote->>Remote: Check KRL
    Note over CLI,Remote: Session proxied and recorded
```

---

## Data Flow — Certificate Revocation

```mermaid
sequenceDiagram
    actor Admin
    participant ACLI as bastion-admin CLI
    participant AAPI as bastion-admin
    participant DB as Database
    participant KRL as KRL File
    participant WORKER as Celery Worker
    participant Remote as Remote Servers

    Admin->>ACLI: bastion-admin cert revoke <cert-id>
    ACLI->>AAPI: POST /certificates/<id>/revoke
    AAPI->>DB: Mark certificate as REVOKED
    AAPI->>DB: Terminate active sessions using this cert
    AAPI->>DB: Write audit log
    AAPI->>KRL: Rebuild KRL from all revoked serials
    AAPI->>WORKER: Queue distribute_krl task
    AAPI-->>ACLI: 204 No Content
    WORKER->>Remote: Push KRL via SSH (CA-verified connection)
    WORKER->>Remote: Verify KRL size after write
```

---

## Data Flow — Background Workers

```mermaid
graph LR
    BEAT[Celery Beat] -->|every 5 min| CT[connectivity.check_all_servers]
    BEAT -->|every N hours| PT[packages.check_all_servers]
    BEAT -->|every 15 min| ET[certificates.expire_old_certificates]
    BEAT -->|every 2 min| AT[alerts.dispatch_pending_anomaly_alerts]
    BEAT -->|every 5 min| JIT[access_requests.expire_jit_access]
    BEAT -->|every 30 min| KRL[notifications.distribute_krl]
    BEAT -->|daily 02:00| BK[notifications.backup_database]
    BEAT -->|every 6h| BL[notifications.refresh_anomaly_baselines]

    CT -->|update status| DB[(Database)]
    CT -->|if unreachable| ALERT[Alert Dispatch]

    PT -->|SSH into server| REMOTE[Remote Server]
    PT -->|update package records| DB

    ET -->|mark expired| DB

    AT -->|read unalerted events| DB
    AT --> ALERT
    ALERT -->|SMTP / SES / Slack\nPagerDuty / Pushover\nWebhook / Syslog| CHANNELS[Alert Channels]

    JIT -->|revoke expired grants| DB
    KRL -->|push KRL via SSH| REMOTE
    BK -->|snapshot DB| S3[S3 / Local]
    BL -->|update baselines| DB
```

---

## Database Schema

The full schema is defined in `migrations/versions/0001_initial_schema.py`. Key entities:

```mermaid
erDiagram
    users {
        string id PK
        string username
        string email
        string hashed_password
        string role
        string status
        string mfa_method
        string totp_secret
        string fido2_credentials
        bool mfa_enabled
        int unix_uid
        datetime last_login_at
        datetime locked_until
        datetime deleted_at
        bool jit_access_enabled
        string ip_allowlist
    }

    servers {
        string id PK
        string hostname
        int ssh_port
        string os_family
        string status
        string proxy_jump_server_id FK
        bool hardening_applied
        datetime deleted_at
        string ip_allowlist
        string session_policy
    }

    server_access {
        string id PK
        string user_id FK
        string server_id FK
        bool allow_sudo
        string remote_username
        bool provisioned
        datetime revoked_at
        datetime expires_at
    }

    ssh_certificates {
        string id PK
        string user_id FK
        int serial
        string key_id
        string principals
        datetime valid_after
        datetime valid_before
        string status
        datetime revoked_at
        string revocation_reason
    }

    sessions {
        string id PK
        string user_id FK
        string server_id FK
        string certificate_id FK
        string status
        datetime started_at
        datetime ended_at
        string recording_path
        bool recording_encrypted
        int bytes_sent
        int bytes_received
    }

    audit_logs {
        string id PK
        int seq
        string user_id FK
        string action
        string resource_type
        string resource_id
        bool success
        string integrity_hash
        datetime created_at
    }

    anomaly_events {
        string id PK
        string user_id FK
        string server_id FK
        string session_id FK
        string event_type
        int score
        bool alerted
        bool resolved
    }

    anomaly_baselines {
        string id PK
        string user_id FK
        string typical_hours
        string known_ips
        float avg_session_duration_seconds
        float avg_session_bytes
        int sample_count
    }

    access_requests {
        string id PK
        string user_id FK
        string server_id FK
        string reason
        int requested_duration_hours
        string status
        datetime expires_at
        string server_access_id FK
    }

    dual_approval_requests {
        string id PK
        string initiated_by_user_id FK
        string action_type
        string action_payload
        string status
        datetime expires_at
        string reviewed_by_user_id FK
    }

    user_groups {
        string id PK
        string name
        datetime deleted_at
    }

    recording_decrypt_logs {
        string id PK
        string session_id FK
        string admin_user_id FK
        string key_fingerprint
    }

    bastion_nodes {
        string id PK
        string node_id
        string version
        datetime last_heartbeat_at
        string load_metrics
    }

    users ||--o{ server_access : "has"
    users ||--o{ ssh_certificates : "holds"
    users ||--o{ sessions : "initiates"
    users ||--o{ audit_logs : "generates"
    users ||--o{ access_requests : "submits"
    servers ||--o{ server_access : "grants"
    servers ||--o{ sessions : "hosts"
    servers ||--o{ server_packages : "tracks"
    servers ||--o| servers : "jumps via"
    sessions ||--o{ anomaly_events : "triggers"
    sessions ||--o{ recording_decrypt_logs : "logged by"
```

---

## Security Boundaries

```mermaid
graph TB
    subgraph Internet
        EXT[External Traffic]
    end

    subgraph Bastion Host
        subgraph SSH Layer
            SSHD[sshd\nport 22\nbastion-users group only]
        end

        subgraph User Space
            CLI[bastion CLI\nruns as logged-in user]
            ACLI[bastion-admin CLI\nruns as admin user]
        end

        subgraph Unix Sockets
            USOCK[bastion-api.sock\nmode 660\nbastion-users group]
            ASOCK[bastion-admin.sock\nmode 660\nbastion group only]
        end

        subgraph Service Layer
            BAPI[bastion-api\nruns as bastion user]
            AAPI[bastion-admin\nruns as bastion user]
        end

        subgraph Data Layer
            DB[(Database\nmode 700)]
            CA[CA Keys\nmode 700\npassphrase-encrypted]
            REC[Recordings\nmode 750\nage-encrypted]
        end
    end

    EXT -->|blocked — no open ports| Bastion Host
    SSHD -->|authenticated SSH session| CLI
    SSHD -->|authenticated SSH session| ACLI
    CLI --> USOCK
    ACLI --> ASOCK
    USOCK --> BAPI
    ASOCK --> AAPI
    BAPI --> DB
    BAPI --> CA
    BAPI --> REC
    AAPI --> DB
    AAPI --> CA
```

---

## HA Architecture

In HA mode, multiple bastion nodes share a single PostgreSQL database. All nodes are stateless — the database is the single source of truth.

```mermaid
graph TB
    subgraph Node 1
        CLI1[bastion CLI] --> API1[bastion-api]
        API1 --> W1[Celery Worker]
        BEAT1[Celery Beat]
    end

    subgraph Node 2
        CLI2[bastion CLI] --> API2[bastion-api]
        API2 --> W2[Celery Worker]
    end

    subgraph Shared Infrastructure
        PG[(PostgreSQL)]
        REDIS[(Redis)]
        S3[S3 / NFS\nSession Recordings]
    end

    API1 --> PG
    API2 --> PG
    W1 --> REDIS
    W2 --> REDIS
    W1 -->|offload recordings| S3
    W2 -->|offload recordings| S3
    BEAT1 -->|schedules tasks| REDIS
```

Only one node should run `bastion-beat`. See [ha.md](ha.md) for full deployment instructions.
