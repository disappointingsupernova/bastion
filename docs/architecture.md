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
| Authentication | Password verification, JWT issuance, MFA flow |
| Certificate issuance | Signs user public keys with the CA, returns cert in response |
| Session management | Creates session records, initiates SSH proxy connections |
| Anomaly evaluation | Scores every login and session for suspicious behaviour |

### `bastion-admin`

The administrative API service. Listens on `/opt/bastion/run/bastion-admin.sock`. Only members of the `bastion` group (administrators) can reach this socket.

| Responsibility | Detail |
|---|---|
| User lifecycle | Create, update, suspend, soft-delete users |
| Server management | Onboard servers, configure proxy jumps, soft-delete |
| Access control | Grant and revoke per-user, per-server access with optional sudo |
| Certificate revocation | Revoke certs by ID, rebuild KRL |
| Audit queries | Read-only access to the full audit trail |
| Package management | View available updates, queue update tasks |
| Provisioning | Queue user provisioning and SSH hardening tasks |

### `bastion-worker`

Celery worker processes. Handle all background and long-running tasks.

| Task | Schedule |
|---|---|
| Connectivity checks | Every 5 minutes |
| Package update scans | Every N hours (configurable) |
| Certificate expiry | Every 15 minutes |
| Anomaly alert dispatch | Every 2 minutes |
| Recording offload (HA) | On-demand, triggered after session completion |

### `bastion-beat`

Celery beat scheduler. Triggers periodic tasks on the configured intervals. Stores its schedule in `/opt/bastion/data/celerybeat-schedule`.

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
├── audit/          Audit log writer
├── auth.py         JWT, bcrypt, TOTP, email MFA
├── anomaly.py      Heuristic anomaly scoring
├── alerting.py     Multi-channel alert dispatch
├── proxy.py        SSH proxy and asciinema session recording
└── provisioning.py Remote server provisioning over SSH
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
        User->>CLI: TOTP / email code
        CLI->>API: POST /auth/mfa/verify
        API->>DB: Verify code
    end
    API->>DB: Write audit log (success)
    API-->>CLI: access_token + refresh_token
    CLI->>CLI: Save token to ~/.bastion/token

    User->>CLI: bastion connect server1.example.com
    CLI->>API: POST /sessions/connect
    API->>DB: Check server exists and is reachable
    API->>DB: Check user has access grant
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
    participant Remote as Remote Servers

    Admin->>ACLI: bastion-admin cert revoke <cert-id>
    ACLI->>AAPI: POST /certificates/<id>/revoke
    AAPI->>DB: Mark certificate as REVOKED
    AAPI->>DB: Write audit log
    AAPI->>KRL: Rebuild KRL from all revoked serials
    AAPI-->>ACLI: 204 No Content
    Note over KRL,Remote: KRL must be distributed to remote servers
    Note over KRL,Remote: Remote servers check KRL on every connection
```

---

## Data Flow — Background Workers

```mermaid
graph LR
    BEAT[Celery Beat] -->|every 5 min| CT[connectivity.check_all_servers]
    BEAT -->|every N hours| PT[packages.check_all_servers]
    BEAT -->|every 15 min| ET[certificates.expire_old_certificates]
    BEAT -->|every 2 min| AT[alerts.dispatch_pending_anomaly_alerts]

    CT -->|update status| DB[(Database)]
    CT -->|if unreachable| ALERT[Alert Dispatch]

    PT -->|SSH into server| REMOTE[Remote Server]
    PT -->|update package records| DB

    ET -->|mark expired| DB

    AT -->|read unalerted events| DB
    AT --> ALERT
    ALERT -->|SMTP / SES / Slack\nPagerDuty / Pushover| CHANNELS[Alert Channels]
```

---

## Database Schema

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
        bool mfa_enabled
        int unix_uid
        datetime last_login_at
        datetime deleted_at
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
    }

    server_access {
        string id PK
        string user_id FK
        string server_id FK
        bool allow_sudo
        string remote_username
        bool provisioned
        datetime revoked_at
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
        string user_id FK
        string action
        string resource_type
        string resource_id
        string detail
        bool success
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

    alert_configs {
        string id PK
        string channel
        bool enabled
        string config_json
        string min_severity
    }

    server_packages {
        string id PK
        string server_id FK
        string package_name
        string installed_version
        string available_version
        bool update_available
    }

    users ||--o{ server_access : "has"
    users ||--o{ ssh_certificates : "holds"
    users ||--o{ sessions : "initiates"
    users ||--o{ audit_logs : "generates"
    servers ||--o{ server_access : "grants"
    servers ||--o{ sessions : "hosts"
    servers ||--o{ server_packages : "tracks"
    servers ||--o| servers : "jumps via"
    sessions ||--o{ anomaly_events : "triggers"
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
            CA[CA Keys\nmode 700]
            REC[Recordings\nmode 750]
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
```

See [ha.md](ha.md) for full deployment instructions.
