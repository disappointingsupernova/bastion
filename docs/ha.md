# High-Availability Mode

Bastion supports high-availability deployment with multiple nodes sharing a single PostgreSQL database. All nodes are stateless — the database is the single source of truth.

---

## Architecture

```mermaid
graph TB
    subgraph Users
        U1[User 1]
        U2[User 2]
    end

    subgraph Load Balancer
        LB[SSH Load Balancer\ne.g. HAProxy / AWS NLB]
    end

    subgraph Node 1
        SSH1[sshd :22]
        API1[bastion-api]
        ADMIN1[bastion-admin]
        W1[Celery Worker]
        BEAT1[Celery Beat]
    end

    subgraph Node 2
        SSH2[sshd :22]
        API2[bastion-api]
        ADMIN2[bastion-admin]
        W2[Celery Worker]
    end

    subgraph Shared Infrastructure
        PG[(PostgreSQL\nShared DB)]
        REDIS[(Redis\nCelery Broker)]
        S3[S3 / NFS\nSession Recordings]
    end

    U1 --> LB
    U2 --> LB
    LB --> SSH1
    LB --> SSH2
    SSH1 --> API1
    SSH2 --> API2
    API1 --> PG
    API2 --> PG
    ADMIN1 --> PG
    ADMIN2 --> PG
    W1 --> REDIS
    W2 --> REDIS
    W1 --> PG
    W2 --> PG
    W1 -->|offload recordings| S3
    W2 -->|offload recordings| S3
    BEAT1 -->|schedules tasks| REDIS

    note1[Only one node should\nrun Celery Beat]
```

> **Note:** Only one node should run `bastion-beat`. Running multiple beat instances will cause duplicate task execution.

---

## Requirements

| Component | Requirement |
|---|---|
| Database | PostgreSQL 14 or later, shared across all nodes |
| Redis | Redis 7.x, shared across all nodes |
| Session recordings | S3 or NFS — local storage is not permitted in HA mode |
| Node IDs | Each node must have a unique `NODE_ID` in its `.env` |

---

## Setup

### 1. Provision a shared PostgreSQL instance

```sql
CREATE USER bastion WITH PASSWORD 'strongpassword';
CREATE DATABASE bastion OWNER bastion;
GRANT ALL PRIVILEGES ON DATABASE bastion TO bastion;
```

### 2. Configure each node

On each bastion node, set the following in `/opt/bastion/.env`:

```env
HA_MODE=true
NODE_ID=node-1   # Unique per node: node-1, node-2, etc.

DB_BACKEND=postgres
DB_URL=postgresql+asyncpg://bastion:strongpassword@db-host:5432/bastion

REDIS_URL=redis://redis-host:6379/0

RECORDINGS_STORAGE=s3
RECORDINGS_S3_BUCKET=my-bastion-recordings
```

### 3. Share the CA keypair

All nodes must use the **same CA keypair**. Copy the CA keys from the first node to all subsequent nodes:

```bash
# On node 1:
sudo cat /opt/bastion/ca/bastion_ca
sudo cat /opt/bastion/ca/bastion_ca.pub

# On node 2 (as root):
mkdir -p /opt/bastion/ca
echo "<private key>" > /opt/bastion/ca/bastion_ca
echo "<public key>" > /opt/bastion/ca/bastion_ca.pub
chmod 700 /opt/bastion/ca
chmod 600 /opt/bastion/ca/bastion_ca
chmod 644 /opt/bastion/ca/bastion_ca.pub
chown -R bastion:bastion /opt/bastion/ca
```

### 4. Run the install script on each node

```bash
sudo bash scripts/install.sh
```

The install script is idempotent. On subsequent nodes, it will detect the existing CA keypair and skip generation.

### 5. Disable Celery Beat on all but one node

On all nodes except the primary scheduler, disable the beat service:

```bash
sudo systemctl disable bastion-beat
sudo systemctl stop bastion-beat
```

### 6. Run database migrations once

Migrations only need to be run once, from any node:

```bash
cd /opt/bastion/app
sudo -u bastion PYTHONPATH=/opt/bastion/app \
    /opt/bastion/venv/bin/alembic upgrade head
```

---

## KRL Distribution

In HA mode, the KRL file is rebuilt on whichever node processes a revocation request. The KRL must be distributed to all remote servers. Options:

1. **Shared NFS mount** — mount the same NFS share at `/opt/bastion/ca/` on all nodes
2. **Periodic sync** — use a cron job or Celery task to sync the KRL from the database to all nodes
3. **OCSP-style endpoint** — a future enhancement

For now, the simplest approach is to mount the CA directory from shared NFS storage.

---

## Failover

Because all nodes are stateless and share the database, failover is automatic. If a node fails:

- The load balancer stops routing new SSH connections to it
- In-flight sessions on the failed node are terminated (the session record will remain in `active` status and should be cleaned up manually or via a future task)
- All other functionality continues on the remaining nodes

---

## Scaling

Additional nodes can be added at any time by running `install.sh` with the shared database and Redis configuration. There is no upper limit on the number of nodes.
