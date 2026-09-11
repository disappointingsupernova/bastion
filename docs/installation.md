# Installation

This guide covers a full installation of the Bastion service on a dedicated Ubuntu 22.04 or 24.04 server.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| Operating system | Ubuntu 22.04 LTS or 24.04 LTS |
| CPU | 2 vCPU minimum |
| RAM | 2 GB minimum, 4 GB recommended |
| Disk | 20 GB minimum (more if storing session recordings locally) |
| Network | Dedicated host, reachable by users via SSH on port 22 |
| Python | 3.11 or later (installed by `install.sh`) |
| Redis | 7.x (installed by `install.sh`) |
| `age` | For session recording encryption (installed by `install.sh`) |

The bastion host should be a **dedicated server** — do not run other services on it. It should not be directly reachable from the internet on any port other than SSH (22).

---

## Installation Steps

### 1. Clone the repository

```bash
git clone https://github.com/disappointingsupernova/bastion /opt/bastion-src
cd /opt/bastion-src
```

### 2. Run the install script

```bash
sudo bash scripts/install.sh
```

The script is fully idempotent — it is safe to run multiple times. It will:

- Install system dependencies (`python3.11`, `redis-server`, `age`, `openssh-client`, etc.)
- Create the `bastion` system user and `bastion-users` group
- Create the directory structure under `/opt/bastion/`
- Set up a Python virtual environment
- Copy application code to `/opt/bastion/app/`
- Install Python dependencies
- Generate a `SECRET_KEY` and write an initial `.env` file
- Generate the SSH CA keypair at `/opt/bastion/ca/bastion_ca`, encrypted with a generated passphrase
- Store the CA passphrase in `/opt/bastion/.env` as `CA_KEY_PASSPHRASE`
- Install and enable systemd service units
- Apply SSH hardening to the bastion host itself

### 3. Review the environment file

```bash
sudo nano /opt/bastion/.env
```

At minimum, review:

- `SECRET_KEY` — auto-generated, do not change after first use
- `CA_KEY_PASSPHRASE` — auto-generated, back this up alongside the CA key
- `RECORDINGS_AGE_PUBLIC_KEY` — set this to your `age` public key to enable encrypted recordings
- `SMTP_*` or `SES_*` — configure at least one alert channel

See [configuration.md](configuration.md) for all available settings.

### 4. Back up the CA private key and passphrase

```bash
# The CA private key and its passphrase are the most critical secrets in the system.
# If either is lost, all issued certificates become unverifiable.
sudo cat /opt/bastion/ca/bastion_ca
sudo grep CA_KEY_PASSPHRASE /opt/bastion/.env
```

Store both in a password manager, encrypted USB drive, or secrets manager. **Do not store them in the same location as the bastion host.**

### 5. Add users to the bastion-users group

Any system user who should be able to use the `bastion` CLI must be in the `bastion-users` group:

```bash
sudo usermod -aG bastion-users yourusername
```

Users must log out and back in for the group change to take effect.

### 6. Create the first admin user

The admin API is accessible only to members of the `bastion` group. Use `curl` over the Unix socket to bootstrap the first admin:

```bash
sudo -u bastion curl --unix-socket /opt/bastion/run/bastion-admin.sock \
    -X POST http://bastion/users/ \
    -H 'Content-Type: application/json' \
    -d '{
        "username": "yourusername",
        "email": "you@example.com",
        "password": "a-strong-password",
        "role": "admin"
    }'
```

After this, use the `bastion-admin` CLI for all subsequent admin operations.

### 7. Distribute the CA public key to remote servers

Remote servers must trust the Bastion CA. Copy the public key to each remote server:

```bash
# On the bastion host:
cat /opt/bastion/ca/bastion_ca.pub

# On each remote server (as root):
echo "<paste public key here>" > /etc/ssh/bastion_ca.pub
chmod 644 /etc/ssh/bastion_ca.pub
```

Then add to `/etc/ssh/sshd_config.d/99-bastion.conf`:

```
TrustedUserCAKeys /etc/ssh/bastion_ca.pub
RevokedKeys /etc/ssh/bastion_krl
```

Restart sshd:

```bash
sshd -t && systemctl restart sshd
```

The bastion's provisioning module handles this automatically when you run `bastion-admin server provision <server-id>`.

### 8. Verify services are running

```bash
systemctl status bastion-api bastion-admin bastion-worker bastion-beat
```

All four services should show `active (running)`.

---

## Post-Installation

### Onboard your first server

```bash
bastion-admin server add server1.example.com --os-family debian
```

### Grant a user access

```bash
bastion-admin access grant --user yourusername --server server1.example.com
```

### Connect

```bash
bastion login
bastion connect server1.example.com
```

---

## Optional: Enable recording encryption

Generate an age keypair and configure recording encryption:

```bash
age-keygen -o /secure/offline/bastion-recordings.key
# Public key: age1...
```

Add to `/opt/bastion/.env`:

```env
RECORDINGS_AGE_PUBLIC_KEY=age1...
```

Restart the services:

```bash
sudo systemctl restart bastion-api bastion-worker
```

Store `bastion-recordings.key` securely offline — it is required to decrypt recordings.

---

## Optional: Enable per-admin derived decrypt keys

If you want admins to decrypt recordings via the API without transmitting private keys, configure a master key:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Add to `/opt/bastion/.env`:

```env
RECORDINGS_MASTER_KEY=<generated-key>
```

---

## Updating

```bash
cd /opt/bastion-src
git pull
sudo bash scripts/update.sh
```

The update script stops services, syncs code, updates dependencies, runs database migrations, and restarts services.

---

## Uninstalling

```bash
# Stop and disable services
sudo systemctl stop bastion-api bastion-admin bastion-worker bastion-beat
sudo systemctl disable bastion-api bastion-admin bastion-worker bastion-beat
sudo rm /etc/systemd/system/bastion-*.service
sudo systemctl daemon-reload

# Remove application files
sudo rm -rf /opt/bastion

# Remove system user and groups
sudo userdel bastion
sudo groupdel bastion
sudo groupdel bastion-users

# Remove CLI
sudo rm /usr/local/bin/bastion /usr/local/bin/bastion-admin
```

---

## Troubleshooting

### Services fail to start

```bash
journalctl -u bastion-api -n 100 --no-pager
```

Common causes:
- Missing or malformed `.env` file
- `SECRET_KEY` shorter than 32 bytes (rejected at startup)
- Redis not running (`systemctl start redis-server`)
- Python dependency not installed (`/opt/bastion/venv/bin/pip install -r /opt/bastion/app/requirements.txt`)

### Socket permission denied

Ensure your user is in the `bastion-users` group:

```bash
groups yourusername
```

If not, add them and log out/in:

```bash
sudo usermod -aG bastion-users yourusername
```

### CA key not found

If `/opt/bastion/ca/bastion_ca` is missing, regenerate it:

```bash
CA_PASSPHRASE=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "CA_KEY_PASSPHRASE=${CA_PASSPHRASE}" >> /opt/bastion/.env
sudo -u bastion /opt/bastion/venv/bin/python -c "
import sys; sys.path.insert(0, '/opt/bastion/app')
from bastion.crypto.ca import generate_ca_keypair
from pathlib import Path
generate_ca_keypair(Path('/opt/bastion/ca/bastion_ca'), passphrase=b'${CA_PASSPHRASE}')
"
```

**Note:** Regenerating the CA key invalidates all previously issued certificates. You must redistribute the new public key to all remote servers.

### Certificate issuance fails

Ensure `CA_KEY_PASSPHRASE` in `/opt/bastion/.env` matches the passphrase used when the CA key was generated. If the passphrase is wrong, `ssh-keygen` will fail with a decryption error.
