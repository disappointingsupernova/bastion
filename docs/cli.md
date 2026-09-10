# CLI Reference

The `bastion` CLI is the primary interface for users on the bastion host. It communicates with the `bastion-api` service over a Unix socket — no network access is required.

The `bastion-admin` CLI provides administrative commands and communicates with the `bastion-admin` service.

---

## Prerequisites

- Your system user must be in the `bastion-users` group
- You must have an Ed25519 SSH keypair at `~/.ssh/id_ed25519` (or specify one with `--identity`)
- The `bastion-api` service must be running

---

## `bastion` — User CLI

### `bastion login`

Authenticate to the Bastion service. Prompts for username and password. If MFA is enabled on your account, you will be prompted for your TOTP code or email code.

Your access token is stored at `~/.bastion/token` with mode `600`.

```bash
bastion login
# Username: alice
# Password: ****
# ✓ Authenticated successfully.
```

```bash
bastion login
# Username: alice
# Password: ****
# MFA code: 123456
# ✓ Authenticated successfully.
```

---

### `bastion connect <hostname>`

Connect to a remote server via the Bastion proxy. Validates your access, issues a short-lived SSH certificate, and executes `ssh` with the certificate.

```bash
bastion connect server1.example.com
# → Connecting to alice@server1.example.com:22
```

**Options**

| Flag | Description |
|---|---|
| `--identity`, `-i` | Path to your SSH private key. Defaults to `~/.ssh/id_ed25519`. |

```bash
bastion connect server1.example.com --identity ~/.ssh/id_ed25519_work
```

The certificate is written to a temporary directory and deleted when the SSH process exits. It is never stored permanently on disk.

---

### `bastion sessions`

List your recent SSH sessions.

```bash
bastion sessions
```

```
Recent Sessions
┌──────────┬──────────────────────────┬───────────┬─────────────────────┬──────────┬───────────┐
│ ID       │ Server                   │ Status    │ Started             │ Duration │ Recording │
├──────────┼──────────────────────────┼───────────┼─────────────────────┼──────────┼───────────┤
│ 550e8400 │ server1.example.com      │ completed │ 2024-01-15 14:30:00 │ 15m 32s  │ ✓         │
│ 3fa85f64 │ server2.example.com      │ completed │ 2024-01-14 09:12:00 │ 4m 18s   │ ✓         │
└──────────┴──────────────────────────┴───────────┴─────────────────────┴──────────┴───────────┘
```

**Options**

| Flag | Description |
|---|---|
| `--limit` | Number of sessions to display. Default `20`. |

---

### `bastion cert`

Issue a new SSH certificate for your public key and save it alongside your key file.

```bash
bastion cert
# ✓ Certificate issued — serial 42, valid for 8h
#   Saved to: /home/alice/.ssh/id_ed25519-cert.pub
```

**Options**

| Flag | Description |
|---|---|
| `--identity`, `-i` | Path to your SSH public key. Defaults to `~/.ssh/id_ed25519.pub`. |

---

## `bastion-admin` — Admin CLI

The admin CLI requires your user to be in the `bastion` group and communicates with the `bastion-admin` Unix socket.

### `bastion-admin login`

Authenticate to the admin API.

```bash
bastion-admin login
```

---

### `bastion-admin user` commands

#### `bastion-admin user create`

Create a new Bastion user.

```bash
bastion-admin user create \
  --username alice \
  --email alice@example.com \
  --role user \
  --mfa-method totp
```

**Options**

| Flag | Required | Description |
|---|---|---|
| `--username` | Yes | Username (must not be a reserved system user) |
| `--email` | Yes | Email address |
| `--role` | No | `admin`, `user`, `auditor`, `read_only`. Default `user`. |
| `--mfa-method` | No | `totp` or `email` |
| `--full-name` | No | Display name |

---

#### `bastion-admin user list`

List all users.

```bash
bastion-admin user list
bastion-admin user list --include-deleted
```

---

#### `bastion-admin user suspend <username>`

Suspend a user account, preventing further logins.

```bash
bastion-admin user suspend alice
```

---

#### `bastion-admin user delete <username>`

Soft-delete a user account.

```bash
bastion-admin user delete alice
```

---

### `bastion-admin server` commands

#### `bastion-admin server add <hostname>`

Onboard a new server.

```bash
bastion-admin server add server1.example.com \
  --os-family debian \
  --display-name "Production Web Server" \
  --port 22
```

**Options**

| Flag | Required | Description |
|---|---|---|
| `--os-family` | No | `debian`, `rhel`, `unknown`. Default `unknown`. |
| `--display-name` | No | Human-readable name |
| `--port` | No | SSH port. Default `22`. |
| `--proxy-jump` | No | Hostname of a proxy jump server |
| `--tags` | No | Comma-separated tags |

---

#### `bastion-admin server list`

List all onboarded servers.

```bash
bastion-admin server list
```

---

#### `bastion-admin server provision <hostname>`

Provision all granted users onto the server and apply SSH hardening.

```bash
bastion-admin server provision server1.example.com
```

---

#### `bastion-admin server reboot <hostname>`

Schedule a reboot on the server.

```bash
bastion-admin server reboot server1.example.com --delay 120
```

---

### `bastion-admin access` commands

#### `bastion-admin access grant`

Grant a user access to a server.

```bash
bastion-admin access grant \
  --user alice \
  --server server1.example.com \
  --sudo
```

**Options**

| Flag | Description |
|---|---|
| `--sudo` | Grant passwordless sudo on the remote server |
| `--remote-username` | Unix account name on the remote server. Defaults to the user's Bastion username. |

---

#### `bastion-admin access revoke`

Revoke a user's access to a server.

```bash
bastion-admin access revoke --user alice --server server1.example.com
```

---

### `bastion-admin cert` commands

#### `bastion-admin cert list`

List SSH certificates.

```bash
bastion-admin cert list
bastion-admin cert list --user alice
bastion-admin cert list --status active
```

---

#### `bastion-admin cert revoke <cert-id>`

Revoke a certificate and rebuild the KRL.

```bash
bastion-admin cert revoke 550e8400-e29b-41d4-a716-446655440000 \
  --reason "User account compromised"
```

---

### `bastion-admin audit` commands

#### `bastion-admin audit log`

Query the audit log.

```bash
bastion-admin audit log
bastion-admin audit log --user alice
bastion-admin audit log --action auth.login
bastion-admin audit log --failures-only
```

---

### `bastion-admin packages` commands

#### `bastion-admin packages list <hostname>`

List packages with available updates on a server.

```bash
bastion-admin packages list server1.example.com
bastion-admin packages list server1.example.com --updates-only
```

---

#### `bastion-admin packages update <hostname>`

Apply package updates on a server.

```bash
# Update all packages
bastion-admin packages update server1.example.com

# Update specific packages
bastion-admin packages update server1.example.com --packages openssl,curl
```

---

## Token Storage

Tokens are stored at `~/.bastion/token` (user CLI) and `~/.bastion/admin-token` (admin CLI) with mode `600`. They expire after the configured JWT lifetime (default 60 minutes for access tokens, 7 days for refresh tokens).

The CLI automatically attempts to refresh the access token using the stored refresh token when it receives a `401` response.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | General error (authentication failure, server error, etc.) |
