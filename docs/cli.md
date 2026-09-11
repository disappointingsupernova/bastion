# CLI Reference

The `bastion` CLI is the primary interface for users on the bastion host. It communicates with the `bastion-api` service over a Unix socket — no network access is required.

The `bastion-admin` CLI provides administrative commands and communicates with the `bastion-admin` service.

---

## Prerequisites

- Your system user must be in the `bastion-users` group
- You must have an SSH keypair at `~/.ssh/id_ed25519` (or specify one with `--identity`)
- The `bastion-api` service must be running

---

## `bastion` — User CLI

### `bastion login`

Authenticate to the Bastion service. Prompts for username and password. If MFA is enabled, you will be prompted for your TOTP code, email code, or FIDO2 hardware key.

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

The certificate is written to a temporary directory and deleted when the SSH process exits.

---

### `bastion sessions`

List your recent SSH sessions.

```bash
bastion sessions
```

**Options**

| Flag | Description |
|---|---|
| `--limit` | Number of sessions to display. Default `20`. |

---

### `bastion cert`

Issue a new SSH certificate for your public key.

```bash
bastion cert
# ✓ Certificate issued — serial 42, valid for 8h
```

**Options**

| Flag | Description |
|---|---|
| `--identity`, `-i` | Path to your SSH public key. Defaults to `~/.ssh/id_ed25519.pub`. |

---

### `bastion access-request`

Submit a just-in-time access request for a server. Requires `jit_access_enabled` on your account.

```bash
bastion access-request create server1.example.com \
  --reason "Investigating production incident" \
  --duration 4
```

**Options**

| Flag | Description |
|---|---|
| `--reason` | Reason for the request (10–1024 characters, required) |
| `--duration` | Requested duration in hours (1–72) |
| `--sudo` | Request sudo access |

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
| `--mfa-method` | No | `totp`, `email`, or `fido2` |
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
  --port 22 \
  --environment production
```

**Options**

| Flag | Required | Description |
|---|---|---|
| `--os-family` | No | `debian`, `rhel`, `unknown`. Default `unknown`. |
| `--display-name` | No | Human-readable name |
| `--port` | No | SSH port. Default `22`. |
| `--proxy-jump` | No | Hostname of a proxy jump server |
| `--tags` | No | Comma-separated tags |
| `--environment` | No | Environment label (e.g. `production`, `staging`) |

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
| `--expires-at` | ISO 8601 datetime for time-limited access (e.g. `2024-02-01T00:00:00Z`) |

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

#### `bastion-admin cert host-issue`

Issue an SSH host certificate for a managed server.

```bash
bastion-admin cert host-issue server1.example.com \
  --public-key "$(cat /etc/ssh/ssh_host_ed25519_key.pub)"
```

---

### `bastion-admin group` commands

#### `bastion-admin group create`

Create a user group.

```bash
bastion-admin group create platform-team --description "Platform engineering"
```

---

#### `bastion-admin group list`

List all groups.

```bash
bastion-admin group list
```

---

#### `bastion-admin group add-member`

Add a user to a group. Automatically provisions them on all group servers.

```bash
bastion-admin group add-member platform-team alice
```

---

#### `bastion-admin group remove-member`

Remove a user from a group.

```bash
bastion-admin group remove-member platform-team alice
```

---

#### `bastion-admin group grant-server`

Grant a group access to a server.

```bash
bastion-admin group grant-server platform-team server1.example.com --sudo
```

---

### `bastion-admin session` commands

#### `bastion-admin session list`

List all sessions across all users.

```bash
bastion-admin session list
bastion-admin session list --active-only
```

---

#### `bastion-admin session terminate <session-id>`

Forcibly terminate an active session in real-time.

```bash
bastion-admin session terminate 550e8400-...
```

---

#### `bastion-admin session tail <session-id>`

Stream live output of an active session.

```bash
bastion-admin session tail 550e8400-...
```

---

#### `bastion-admin session playback <session-id>`

Stream a decrypted session recording.

```bash
# Using a custom age identity
bastion-admin session playback 550e8400-... --identity bastion-recordings.key

# Using a derived key (requires RECORDINGS_MASTER_KEY)
bastion-admin session playback 550e8400-... --derived
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

#### `bastion-admin audit verify-chain`

Verify the HMAC integrity chain of the entire audit log.

```bash
bastion-admin audit verify-chain
# ✓ Audit chain valid — 1042 entries checked.
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

### `bastion-admin compliance` commands

#### `bastion-admin compliance report`

Generate and download a compliance report.

```bash
bastion-admin compliance report access_matrix
bastion-admin compliance report sessions --days 90 --format pdf
bastion-admin compliance report cert_history --format csv
bastion-admin compliance report failed_auth
```

**Report types:** `access_matrix`, `sessions`, `cert_history`, `failed_auth`

---

#### `bastion-admin compliance email`

Generate a compliance report and deliver it by email.

```bash
bastion-admin compliance email access_matrix --recipient auditor@example.com
```

---

### `bastion-admin access-request` commands

#### `bastion-admin access-request list`

List all JIT access requests.

```bash
bastion-admin access-request list
bastion-admin access-request list --status pending
```

---

#### `bastion-admin access-request review <request-id>`

Approve or deny a pending JIT access request.

```bash
bastion-admin access-request review <id> --approve --note "Approved for incident"
bastion-admin access-request review <id> --deny --note "Not authorised"
```

---

### `bastion-admin dual-approval` commands

#### `bastion-admin dual-approval list`

List pending dual-approval requests.

```bash
bastion-admin dual-approval list
bastion-admin dual-approval list --status pending
```

---

#### `bastion-admin dual-approval review <request-id>`

Approve or reject a pending dual-approval request. You must be a different admin from the initiator.

```bash
bastion-admin dual-approval review <id> --approve
bastion-admin dual-approval review <id> --reject --note "Cannot verify"
```

---

### `bastion-admin import` commands

#### `bastion-admin import csv <file>`

Bulk import users from a CSV file.

```bash
bastion-admin import csv users.csv
```

Expected columns: `username`, `email`, `full_name` (optional), `role` (optional), `password` (optional).

---

#### `bastion-admin import ldap-sync`

Synchronise users from LDAP/Active Directory.

```bash
bastion-admin import ldap-sync
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
