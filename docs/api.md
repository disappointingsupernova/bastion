# API Reference

Both APIs are accessible only via Unix sockets on the bastion host. They are never exposed over TCP.

| Service | Socket | Group |
|---|---|---|
| `bastion-api` | `/opt/bastion/run/bastion-api.sock` | `bastion-users` |
| `bastion-admin` | `/opt/bastion/run/bastion-admin.sock` | `bastion` (admins only) |

All requests must include a valid `Authorization: Bearer <token>` header, except `/health` and the login/MFA endpoints listed below.

---

## Authentication

All protected endpoints return `401 Unauthorized` if the token is missing or invalid, and `403 Forbidden` if the user's role is insufficient.

---

## bastion-api

### `GET /health`

Returns service status. Unauthenticated.

**Response `200`**
```json
{ "status": "ok", "service": "bastion-api" }
```

---

### `POST /auth/login`

Authenticate with username and password. Rate-limited to 10/minute per IP.

Accounts are locked for 15 minutes after 10 consecutive failed attempts.

**Request**
```json
{ "username": "alice", "password": "correct-horse-battery-staple" }
```

**Response `200` — MFA not enabled**
```json
{ "access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer" }
```

**Response `200` — MFA enabled**
```json
{ "mfa_required": true, "mfa_token": "eyJ..." }
```

The `mfa_token` is a short-lived (5-minute) token that must be exchanged via `/auth/mfa/verify`.

**Errors:** `401` invalid credentials, `403` account suspended, `429` rate limit or account locked

---

### `POST /auth/mfa/verify`

Exchange an MFA token for a full access token. Supports TOTP and email methods.

**Request**
```json
{ "mfa_token": "eyJ...", "code": "123456" }
```

**Response `200`**
```json
{ "access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer" }
```

**Errors:** `401` invalid or expired MFA token or code, `400` FIDO2 accounts must use `/auth/fido2/authenticate/complete`

---

### `POST /auth/refresh`

Exchange a refresh token for a new access token.

**Request**
```json
{ "refresh_token": "eyJ..." }
```

**Response `200`**
```json
{ "access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer" }
```

---

### `POST /auth/cert/issue`

Issue an SSH certificate for the authenticated user's public key. Valid for `SSH_CERT_VALIDITY_HOURS` (default 8h). The certificate is returned in the response only — never written to disk.

**Request**
```json
{ "public_key": "ssh-ed25519 AAAA... user@host" }
```

**Response `200`**
```json
{ "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...", "valid_hours": 8, "serial": 42 }
```

---

### `POST /auth/totp/setup`

Generate a new TOTP secret. Returns the secret and `otpauth://` URI. MFA is not activated until `/auth/totp/verify` is called.

**Response `200`**
```json
{ "secret": "JBSWY3DPEHPK3PXP", "uri": "otpauth://totp/Bastion:alice?secret=...&issuer=Bastion" }
```

---

### `POST /auth/totp/verify`

Verify a TOTP code to activate MFA on the account.

**Request**
```json
{ "code": "123456" }
```

**Response `204`** — No content

---

### `POST /auth/fido2/register/begin`

Begin FIDO2 credential registration. Returns `PublicKeyCredentialCreationOptions`.

**Response `200`**
```json
{ "options": { ... } }
```

---

### `POST /auth/fido2/register/complete`

Complete FIDO2 credential registration and store the credential.

**Request**
```json
{ "credential": { "clientDataJSON": "...", "attestationObject": "..." } }
```

**Response `204`** — No content

---

### `POST /auth/fido2/authenticate/begin`

Begin FIDO2 authentication. Requires password verification. Returns challenge options and a short-lived state token. Unauthenticated endpoint.

**Request**
```json
{ "username": "alice", "password": "correct-horse-battery-staple" }
```

**Response `200`**
```json
{ "options": { "challenge_options": { ... }, "state_token": "eyJ..." } }
```

---

### `POST /auth/fido2/authenticate/complete`

Complete FIDO2 authentication and issue tokens.

**Request**
```json
{
  "mfa_token": "eyJ...",
  "credential": { "clientDataJSON": "...", "authenticatorData": "...", "signature": "...", "credentialId": "..." }
}
```

**Response `200`**
```json
{ "access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer" }
```

---

### `POST /sessions/connect`

Initiate an SSH session to a server. Validates access, issues a certificate, and returns connection details.

**Request**
```json
{ "hostname": "server1.example.com", "public_key": "ssh-ed25519 AAAA... user@host" }
```

**Response `200`**
```json
{
  "session_id": "550e8400-...",
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "hostname": "server1.example.com",
  "port": 22,
  "remote_username": "alice",
  "proxy_jump": false
}
```

**Errors:** `403` no access grant or expired grant, `404` server not found, `503` server unreachable

---

### `GET /sessions/`

List the authenticated user's sessions, most recent first.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | integer | `50` | Maximum results (max 500) |
| `offset` | integer | `0` | Pagination offset |

---

### `DELETE /sessions/{session_id}`

Terminate an active session.

**Response `204`** — No content

---

### `POST /access-requests/`

Submit a just-in-time access request. Requires `jit_access_enabled=true` on the account.

**Request**
```json
{
  "server_hostname": "server1.example.com",
  "reason": "Investigating production incident",
  "requested_duration_hours": 4,
  "allow_sudo": false
}
```

**Response `201`**

**Errors:** `403` JIT not enabled, `404` server not found, `409` pending request already exists

---

### `GET /access-requests/`

List the authenticated user's access requests.

| Parameter | Type | Description |
|---|---|---|
| `req_status` | string | Filter: `pending`, `approved`, `denied`, `expired`, `withdrawn` |

---

### `DELETE /access-requests/{request_id}`

Withdraw a pending access request.

**Response `204`** — No content

---

## bastion-admin

### `GET /health`

Returns service status. Unauthenticated.

### `GET /health/dashboard`

Returns a comprehensive health and status dashboard. Requires `admin` or `auditor` role.

**Response `200`**
```json
{
  "service": "bastion-admin",
  "status": "ok",
  "db_size_bytes": 1048576,
  "recording_storage_bytes": 52428800,
  "active_sessions": 3,
  "pending_anomaly_events": 1,
  "certs_expiring_soon": 0,
  "active_users": 12,
  "cluster_nodes": [
    { "node_id": "node-1", "version": "0.1.0", "last_heartbeat_at": "2024-01-15T14:30:00Z", "alive": true, "load_metrics": "{...}" }
  ],
  "generated_at": "2024-01-15T14:30:00Z"
}
```

---

### Users

#### `POST /users/`

Create a new Bastion user. Requires `admin` role.

**Request**
```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "strong-password",
  "full_name": "Alice Smith",
  "role": "user",
  "mfa_method": "totp"
}
```

**Roles:** `admin`, `user`, `auditor`, `read_only`
**MFA methods:** `totp`, `email`, `fido2`

**Response `201`**

**Errors:** `400` reserved username, `409` username or email already exists

---

#### `GET /users/`

List all users. Requires `admin`, `auditor`, or `read_only` role.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `include_deleted` | boolean | `false` | Include soft-deleted users |

---

#### `GET /users/{user_id}`

Retrieve a single user. Requires `admin`, `auditor`, or `read_only` role.

---

#### `PATCH /users/{user_id}`

Update a user's details. Requires `admin` role.

**Request** (all fields optional)
```json
{
  "email": "newemail@example.com",
  "full_name": "Alice Jones",
  "role": "auditor",
  "mfa_method": "email",
  "password": "new-password",
  "ssh_public_key": "ssh-ed25519 AAAA...",
  "ip_allowlist": ["10.0.0.0/8", "192.168.1.0/24"]
}
```

---

#### `POST /users/{user_id}/suspend`

Suspend a user account. Requires `admin` role. **Response `204`**

---

#### `DELETE /users/{user_id}`

Soft-delete a user account. Requires `admin` role. **Response `204`**

---

### Servers

#### `POST /servers/`

Onboard a new server. Requires `admin` role.

**Request**
```json
{
  "hostname": "server1.example.com",
  "display_name": "Production Web Server",
  "ssh_port": 22,
  "os_family": "debian",
  "tags": ["production", "web"],
  "notes": "Primary web server",
  "proxy_jump_hostname": null,
  "environment": "production",
  "ip_allowlist": ["10.0.0.0/8"],
  "session_policy": { "block_scp": true, "block_port_forwarding": true }
}
```

**OS families:** `debian`, `rhel`, `unknown`

**Response `201`**

---

#### `GET /servers/`

List all onboarded servers. Requires `admin`, `auditor`, or `read_only` role.

---

#### `POST /servers/{server_id}/access`

Grant a user access to a server. Requires `admin` role.

**Request**
```json
{
  "user_id": "550e8400-...",
  "allow_sudo": false,
  "remote_username": "alice",
  "expires_at": "2024-02-01T00:00:00Z"
}
```

`expires_at` is optional. If set, the access grant auto-revokes at that time.

**Response `201`**

---

#### `DELETE /servers/{server_id}/access/{user_id}`

Revoke a user's access to a server. Requires `admin` role. **Response `204`**

---

#### `POST /servers/{server_id}/provision`

Queue a provisioning task. Creates Unix accounts for all granted users, applies SSH hardening, distributes the CA public key. Requires `admin` role.

**Response `202`**

---

#### `GET /servers/{server_id}/packages`

List tracked packages. Requires `admin`, `auditor`, or `read_only` role.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `updates_only` | boolean | `false` | Only packages with updates available |

---

#### `POST /servers/{server_id}/packages/update`

Queue a package update task. Requires `admin` role.

**Request**
```json
{ "package_names": ["openssl", "curl"] }
```

Omit `package_names` or set to `null` to update all packages.

**Response `202`**

---

#### `POST /servers/{server_id}/reboot`

Queue a reboot. `delay_seconds` must be between 60 and 3600. Requires `admin` role.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `delay_seconds` | integer | `60` | Seconds before reboot (60–3600) |

**Response `202`**

---

#### `DELETE /servers/{server_id}`

Soft-delete a server. Requires `admin` role. **Response `204`**

---

### Certificates

#### `POST /certificates/host`

Issue an SSH host certificate for a managed server. Requires `admin` role.

**Request**
```json
{
  "hostname": "server1.example.com",
  "host_public_key": "ssh-ed25519 AAAA...",
  "validity_hours": 192
}
```

**Response `200`**
```json
{ "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...", "hostname": "server1.example.com" }
```

---

#### `GET /certificates/`

List SSH certificates. Requires `admin`, `auditor`, or `read_only` role.

| Parameter | Type | Description |
|---|---|---|
| `user_id` | string | Filter by user |
| `cert_status` | string | `active`, `expired`, `revoked` |
| `limit` | integer | Default `100`, max `500` |
| `offset` | integer | Default `0` |

---

#### `POST /certificates/{cert_id}/revoke`

Revoke a certificate and rebuild the KRL. Requires `admin` role.

**Request**
```json
{ "reason": "User account compromised" }
```

**Response `204`** — No content

---

### Sessions (Admin)

#### `GET /sessions/`

List all sessions across all users. Requires `admin`, `auditor`, or `read_only` role.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `active_only` | boolean | `false` | Only active sessions |
| `limit` | integer | `100` | Max results (max 500) |
| `offset` | integer | `0` | Pagination offset |

---

#### `POST /sessions/{session_id}/terminate`

Forcibly terminate an active session in real-time via Redis kill signal. Requires `admin` role.

**Response `204`** — No content

---

#### `GET /sessions/{session_id}/tail`

Stream live output of an active session as Server-Sent Events. Requires `admin` role.

Each event contains a chunk of terminal output. The stream ends when the session terminates with `data: [SESSION_ENDED]`.

**Response `200`** — `text/event-stream`

---

#### `POST /sessions/{session_id}/playback`

Stream a decrypted session recording. The admin provides their age identity (private key) in the request body. Requires `admin` role.

**Request**
```json
{ "age_identity": "AGE-SECRET-KEY-1..." }
```

**Response `200`** — `application/octet-stream` (asciinema v2 cast file)

---

#### `GET /sessions/{session_id}/playback/derived`

Stream a decrypted recording using a key derived from `RECORDINGS_MASTER_KEY`. No private key transmission required. Requires `admin` role.

**Response `200`** — `application/octet-stream`

---

### Audit

#### `GET /audit/`

Query the audit log. Requires `admin` or `auditor` role.

| Parameter | Type | Description |
|---|---|---|
| `user_id` | string | Filter by user |
| `action` | string | Partial match on action name |
| `success` | boolean | Filter by success/failure |
| `limit` | integer | Default `100`, max `500` |
| `offset` | integer | Default `0` |

---

#### `GET /audit/verify-chain`

Verify the HMAC integrity chain of the entire audit log. Requires `admin` or `auditor` role.

**Response `200`**
```json
{ "valid": true, "entries_checked": 1042, "first_broken_entry_id": null }
```

A `valid: false` response indicates tampering from `first_broken_entry_id` onwards.

---

### Access Requests (Admin)

#### `GET /access-requests/`

List all JIT access requests. Requires `admin` or `auditor` role.

| Parameter | Type | Description |
|---|---|---|
| `req_status` | string | Filter by status |
| `limit` | integer | Default `100` |
| `offset` | integer | Default `0` |

---

#### `POST /access-requests/{request_id}/review`

Approve or deny a pending JIT access request. Requires `admin` role.

**Request**
```json
{ "approved": true, "note": "Approved for incident response" }
```

**Response `204`** — No content

---

### Dual Approvals

#### `GET /dual-approvals/`

List dual-approval requests. Requires `admin` role.

| Parameter | Type | Description |
|---|---|---|
| `req_status` | string | `pending`, `approved`, `rejected`, `expired`, `cancelled` |

---

#### `POST /dual-approvals/{request_id}/review`

Approve or reject a pending dual-approval request. The reviewing admin must be different from the initiator. Requires `admin` role.

**Request**
```json
{ "approved": true, "note": "Verified with initiator out-of-band" }
```

**Response `204`** — No content

---

### User Groups

#### `POST /groups/`

Create a user group. Requires `admin` role.

**Request**
```json
{ "name": "platform-team", "description": "Platform engineering team" }
```

**Response `201`**

---

#### `GET /groups/`

List all groups. Requires `admin`, `auditor`, or `read_only` role.

---

#### `POST /groups/{group_id}/members/{user_id}`

Add a user to a group. Automatically provisions them on all group servers. Requires `admin` role.

**Response `204`** — No content

---

#### `DELETE /groups/{group_id}/members/{user_id}`

Remove a user from a group. Requires `admin` role. **Response `204`**

---

#### `POST /groups/{group_id}/servers`

Grant a group access to a server. All current members are provisioned immediately. Requires `admin` role.

**Request**
```json
{ "server_id": "550e8400-...", "allow_sudo": false, "remote_username": "deploy" }
```

**Response `201`**

---

### Compliance

#### `GET /compliance/reports/{report_type}`

Generate and download a compliance report. Requires `admin` or `auditor` role.

**Report types:** `access_matrix`, `sessions`, `cert_history`, `failed_auth`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `fmt` | string | `csv` | `csv` or `pdf` |
| `days` | integer | `30` | Lookback window (ignored for `access_matrix`) |

**Response `200`** — `text/csv` or `application/pdf`

---

#### `POST /compliance/reports/email`

Generate a compliance report and deliver it by email. Requires `admin` or `auditor` role.

**Request**
```json
{ "report_type": "access_matrix", "fmt": "csv", "recipient": "auditor@example.com", "days": 30 }
```

**Response `202`**

---

### Import

#### `POST /import/users/csv`

Bulk import users from a CSV file. Requires `admin` role.

Expected columns: `username`, `email`, `full_name` (optional), `role` (optional), `password` (optional).

**Response `200`**
```json
{ "created": 42, "skipped": 3, "errors": ["Row 5: missing email — skipped."] }
```

---

#### `POST /import/users/ldap-sync`

Synchronise users from LDAP/Active Directory. Creates new users, suspends disabled or removed accounts. Requires `admin` role. Requires `LDAP_URL` and related settings to be configured.

**Response `200`**
```json
{ "created": 5, "suspended": 2, "errors": [] }
```

---

## Error Responses

All errors follow a consistent format:

```json
{ "detail": "Human-readable error message." }
```

| Status | Meaning |
|---|---|
| `400` | Bad request — invalid input |
| `401` | Unauthenticated — missing or invalid token |
| `403` | Forbidden — insufficient role |
| `404` | Resource not found |
| `409` | Conflict — resource already exists |
| `422` | Validation error — request body failed Pydantic validation |
| `429` | Rate limit exceeded or account locked |
| `500` | Internal server error |
| `501` | Feature not configured (e.g. LDAP not set up) |
| `503` | Service unavailable (e.g. target server unreachable) |
