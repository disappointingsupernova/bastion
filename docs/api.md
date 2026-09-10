# API Reference

Both APIs are accessible only via Unix sockets on the bastion host. They are never exposed over TCP.

| Service | Socket | Group |
|---|---|---|
| `bastion-api` | `/opt/bastion/run/bastion-api.sock` | `bastion-users` |
| `bastion-admin` | `/opt/bastion/run/bastion-admin.sock` | `bastion` (admins only) |

All requests must include a valid `Authorization: Bearer <token>` header, except `/health` and the login endpoints.

---

## Authentication

All protected endpoints return `401 Unauthorized` if the token is missing or invalid, and `403 Forbidden` if the user's role is insufficient.

---

## bastion-api

### Health

#### `GET /health`

Returns service status. Unauthenticated.

**Response `200`**
```json
{ "status": "ok", "service": "bastion-api" }
```

---

### Authentication — `POST /auth/login`

Authenticate with username and password.

**Request**
```json
{
  "username": "alice",
  "password": "correct-horse-battery-staple"
}
```

**Response `200` — MFA not enabled**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer"
}
```

**Response `200` — MFA enabled**
```json
{
  "mfa_required": true,
  "mfa_token": "eyJ..."
}
```

The `mfa_token` is a short-lived (5-minute) token that must be exchanged via `/auth/mfa/verify`.

**Errors**
- `401` — Invalid credentials
- `403` — Account suspended or deleted
- `429` — Rate limit exceeded

---

### Authentication — `POST /auth/mfa/verify`

Exchange an MFA token for a full access token.

**Request**
```json
{
  "mfa_token": "eyJ...",
  "code": "123456"
}
```

**Response `200`**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer"
}
```

**Errors**
- `401` — Invalid or expired MFA token, or incorrect code

---

### Authentication — `POST /auth/refresh`

Exchange a refresh token for a new access token.

**Request**
```json
{ "refresh_token": "eyJ..." }
```

**Response `200`**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer"
}
```

---

### Certificates — `POST /auth/cert/issue`

Issue an SSH certificate for the authenticated user's public key.

**Request**
```json
{
  "public_key": "ssh-ed25519 AAAA... user@host"
}
```

**Response `200`**
```json
{
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "valid_hours": 8,
  "serial": 42
}
```

The certificate is returned in the response body only — it is never written to disk on the server.

**Errors**
- `401` — Not authenticated

---

### TOTP Setup — `POST /auth/totp/setup`

Generate a new TOTP secret for the authenticated user. Returns the secret and a `otpauth://` URI for QR code generation.

**Response `200`**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "uri": "otpauth://totp/Bastion:alice?secret=JBSWY3DPEHPK3PXP&issuer=Bastion"
}
```

---

### Sessions — `POST /sessions/connect`

Initiate an SSH session to a server. Validates access, issues a certificate, and returns connection details.

**Request**
```json
{
  "hostname": "server1.example.com",
  "public_key": "ssh-ed25519 AAAA... user@host"
}
```

**Response `200`**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "hostname": "server1.example.com",
  "port": 22,
  "remote_username": "alice",
  "proxy_jump": false
}
```

**Errors**
- `403` — No access grant for this server
- `404` — Server not found
- `503` — Server is currently unreachable

---

### Sessions — `GET /sessions/`

List the authenticated user's sessions, most recent first.

**Query parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | integer | `50` | Maximum number of results |
| `offset` | integer | `0` | Pagination offset |

**Response `200`**
```json
[
  {
    "id": "550e8400-...",
    "server_hostname": "server1.example.com",
    "status": "completed",
    "started_at": "2024-01-15T14:30:00Z",
    "ended_at": "2024-01-15T14:45:00Z",
    "bytes_sent": 1024,
    "bytes_received": 8192,
    "recording_available": true
  }
]
```

---

### Sessions — `DELETE /sessions/{session_id}`

Terminate an active session.

**Response `204`** — No content

**Errors**
- `404` — Session not found or not active

---

## bastion-admin

### Health

#### `GET /health`

Returns service status. Unauthenticated.

---

### Users — `POST /users/`

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

**MFA methods:** `totp`, `email`

**Response `201`**
```json
{
  "id": "550e8400-...",
  "username": "alice",
  "email": "alice@example.com",
  "full_name": "Alice Smith",
  "role": "user",
  "status": "active",
  "mfa_enabled": false,
  "mfa_method": "totp",
  "last_login_at": null,
  "created_at": "2024-01-15T12:00:00Z"
}
```

**Errors**
- `400` — Reserved username
- `409` — Username or email already exists

---

### Users — `GET /users/`

List all users. Requires `admin`, `auditor`, or `read_only` role.

**Query parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `include_deleted` | boolean | `false` | Include soft-deleted users |

---

### Users — `GET /users/{user_id}`

Retrieve a single user. Requires `admin`, `auditor`, or `read_only` role.

---

### Users — `PATCH /users/{user_id}`

Update a user's details. Requires `admin` role.

**Request** (all fields optional)
```json
{
  "email": "newemail@example.com",
  "full_name": "Alice Jones",
  "role": "auditor",
  "mfa_method": "email",
  "password": "new-password"
}
```

---

### Users — `POST /users/{user_id}/suspend`

Suspend a user account. Requires `admin` role.

**Response `204`** — No content

---

### Users — `DELETE /users/{user_id}`

Soft-delete a user account. Requires `admin` role.

**Response `204`** — No content

---

### Servers — `POST /servers/`

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
  "proxy_jump_hostname": null
}
```

**OS families:** `debian`, `rhel`, `unknown`

**Response `201`**
```json
{
  "id": "550e8400-...",
  "hostname": "server1.example.com",
  "display_name": "Production Web Server",
  "ssh_port": 22,
  "os_family": "debian",
  "status": "active",
  "hardening_applied": false,
  "last_seen_at": null,
  "created_at": "2024-01-15T12:00:00Z"
}
```

---

### Servers — `GET /servers/`

List all onboarded servers. Requires `admin`, `auditor`, or `read_only` role.

---

### Servers — `POST /servers/{server_id}/access`

Grant a user access to a server. Requires `admin` role.

**Request**
```json
{
  "user_id": "550e8400-...",
  "allow_sudo": false,
  "remote_username": "alice"
}
```

If `remote_username` is omitted, the user's Bastion username is used.

**Response `201`**
```json
{
  "id": "550e8400-...",
  "message": "Access granted."
}
```

---

### Servers — `DELETE /servers/{server_id}/access/{user_id}`

Revoke a user's access to a server. Requires `admin` role.

**Response `204`** — No content

---

### Servers — `POST /servers/{server_id}/provision`

Queue a provisioning task for the server. Creates Unix accounts for all granted users, applies SSH hardening, and distributes the CA public key. Requires `admin` role.

**Response `202`**
```json
{
  "message": "Provisioning task queued.",
  "server_id": "550e8400-..."
}
```

---

### Servers — `GET /servers/{server_id}/packages`

List tracked packages for a server. Requires `admin`, `auditor`, or `read_only` role.

**Query parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `updates_only` | boolean | `false` | Only return packages with updates available |

**Response `200`**
```json
[
  {
    "name": "openssl",
    "installed_version": "3.0.2-0ubuntu1.14",
    "available_version": "3.0.2-0ubuntu1.15",
    "update_available": true,
    "last_checked_at": "2024-01-15T06:00:00Z"
  }
]
```

---

### Servers — `POST /servers/{server_id}/packages/update`

Queue a package update task. Requires `admin` role.

**Request**
```json
{
  "package_names": ["openssl", "curl"]
}
```

Omit `package_names` (or set to `null`) to update all available packages.

**Response `202`**
```json
{
  "message": "Package update task queued.",
  "server_id": "550e8400-..."
}
```

---

### Servers — `POST /servers/{server_id}/reboot`

Queue a reboot for the server. Requires `admin` role.

**Query parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `delay_seconds` | integer | `60` | Seconds before the reboot is initiated |

**Response `202`**
```json
{
  "message": "Reboot queued with 60s delay.",
  "server_id": "550e8400-..."
}
```

---

### Servers — `DELETE /servers/{server_id}`

Soft-delete a server. Requires `admin` role.

**Response `204`** — No content

---

### Certificates — `GET /certificates/`

List SSH certificates. Requires `admin`, `auditor`, or `read_only` role.

**Query parameters**

| Parameter | Type | Description |
|---|---|---|
| `user_id` | string | Filter by user |
| `cert_status` | string | Filter by status: `active`, `expired`, `revoked` |
| `limit` | integer | Default `100` |
| `offset` | integer | Default `0` |

---

### Certificates — `POST /certificates/{cert_id}/revoke`

Revoke a certificate and rebuild the KRL. Requires `admin` role.

**Request**
```json
{
  "reason": "User account compromised"
}
```

**Response `204`** — No content

---

### Audit — `GET /audit/`

Query the audit log. Requires `admin` or `auditor` role.

**Query parameters**

| Parameter | Type | Description |
|---|---|---|
| `user_id` | string | Filter by user |
| `action` | string | Partial match on action name (e.g. `auth.login`) |
| `success` | boolean | Filter by success/failure |
| `limit` | integer | Default `100` |
| `offset` | integer | Default `0` |

**Response `200`**
```json
[
  {
    "id": "550e8400-...",
    "user_id": "550e8400-...",
    "action": "auth.login",
    "resource_type": null,
    "resource_id": null,
    "detail": null,
    "ip_address": "127.0.0.1",
    "success": true,
    "created_at": "2024-01-15T14:30:00Z"
  }
]
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
| `429` | Rate limit exceeded |
| `500` | Internal server error |
| `503` | Service unavailable (e.g. target server unreachable) |
