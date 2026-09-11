"""Bastion API client library — for use by IaC pipelines, Terraform, and Ansible.

Communicates with the bastion-admin Unix socket. Intended for use on the
bastion host itself or via SSH forwarding.
"""

from __future__ import annotations

from typing import Any

import httpx


class BastionClientError(Exception):
    """Raised when the Bastion API returns an error response."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


# ── Module-level helpers ──────────────────────────────────────────────────────


def make_http_client(token: str, socket_path: str, base_url: str = "http://bastion") -> httpx.Client:
    """Return a configured httpx.Client for the given Unix socket and token.

    Extracted as a standalone function so it can be replaced in tests without
    subclassing BastionClient.
    """
    return httpx.Client(
        transport=httpx.HTTPTransport(uds=socket_path),
        base_url=base_url,
        headers={"Authorization": f"Bearer {token}"},
        timeout=30.0,
    )


def check_response(response: httpx.Response) -> dict[str, Any]:
    """Raise BastionClientError on non-2xx responses, else return parsed JSON.

    Returns an empty dict for successful responses with no body (e.g. 204).
    Extracted as a standalone function so error-handling logic can be tested
    independently of the HTTP transport.
    """
    if response.is_success:
        if response.content:
            return response.json()  # type: ignore[no-any-return]
        return {}
    try:
        detail = response.json().get("detail", response.text)
    except Exception:
        detail = response.text
    raise BastionClientError(response.status_code, detail)


# ── Client class ──────────────────────────────────────────────────────────────


class BastionClient:
    """Synchronous Bastion admin API client over a Unix socket.

    Usage::

        client = BastionClient(token="<admin-jwt>")
        user = client.create_user("alice", "alice@example.com", "s3cr3t")
        client.grant_access(user["id"], server_id="<id>")
    """

    def __init__(
        self,
        token: str,
        socket_path: str = "/opt/bastion/run/bastion-admin.sock",
    ) -> None:
        self._token = token
        self._socket_path = socket_path

    def _client(self) -> httpx.Client:
        """Return a configured httpx client for this instance."""
        return make_http_client(self._token, self._socket_path)

    def _check(self, response: httpx.Response) -> dict[str, Any]:
        """Delegate to the module-level check_response function."""
        return check_response(response)

    # ── Authentication ────────────────────────────────────────────────────────

    @classmethod
    def login(
        cls,
        username: str,
        password: str,
        socket_path: str = "/opt/bastion/run/bastion-api.sock",
    ) -> "BastionClient":
        """Authenticate and return a client with a valid access token.

        Uses the user-facing API socket for login, then switches to the admin
        socket for subsequent calls. The caller must have the admin role.
        """
        with make_http_client("", socket_path) as client:
            response = client.post(
                "/auth/login", json={"username": username, "password": password}
            )
        if not response.is_success:
            raise BastionClientError(response.status_code, response.json().get("detail", ""))
        data = response.json()
        if data.get("mfa_required"):
            raise BastionClientError(400, "MFA is required — use a pre-issued token instead.")
        return cls(token=data["access_token"])

    # ── Users ─────────────────────────────────────────────────────────────────

    def list_users(self, include_deleted: bool = False) -> list[dict[str, Any]]:
        """Return all Bastion users."""
        with self._client() as c:
            return self._check(c.get("/users/", params={"include_deleted": include_deleted}))  # type: ignore[return-value]

    def get_user(self, user_id: str) -> dict[str, Any]:
        """Return a single user by ID."""
        with self._client() as c:
            return self._check(c.get(f"/users/{user_id}"))

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: str | None = None,
        role: str = "user",
    ) -> dict[str, Any]:
        """Create a new Bastion user. Returns the created user dict."""
        with self._client() as c:
            return self._check(
                c.post(
                    "/users/",
                    json={
                        "username": username,
                        "email": email,
                        "password": password,
                        "full_name": full_name,
                        "role": role,
                    },
                )
            )

    def update_user(self, user_id: str, **fields: Any) -> dict[str, Any]:
        """Update a user's fields. Pass keyword arguments matching UpdateUserRequest."""
        with self._client() as c:
            return self._check(c.patch(f"/users/{user_id}", json=fields))

    def suspend_user(self, user_id: str) -> None:
        """Suspend a user account."""
        with self._client() as c:
            self._check(c.post(f"/users/{user_id}/suspend"))

    def delete_user(self, user_id: str) -> None:
        """Soft-delete a user account."""
        with self._client() as c:
            self._check(c.delete(f"/users/{user_id}"))

    # ── Servers ───────────────────────────────────────────────────────────────

    def list_servers(self) -> list[dict[str, Any]]:
        """Return all onboarded servers."""
        with self._client() as c:
            return self._check(c.get("/servers/"))  # type: ignore[return-value]

    def onboard_server(
        self,
        hostname: str,
        display_name: str | None = None,
        ssh_port: int = 22,
        os_family: str = "unknown",
        tags: list[str] | None = None,
        environment: str | None = None,
        ip_allowlist: list[str] | None = None,
        session_policy: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Onboard a new server. Returns the created server dict."""
        with self._client() as c:
            return self._check(
                c.post(
                    "/servers/",
                    json={
                        "hostname": hostname,
                        "display_name": display_name,
                        "ssh_port": ssh_port,
                        "os_family": os_family,
                        "tags": tags,
                        "environment": environment,
                        "ip_allowlist": ip_allowlist,
                        "session_policy": session_policy,
                    },
                )
            )

    def delete_server(self, server_id: str) -> None:
        """Soft-delete a server."""
        with self._client() as c:
            self._check(c.delete(f"/servers/{server_id}"))

    # ── Access grants ─────────────────────────────────────────────────────────

    def grant_access(
        self,
        server_id: str,
        user_id: str,
        allow_sudo: bool = False,
        remote_username: str | None = None,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        """Grant a user access to a server. Returns the access grant dict."""
        with self._client() as c:
            return self._check(
                c.post(
                    f"/servers/{server_id}/access",
                    json={
                        "user_id": user_id,
                        "allow_sudo": allow_sudo,
                        "remote_username": remote_username,
                        "expires_at": expires_at,
                    },
                )
            )

    def revoke_access(self, server_id: str, user_id: str) -> None:
        """Revoke a user's access to a server."""
        with self._client() as c:
            self._check(c.delete(f"/servers/{server_id}/access/{user_id}"))

    # ── Groups ────────────────────────────────────────────────────────────────

    def list_groups(self) -> list[dict[str, Any]]:
        """Return all user groups."""
        with self._client() as c:
            return self._check(c.get("/groups/"))  # type: ignore[return-value]

    def create_group(self, name: str, description: str | None = None) -> dict[str, Any]:
        """Create a user group."""
        with self._client() as c:
            return self._check(c.post("/groups/", json={"name": name, "description": description}))

    def add_group_member(self, group_id: str, user_id: str) -> None:
        """Add a user to a group."""
        with self._client() as c:
            self._check(c.post(f"/groups/{group_id}/members/{user_id}"))

    def remove_group_member(self, group_id: str, user_id: str) -> None:
        """Remove a user from a group."""
        with self._client() as c:
            self._check(c.delete(f"/groups/{group_id}/members/{user_id}"))

    # ── Certificates ──────────────────────────────────────────────────────────

    def list_certificates(
        self,
        user_id: str | None = None,
        cert_status: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return SSH certificates, optionally filtered."""
        params: dict[str, Any] = {}
        if user_id:
            params["user_id"] = user_id
        if cert_status:
            params["cert_status"] = cert_status
        with self._client() as c:
            return self._check(c.get("/certificates/", params=params))  # type: ignore[return-value]

    def revoke_certificate(self, cert_id: str, reason: str) -> None:
        """Revoke an SSH certificate."""
        with self._client() as c:
            self._check(c.post(f"/certificates/{cert_id}/revoke", json={"reason": reason}))

    # ── Audit ─────────────────────────────────────────────────────────────────

    def list_audit_logs(
        self,
        user_id: str | None = None,
        action: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return audit log entries."""
        params: dict[str, Any] = {"limit": limit}
        if user_id:
            params["user_id"] = user_id
        if action:
            params["action"] = action
        with self._client() as c:
            return self._check(c.get("/audit/", params=params))  # type: ignore[return-value]
