"""Bastion Admin CLI — administrative interface for the bastion-admin API."""

from __future__ import annotations

from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="bastion-admin",
    help="Bastion administrative CLI — user management, server onboarding, and audit queries.",
    no_args_is_help=True,
)
user_app = typer.Typer(help="Manage Bastion users.", no_args_is_help=True)
server_app = typer.Typer(help="Manage remote servers.", no_args_is_help=True)
access_app = typer.Typer(help="Manage server access grants.", no_args_is_help=True)
cert_app = typer.Typer(help="Manage SSH certificates.", no_args_is_help=True)
audit_app = typer.Typer(help="Query the audit log.", no_args_is_help=True)
packages_app = typer.Typer(help="Manage remote server packages.", no_args_is_help=True)

app.add_typer(user_app, name="user")
app.add_typer(server_app, name="server")
app.add_typer(access_app, name="access")
app.add_typer(cert_app, name="cert")
app.add_typer(audit_app, name="audit")
app.add_typer(packages_app, name="packages")

console = Console()
err_console = Console(stderr=True)

_ADMIN_SOCKET = Path("/opt/bastion/run/bastion-admin.sock")
_TOKEN_FILE = Path.home() / ".bastion" / "admin-token"


def _api_client() -> httpx.Client:
    """Return an httpx client connected to the admin Unix socket."""
    if not _ADMIN_SOCKET.exists():
        err_console.print(
            f"[red]Error:[/red] Admin socket not found at {_ADMIN_SOCKET}. "
            "Is bastion-admin running? Are you in the bastion group?"
        )
        raise typer.Exit(1)
    return httpx.Client(
        transport=httpx.HTTPTransport(uds=str(_ADMIN_SOCKET)),
        base_url="http://bastion",
    )


def _load_token() -> str | None:
    """Load the stored admin access token."""
    if _TOKEN_FILE.exists():
        return _TOKEN_FILE.read_text().strip()
    return None


def _save_token(token: str) -> None:
    """Save the admin access token with restricted permissions."""
    _TOKEN_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _TOKEN_FILE.write_text(token)
    _TOKEN_FILE.chmod(0o600)


def _auth_headers() -> dict[str, str]:
    """Return the Authorization header for authenticated requests."""
    token = _load_token()
    if not token:
        err_console.print(
            "[red]Not authenticated.[/red] Run [bold]bastion-admin login[/bold] first."
        )
        raise typer.Exit(1)
    return {"Authorization": f"Bearer {token}"}


def _handle_error(response: httpx.Response) -> None:
    """Print a formatted error message and exit on non-2xx responses."""
    detail = (
        response.json().get("detail", "Unknown error") if response.content else "No response body"
    )
    err_console.print(f"[red]Error {response.status_code}:[/red] {detail}")
    raise typer.Exit(1)


# ── Login ─────────────────────────────────────────────────────────────────────


@app.command()
def login(
    username: str = typer.Option(..., prompt=True),
    password: str = typer.Option(..., prompt=True, hide_input=True),
) -> None:
    """Authenticate to the Bastion admin API."""
    with _api_client() as client:
        response = client.post("/auth/login", json={"username": username, "password": password})

    if response.status_code != 200:
        _handle_error(response)

    data = response.json()
    if data.get("mfa_required"):
        mfa_token = data["mfa_token"]
        code = typer.prompt("MFA code")
        with _api_client() as client:
            response = client.post("/auth/mfa/verify", json={"mfa_token": mfa_token, "code": code})
        if response.status_code != 200:
            _handle_error(response)
        data = response.json()

    _save_token(data["access_token"])
    console.print("[green]✓[/green] Authenticated to admin API.")


# ── User commands ─────────────────────────────────────────────────────────────


@user_app.command("create")
def user_create(
    username: str = typer.Option(..., prompt=True),
    email: str = typer.Option(..., prompt=True),
    role: str = typer.Option("user", help="Role: admin, user, auditor, read_only"),
    mfa_method: str | None = typer.Option(None, help="MFA method: totp, email"),
    full_name: str | None = typer.Option(None),
) -> None:
    """Create a new Bastion user."""
    password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    payload = {
        "username": username,
        "email": email,
        "password": password,
        "role": role,
        "full_name": full_name,
        "mfa_method": mfa_method,
    }
    with _api_client() as client:
        response = client.post("/users/", json=payload, headers=_auth_headers())
    if response.status_code != 201:
        _handle_error(response)
    u = response.json()
    console.print(f"[green]✓[/green] User [bold]{u['username']}[/bold] created (ID: {u['id'][:8]})")


@user_app.command("list")
def user_list(
    include_deleted: bool = typer.Option(False, "--include-deleted"),
) -> None:
    """List all Bastion users."""
    with _api_client() as client:
        response = client.get(
            f"/users/?include_deleted={str(include_deleted).lower()}",
            headers=_auth_headers(),
        )
    if response.status_code != 200:
        _handle_error(response)

    users = response.json()
    if not users:
        console.print("No users found.")
        return

    table = Table(title="Bastion Users")
    table.add_column("ID", style="dim", width=10)
    table.add_column("Username", style="bold")
    table.add_column("Email")
    table.add_column("Role")
    table.add_column("Status")
    table.add_column("MFA")
    table.add_column("Last Login")

    for u in users:
        last_login = u["last_login_at"][:10] if u.get("last_login_at") else "—"
        mfa = u.get("mfa_method") or "—"
        status_colour = "green" if u["status"] == "active" else "red"
        table.add_row(
            u["id"][:8],
            u["username"],
            u["email"],
            u["role"],
            f"[{status_colour}]{u['status']}[/{status_colour}]",
            mfa,
            last_login,
        )
    console.print(table)


@user_app.command("suspend")
def user_suspend(username: str = typer.Argument(...)) -> None:
    """Suspend a user account."""
    user_id = _resolve_user_id(username)
    with _api_client() as client:
        response = client.post(f"/users/{user_id}/suspend", headers=_auth_headers())
    if response.status_code != 204:
        _handle_error(response)
    console.print(f"[yellow]⚠[/yellow] User [bold]{username}[/bold] suspended.")


@user_app.command("delete")
def user_delete(
    username: str = typer.Argument(...),
    confirm: bool = typer.Option(False, "--confirm", help="Skip confirmation prompt"),
) -> None:
    """Soft-delete a user account."""
    if not confirm:
        typer.confirm(f"Delete user '{username}'? This cannot be undone.", abort=True)
    user_id = _resolve_user_id(username)
    with _api_client() as client:
        response = client.delete(f"/users/{user_id}", headers=_auth_headers())
    if response.status_code != 204:
        _handle_error(response)
    console.print(f"[red]✗[/red] User [bold]{username}[/bold] deleted.")


# ── Server commands ───────────────────────────────────────────────────────────


@server_app.command("add")
def server_add(
    hostname: str = typer.Argument(...),
    display_name: str | None = typer.Option(None, "--display-name"),
    port: int = typer.Option(22, "--port"),
    os_family: str = typer.Option("unknown", "--os-family", help="debian, rhel, unknown"),
    proxy_jump: str | None = typer.Option(None, "--proxy-jump", help="Proxy jump server hostname"),
    tags: str | None = typer.Option(None, "--tags", help="Comma-separated tags"),
) -> None:
    """Onboard a new server."""
    tag_list = [t.strip() for t in tags.split(",")] if tags else []
    payload = {
        "hostname": hostname,
        "display_name": display_name,
        "ssh_port": port,
        "os_family": os_family,
        "tags": tag_list,
        "proxy_jump_hostname": proxy_jump,
    }
    with _api_client() as client:
        response = client.post("/servers/", json=payload, headers=_auth_headers())
    if response.status_code != 201:
        _handle_error(response)
    s = response.json()
    console.print(
        f"[green]✓[/green] Server [bold]{s['hostname']}[/bold] onboarded (ID: {s['id'][:8]})"
    )


@server_app.command("list")
def server_list() -> None:
    """List all onboarded servers."""
    with _api_client() as client:
        response = client.get("/servers/", headers=_auth_headers())
    if response.status_code != 200:
        _handle_error(response)

    servers = response.json()
    if not servers:
        console.print("No servers onboarded.")
        return

    table = Table(title="Onboarded Servers")
    table.add_column("ID", style="dim", width=10)
    table.add_column("Hostname", style="bold")
    table.add_column("Port")
    table.add_column("OS")
    table.add_column("Status")
    table.add_column("Hardened")
    table.add_column("Last Seen")

    for s in servers:
        last_seen = s["last_seen_at"][:10] if s.get("last_seen_at") else "—"
        status_colour = "green" if s["status"] == "active" else "red"
        hardened = "[green]✓[/green]" if s["hardening_applied"] else "[red]✗[/red]"
        table.add_row(
            s["id"][:8],
            s["hostname"],
            str(s["ssh_port"]),
            s["os_family"],
            f"[{status_colour}]{s['status']}[/{status_colour}]",
            hardened,
            last_seen,
        )
    console.print(table)


@server_app.command("provision")
def server_provision(hostname: str = typer.Argument(...)) -> None:
    """Provision all granted users onto a server and apply SSH hardening."""
    server_id = _resolve_server_id(hostname)
    with _api_client() as client:
        response = client.post(f"/servers/{server_id}/provision", headers=_auth_headers())
    if response.status_code != 202:
        _handle_error(response)
    console.print(f"[green]✓[/green] Provisioning task queued for [bold]{hostname}[/bold].")


@server_app.command("reboot")
def server_reboot(
    hostname: str = typer.Argument(...),
    delay: int = typer.Option(60, "--delay", help="Seconds before reboot"),
    confirm: bool = typer.Option(False, "--confirm"),
) -> None:
    """Schedule a reboot on a remote server."""
    if not confirm:
        typer.confirm(f"Schedule reboot of '{hostname}' in {delay}s?", abort=True)
    server_id = _resolve_server_id(hostname)
    with _api_client() as client:
        response = client.post(
            f"/servers/{server_id}/reboot?delay_seconds={delay}",
            headers=_auth_headers(),
        )
    if response.status_code != 202:
        _handle_error(response)
    console.print(f"[yellow]⚠[/yellow] Reboot queued for [bold]{hostname}[/bold] in {delay}s.")


# ── Access commands ───────────────────────────────────────────────────────────


@access_app.command("grant")
def access_grant(
    user: str = typer.Option(..., "--user", "-u"),
    server: str = typer.Option(..., "--server", "-s"),
    sudo: bool = typer.Option(False, "--sudo", help="Grant passwordless sudo"),
    remote_username: str | None = typer.Option(None, "--remote-username"),
) -> None:
    """Grant a user access to a server."""
    user_id = _resolve_user_id(user)
    server_id = _resolve_server_id(server)
    payload = {
        "user_id": user_id,
        "allow_sudo": sudo,
        "remote_username": remote_username,
    }
    with _api_client() as client:
        response = client.post(
            f"/servers/{server_id}/access", json=payload, headers=_auth_headers()
        )
    if response.status_code != 201:
        _handle_error(response)
    sudo_note = " [bold](with sudo)[/bold]" if sudo else ""
    console.print(
        f"[green]✓[/green] Access granted: [bold]{user}[/bold] → [bold]{server}[/bold]{sudo_note}"
    )


@access_app.command("revoke")
def access_revoke(
    user: str = typer.Option(..., "--user", "-u"),
    server: str = typer.Option(..., "--server", "-s"),
) -> None:
    """Revoke a user's access to a server."""
    user_id = _resolve_user_id(user)
    server_id = _resolve_server_id(server)
    with _api_client() as client:
        response = client.delete(f"/servers/{server_id}/access/{user_id}", headers=_auth_headers())
    if response.status_code != 204:
        _handle_error(response)
    console.print(f"[red]✗[/red] Access revoked: [bold]{user}[/bold] → [bold]{server}[/bold]")


# ── Certificate commands ──────────────────────────────────────────────────────


@cert_app.command("list")
def cert_list(
    user: str | None = typer.Option(None, "--user", "-u"),
    cert_status: str | None = typer.Option(None, "--status", help="active, expired, revoked"),
    limit: int = typer.Option(50, "--limit"),
) -> None:
    """List SSH certificates."""
    params = f"?limit={limit}"
    if user:
        user_id = _resolve_user_id(user)
        params += f"&user_id={user_id}"
    if cert_status:
        params += f"&cert_status={cert_status}"

    with _api_client() as client:
        response = client.get(f"/certificates/{params}", headers=_auth_headers())
    if response.status_code != 200:
        _handle_error(response)

    certs = response.json()
    if not certs:
        console.print("No certificates found.")
        return

    table = Table(title="SSH Certificates")
    table.add_column("ID", style="dim", width=10)
    table.add_column("Serial")
    table.add_column("Key ID")
    table.add_column("Principals")
    table.add_column("Valid Until")
    table.add_column("Status")

    for c in certs:
        status_colour = {"active": "green", "expired": "yellow", "revoked": "red"}.get(
            c["status"], "white"
        )
        valid_until = c["valid_before"][:16].replace("T", " ")
        table.add_row(
            c["id"][:8],
            str(c["serial"]),
            c["key_id"],
            c["principals"],
            valid_until,
            f"[{status_colour}]{c['status']}[/{status_colour}]",
        )
    console.print(table)


@cert_app.command("revoke")
def cert_revoke(
    cert_id: str = typer.Argument(...),
    reason: str = typer.Option(..., "--reason", "-r", prompt=True),
) -> None:
    """Revoke an SSH certificate and rebuild the KRL."""
    with _api_client() as client:
        response = client.post(
            f"/certificates/{cert_id}/revoke",
            json={"reason": reason},
            headers=_auth_headers(),
        )
    if response.status_code != 204:
        _handle_error(response)
    console.print(f"[red]✗[/red] Certificate [bold]{cert_id[:8]}[/bold] revoked. KRL rebuilt.")


# ── Audit commands ────────────────────────────────────────────────────────────


@audit_app.command("log")
def audit_log(
    user: str | None = typer.Option(None, "--user", "-u"),
    action: str | None = typer.Option(None, "--action", "-a"),
    failures_only: bool = typer.Option(False, "--failures-only"),
    limit: int = typer.Option(50, "--limit"),
) -> None:
    """Query the audit log."""
    params = f"?limit={limit}"
    if user:
        user_id = _resolve_user_id(user)
        params += f"&user_id={user_id}"
    if action:
        params += f"&action={action}"
    if failures_only:
        params += "&success=false"

    with _api_client() as client:
        response = client.get(f"/audit/{params}", headers=_auth_headers())
    if response.status_code != 200:
        _handle_error(response)

    entries = response.json()
    if not entries:
        console.print("No audit log entries found.")
        return

    table = Table(title="Audit Log")
    table.add_column("Time", width=19)
    table.add_column("Action")
    table.add_column("User ID", style="dim", width=10)
    table.add_column("Resource")
    table.add_column("IP")
    table.add_column("Result")

    for e in entries:
        ts = e["created_at"][:19].replace("T", " ")
        resource = f"{e['resource_type']}/{e['resource_id'][:8]}" if e.get("resource_type") else "—"
        result = "[green]✓[/green]" if e["success"] else "[red]✗[/red]"
        table.add_row(
            ts,
            e["action"],
            (e.get("user_id") or "—")[:8],
            resource,
            e.get("ip_address") or "—",
            result,
        )
    console.print(table)


# ── Package commands ──────────────────────────────────────────────────────────


@packages_app.command("list")
def packages_list(
    hostname: str = typer.Argument(...),
    updates_only: bool = typer.Option(False, "--updates-only"),
) -> None:
    """List packages on a remote server."""
    server_id = _resolve_server_id(hostname)
    with _api_client() as client:
        response = client.get(
            f"/servers/{server_id}/packages?updates_only={str(updates_only).lower()}",
            headers=_auth_headers(),
        )
    if response.status_code != 200:
        _handle_error(response)

    packages = response.json()
    if not packages:
        console.print("No packages found." if not updates_only else "No updates available.")
        return

    table = Table(title=f"Packages — {hostname}")
    table.add_column("Package", style="bold")
    table.add_column("Installed")
    table.add_column("Available")
    table.add_column("Update?")

    for p in packages:
        update_flag = "[green]✓[/green]" if p["update_available"] else "—"
        table.add_row(
            p["name"],
            p.get("installed_version") or "—",
            p.get("available_version") or "—",
            update_flag,
        )
    console.print(table)


@packages_app.command("update")
def packages_update(
    hostname: str = typer.Argument(...),
    packages: str | None = typer.Option(None, "--packages", help="Comma-separated package names"),
    confirm: bool = typer.Option(False, "--confirm"),
) -> None:
    """Apply package updates on a remote server."""
    package_list = [p.strip() for p in packages.split(",")] if packages else None
    if not confirm:
        target = f"packages: {packages}" if package_list else "all available packages"
        typer.confirm(f"Update {target} on '{hostname}'?", abort=True)

    server_id = _resolve_server_id(hostname)
    with _api_client() as client:
        response = client.post(
            f"/servers/{server_id}/packages/update",
            json={"package_names": package_list},
            headers=_auth_headers(),
        )
    if response.status_code != 202:
        _handle_error(response)
    console.print(f"[green]✓[/green] Package update task queued for [bold]{hostname}[/bold].")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _resolve_user_id(username: str) -> str:
    """Resolve a username to a user ID via the API."""
    with _api_client() as client:
        response = client.get("/users/", headers=_auth_headers())
    if response.status_code != 200:
        _handle_error(response)
    for u in response.json():
        if u["username"] == username:
            return str(u["id"])
    err_console.print(f"[red]Error:[/red] User '{username}' not found.")
    raise typer.Exit(1)


def _resolve_server_id(hostname: str) -> str:
    """Resolve a hostname to a server ID via the API."""
    with _api_client() as client:
        response = client.get("/servers/", headers=_auth_headers())
    if response.status_code != 200:
        _handle_error(response)
    for s in response.json():
        if s["hostname"] == hostname:
            return str(s["id"])
    err_console.print(f"[red]Error:[/red] Server '{hostname}' not found.")
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
