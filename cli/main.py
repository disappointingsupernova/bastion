"""Bastion CLI — the primary interface for users on the bastion host."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

import httpx
import jwt as _jwt
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="bastion",
    help="Bastion SSH jumphost CLI — connect to servers, manage sessions, and issue certificates.",
    no_args_is_help=False,
    invoke_without_command=True,
)
console = Console()
err_console = Console(stderr=True)

_API_SOCKET = Path("/opt/bastion/run/bastion-api.sock")
_ADMIN_SOCKET = Path("/opt/bastion/run/bastion-admin.sock")
_TOKEN_FILE = Path.home() / ".bastion" / "token"
_REFRESH_TOKEN_FILE = Path.home() / ".bastion" / "refresh_token"


def _get_transport(socket_path: Path) -> httpx.HTTPTransport:
    """Return an httpx transport configured for the given Unix socket."""
    return httpx.HTTPTransport(uds=str(socket_path))


def _api_client(admin: bool = False) -> httpx.Client:
    """Return an httpx client connected to the appropriate Unix socket."""
    socket = _ADMIN_SOCKET if admin else _API_SOCKET
    if not socket.exists():
        err_console.print(
            f"[red]Error:[/red] Bastion API socket not found at {socket}. Is the service running?"
        )
        raise typer.Exit(1)
    return httpx.Client(transport=_get_transport(socket), base_url="http://bastion")


def _load_token() -> str | None:
    """Load the stored access token from the user's home directory."""
    try:
        raw = _TOKEN_FILE.read_text(encoding="utf-8")
        stripped: str = raw.strip()  # type: ignore[assignment]
        return stripped or None
    except OSError:
        return None


def _load_refresh_token() -> str | None:
    """Load the stored refresh token from the user's home directory."""
    if _REFRESH_TOKEN_FILE.exists():
        return _REFRESH_TOKEN_FILE.read_text().strip()
    return None


def _save_token(access_token: str, refresh_token: str | None = None) -> None:
    """Save the access and optional refresh token with restricted permissions."""
    _TOKEN_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _TOKEN_FILE.write_text(access_token)
    _TOKEN_FILE.chmod(0o600)
    if refresh_token is not None:
        _REFRESH_TOKEN_FILE.write_text(refresh_token)
        _REFRESH_TOKEN_FILE.chmod(0o600)


def _token_expires_at(token: str) -> float:
    """Return the expiry timestamp of a JWT without verifying the signature."""
    try:
        payload = _jwt.decode(token, options={"verify_signature": False})
        return float(payload.get("exp", 0))
    except Exception:
        return 0.0


def _try_refresh() -> str | None:
    """Attempt a silent token refresh using the stored refresh token.

    Returns the new access token on success, or None if the refresh token is
    missing or the refresh request fails.
    """
    refresh_token = _load_refresh_token()
    if not refresh_token:
        return None
    try:
        with _api_client() as client:
            response = client.post("/auth/refresh", json={"refresh_token": refresh_token})
        if response.status_code == 200:
            data = response.json()
            _save_token(data["access_token"], data.get("refresh_token"))
            return data["access_token"]
    except Exception:
        pass
    return None


def _auth_headers() -> dict[str, str]:
    """Return the Authorization header, silently refreshing the token if it is
    expired or about to expire within the next 60 seconds.

    Exits with a clear message if no valid token can be obtained.
    """
    token = _load_token()
    if not token:
        err_console.print("[red]Not authenticated.[/red] Run [bold]bastion login[/bold] first.")
        raise typer.Exit(1)

    # Proactively refresh if the token expires within 60 seconds
    if _token_expires_at(token) < time.time() + 60:
        refreshed = _try_refresh()
        if refreshed:
            token = refreshed
        else:
            err_console.print(
                "[red]Session expired.[/red] Run [bold]bastion login[/bold] to re-authenticate."
            )
            raise typer.Exit(1)

    return {"Authorization": f"Bearer {token}"}


def _complete_hostnames(
    ctx: typer.Context, param: typer.CallbackParam, incomplete: str
) -> list[str]:
    """Shell completion callback — returns server hostnames matching the incomplete string."""
    token = _load_token()
    if not token:
        return []
    try:
        with _api_client() as client:
            response = client.get(
                "/sessions/?limit=500",
                headers={"Authorization": f"Bearer {token}"},
                timeout=2.0,
            )
        if response.status_code != 200:
            return []
        seen: dict[str, None] = {}
        for s in response.json():
            h = s.get("server_hostname", "")
            if h and h.startswith(incomplete):
                seen[h] = None
        return list(seen)
    except Exception:
        return []


# ── Commands ──────────────────────────────────────────────────────────────────


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Launch the Bastion TUI when no subcommand is given."""
    if ctx.invoked_subcommand is None:
        from cli.tui import run_tui

        run_tui()


@app.command()
def login(
    username: str = typer.Option(..., prompt=True),
    password: str = typer.Option(..., prompt=True, hide_input=True),
) -> None:
    """Authenticate to the Bastion service and store your access token."""
    with _api_client() as client:
        response = client.post("/auth/login", json={"username": username, "password": password})

    if response.status_code != 200:
        err_console.print(
            f"[red]Login failed:[/red] {response.json().get('detail', 'Unknown error')}"
        )
        raise typer.Exit(1)

    data = response.json()

    if data.get("mfa_required"):
        mfa_token = data["mfa_token"]
        code = typer.prompt("MFA code")
        with _api_client() as client:
            response = client.post("/auth/mfa/verify", json={"mfa_token": mfa_token, "code": code})
        if response.status_code != 200:
            err_console.print(
                f"[red]MFA verification failed:[/red] {response.json().get('detail', 'Unknown error')}"
            )
            raise typer.Exit(1)
        data = response.json()

    _save_token(data["access_token"], data.get("refresh_token"))
    console.print("[green]✓[/green] Authenticated successfully.")


@app.command()
def connect(
    hostname: str = typer.Argument(
        ...,
        help="Hostname of the server to connect to.",
        autocompletion=_complete_hostnames,
    ),
    identity: Path | None = typer.Option(
        None, "--identity", "-i", help="Path to your SSH private key."
    ),
) -> None:
    """Connect to a remote server via the Bastion proxy."""
    key_path = identity or Path.home() / ".ssh" / "id_ed25519"
    pub_key_path = Path(str(key_path) + ".pub")

    if not key_path.exists():
        err_console.print(f"[red]SSH key not found:[/red] {key_path}")
        err_console.print("Generate one with: [bold]ssh-keygen -t ed25519[/bold]")
        raise typer.Exit(1)

    if not pub_key_path.exists():
        err_console.print(f"[red]SSH public key not found:[/red] {pub_key_path}")
        raise typer.Exit(1)

    public_key = pub_key_path.read_text().strip()

    with _api_client() as client:
        response = client.post(
            "/sessions/connect",
            json={"hostname": hostname, "public_key": public_key},
            headers=_auth_headers(),
        )

    if response.status_code != 200:
        err_console.print(
            f"[red]Connection failed:[/red] {response.json().get('detail', 'Unknown error')}"
        )
        raise typer.Exit(1)

    data = response.json()
    cert = data["certificate"]
    remote_user = data["remote_username"]
    port = data["port"]

    with tempfile.TemporaryDirectory(prefix="bastion-") as tmpdir:
        tmp = Path(tmpdir)
        cert_file = tmp / "id_ed25519-cert.pub"
        cert_file.write_text(cert)
        cert_file.chmod(0o600)

        known_hosts_file = tmp / "known_hosts"
        ca_pub_key_path = Path.home() / ".bastion" / "ca.pub"
        if ca_pub_key_path.exists():
            ca_pub_key = ca_pub_key_path.read_text().strip()
            known_hosts_file.write_text(f"@cert-authority * {ca_pub_key}\n")
        else:
            err_console.print(
                "[yellow]Warning:[/yellow] Bastion CA public key not found at "
                f"{ca_pub_key_path}. Host verification will use accept-new. "
                "Run [bold]bastion fetch-ca[/bold] to cache the CA key."
            )
            known_hosts_file.write_text("")

        console.print(
            f"[green]→[/green] Connecting to [bold]{remote_user}@{hostname}[/bold]:{port}"
        )

        os.execvp(
            "ssh",
            [
                "ssh",
                "-i",
                str(key_path),
                "-o",
                f"CertificateFile={cert_file}",
                "-o",
                f"UserKnownHostsFile={known_hosts_file}",
                "-o",
                "StrictHostKeyChecking=yes",
                "-p",
                str(port),
                f"{remote_user}@{hostname}",
            ],
        )


@app.command()
def sessions(
    limit: int = typer.Option(20, help="Number of sessions to display."),
) -> None:
    """List your recent SSH sessions."""
    with _api_client() as client:
        response = client.get(f"/sessions/?limit={limit}", headers=_auth_headers())

    if response.status_code != 200:
        err_console.print(f"[red]Error:[/red] {response.json().get('detail', 'Unknown error')}")
        raise typer.Exit(1)

    data = response.json()
    if not data:
        console.print("No sessions found.")
        return

    table = Table(title="Recent Sessions")
    table.add_column("ID", style="dim", width=12)
    table.add_column("Server")
    table.add_column("Status")
    table.add_column("Started")
    table.add_column("Duration")
    table.add_column("Recording")

    for s in data:
        started = s["started_at"][:19].replace("T", " ")
        duration = "—"
        if s.get("ended_at"):
            from datetime import datetime

            start = datetime.fromisoformat(s["started_at"])
            end = datetime.fromisoformat(s["ended_at"])
            secs = int((end - start).total_seconds())
            duration = f"{secs // 60}m {secs % 60}s"
        recording = "✓" if s["recording_available"] else "—"
        table.add_row(
            s["id"][:8],
            s["server_hostname"],
            s["status"],
            started,
            duration,
            recording,
        )

    console.print(table)


@app.command()
def cert(
    identity: Path | None = typer.Option(
        None, "--identity", "-i", help="Path to your SSH public key."
    ),
) -> None:
    """Issue a new SSH certificate and display its details.

    The certificate is NOT written to disk. Use 'bastion connect' to connect.
    """
    pub_key_path = identity or Path.home() / ".ssh" / "id_ed25519.pub"
    if not pub_key_path.exists():
        err_console.print(f"[red]Public key not found:[/red] {pub_key_path}")
        raise typer.Exit(1)

    public_key = pub_key_path.read_text().strip()

    with _api_client() as client:
        response = client.post(
            "/auth/cert/issue",
            json={"public_key": public_key},
            headers=_auth_headers(),
        )

    if response.status_code != 200:
        err_console.print(
            f"[red]Certificate issuance failed:[/red] {response.json().get('detail', 'Unknown error')}"
        )
        raise typer.Exit(1)

    data = response.json()
    console.print(
        f"[green]✓[/green] Certificate issued — serial [bold]{data['serial']}[/bold], "
        f"valid for [bold]{data['valid_hours']}h[/bold]"
    )
    console.print(
        "  [dim]Certificate not written to disk. Use [bold]bastion connect[/bold] to connect.[/dim]"
    )


if __name__ == "__main__":
    app()
