"""Bastion CLI — the primary interface for users on the bastion host."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="bastion",
    help="Bastion SSH jumphost CLI — connect to servers, manage sessions, and issue certificates.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)

# Unix socket transport for all API calls
_API_SOCKET = Path("/opt/bastion/run/bastion-api.sock")
_ADMIN_SOCKET = Path("/opt/bastion/run/bastion-admin.sock")
_TOKEN_FILE = Path.home() / ".bastion" / "token"


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
    if _TOKEN_FILE.exists():
        return _TOKEN_FILE.read_text().strip()
    return None


def _save_token(token: str) -> None:
    """Save the access token to the user's home directory with restricted permissions."""
    _TOKEN_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _TOKEN_FILE.write_text(token)
    _TOKEN_FILE.chmod(0o600)


def _auth_headers() -> dict[str, str]:
    """Return the Authorization header for authenticated requests."""
    token = _load_token()
    if not token:
        err_console.print("[red]Not authenticated.[/red] Run [bold]bastion login[/bold] first.")
        raise typer.Exit(1)
    return {"Authorization": f"Bearer {token}"}


# ── Commands ──────────────────────────────────────────────────────────────────


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

    _save_token(data["access_token"])
    console.print("[green]✓[/green] Authenticated successfully.")


@app.command()
def connect(
    hostname: str = typer.Argument(..., help="Hostname of the server to connect to"),
    identity: Path | None = typer.Option(
        None, "--identity", "-i", help="Path to your SSH private key"
    ),
) -> None:
    """Connect to a remote server via the Bastion proxy."""
    # Resolve the SSH key to use
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

    if response.status_code == 401:
        err_console.print(
            "[red]Session expired.[/red] Run [bold]bastion login[/bold] to re-authenticate."
        )
        raise typer.Exit(1)
    if response.status_code != 200:
        err_console.print(
            f"[red]Connection failed:[/red] {response.json().get('detail', 'Unknown error')}"
        )
        raise typer.Exit(1)

    data = response.json()
    cert = data["certificate"]
    remote_user = data["remote_username"]
    port = data["port"]

    # Write the certificate to a temporary file and connect
    with tempfile.TemporaryDirectory(prefix="bastion-") as tmpdir:
        tmp = Path(tmpdir)
        cert_file = tmp / "id_ed25519-cert.pub"
        cert_file.write_text(cert)
        cert_file.chmod(0o600)

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
                "StrictHostKeyChecking=accept-new",
                "-p",
                str(port),
                f"{remote_user}@{hostname}",
            ],
        )


@app.command()
def sessions(
    limit: int = typer.Option(20, help="Number of sessions to display"),
) -> None:
    """List your recent SSH sessions."""
    with _api_client() as client:
        response = client.get(
            f"/sessions/?limit={limit}",
            headers=_auth_headers(),
        )

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
        None, "--identity", "-i", help="Path to your SSH public key"
    ),
) -> None:
    """Issue a new SSH certificate for your public key."""
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
    cert_path = pub_key_path.parent / (pub_key_path.stem + "-cert.pub")
    cert_path.write_text(data["certificate"])
    cert_path.chmod(0o600)

    console.print(
        f"[green]✓[/green] Certificate issued — serial [bold]{data['serial']}[/bold], valid for [bold]{data['valid_hours']}h[/bold]"
    )
    console.print(f"  Saved to: {cert_path}")


if __name__ == "__main__":
    app()
