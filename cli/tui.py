"""Bastion terminal user interface — launched when no subcommand is given."""

from __future__ import annotations

from pathlib import Path

import httpx
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
    TabbedContent,
    TabPane,
)

_API_SOCKET = Path("/opt/bastion/run/bastion-api.sock")
_TOKEN_FILE = Path.home() / ".bastion" / "token"


def _api_client() -> httpx.Client:
    """Return an httpx client connected to the bastion-api Unix socket."""
    return httpx.Client(
        transport=httpx.HTTPTransport(uds=str(_API_SOCKET)),
        base_url="http://bastion",
    )


def _auth_headers() -> dict[str, str]:
    """Return the Bearer auth header from the stored token."""
    if _TOKEN_FILE.exists():
        return {"Authorization": f"Bearer {_TOKEN_FILE.read_text().strip()}"}
    return {}


# ── Login screen ──────────────────────────────────────────────────────────────


class LoginScreen(Screen):
    """Full-screen login form shown when no token is stored."""

    CSS = """
    LoginScreen {
        align: center middle;
    }
    #login-box {
        width: 50;
        height: auto;
        border: solid $accent;
        padding: 1 2;
    }
    #login-box Label { margin-bottom: 1; }
    #login-box Input { margin-bottom: 1; }
    #login-error { color: $error; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        with Container(id="login-box"):
            yield Label("  Bastion Login", id="login-title")
            yield Input(placeholder="Username", id="username")
            yield Input(placeholder="Password", password=True, id="password")
            yield Button("Login", variant="primary", id="login-btn")
            yield Label("", id="login-error")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle the login button press."""
        if event.button.id != "login-btn":
            return
        username = self.query_one("#username", Input).value.strip()
        password = self.query_one("#password", Input).value
        error_label = self.query_one("#login-error", Label)

        if not username or not password:
            error_label.update("Username and password are required.")
            return

        try:
            with _api_client() as client:
                resp = client.post("/auth/login", json={"username": username, "password": password})
        except Exception as exc:
            error_label.update(f"Connection error: {exc}")
            return

        if resp.status_code != 200:
            error_label.update(resp.json().get("detail", "Login failed."))
            return

        data = resp.json()
        if data.get("mfa_required"):
            self.app.push_screen(
                MfaScreen(mfa_token=data["mfa_token"]),
                callback=self._on_mfa_done,
            )
            return

        _TOKEN_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _TOKEN_FILE.write_text(data["access_token"])
        _TOKEN_FILE.chmod(0o600)
        self.app.pop_screen()

    def _on_mfa_done(self, token: str | None) -> None:
        if token:
            _TOKEN_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _TOKEN_FILE.write_text(token)
            _TOKEN_FILE.chmod(0o600)
            self.app.pop_screen()


class MfaScreen(ModalScreen):
    """Modal MFA code entry screen."""

    CSS = """
    MfaScreen {
        align: center middle;
    }
    #mfa-box {
        width: 40;
        height: auto;
        border: solid $accent;
        padding: 1 2;
    }
    """

    def __init__(self, mfa_token: str) -> None:
        super().__init__()
        self._mfa_token = mfa_token

    def compose(self) -> ComposeResult:
        with Container(id="mfa-box"):
            yield Label("🔑  MFA Code Required")
            yield Input(placeholder="6-digit code", id="mfa-code")
            yield Button("Verify", variant="primary", id="mfa-btn")
            yield Label("", id="mfa-error")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "mfa-btn":
            return
        code = self.query_one("#mfa-code", Input).value.strip()
        try:
            with _api_client() as client:
                resp = client.post(
                    "/auth/mfa/verify",
                    json={"mfa_token": self._mfa_token, "code": code},
                )
        except Exception as exc:
            self.query_one("#mfa-error", Label).update(str(exc))
            return

        if resp.status_code != 200:
            self.query_one("#mfa-error", Label).update(resp.json().get("detail", "Invalid code."))
            return

        self.dismiss(resp.json()["access_token"])


# ── Main dashboard ────────────────────────────────────────────────────────────


class SessionsPane(Static):
    """Displays the user's recent sessions in a table."""

    def compose(self) -> ComposeResult:
        yield DataTable(id="sessions-table")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("ID", "Server", "Status", "Started", "Duration", "Rec")
        self._refresh()

    def _refresh(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        try:
            with _api_client() as client:
                resp = client.get("/sessions/?limit=50", headers=_auth_headers())
            if resp.status_code != 200:
                return
            for s in resp.json():
                started = s["started_at"][:16].replace("T", " ")
                duration = "—"
                if s.get("ended_at"):
                    from datetime import datetime

                    secs = int(
                        (
                            datetime.fromisoformat(s["ended_at"])
                            - datetime.fromisoformat(s["started_at"])
                        ).total_seconds()
                    )
                    duration = f"{secs // 60}m {secs % 60}s"
                table.add_row(
                    s["id"][:8],
                    s["server_hostname"],
                    s["status"],
                    started,
                    duration,
                    "✓" if s["recording_available"] else "—",
                )
        except Exception:
            pass


class ConnectPane(Static):
    """Quick-connect form."""

    CSS = """
    ConnectPane {
        padding: 1 2;
    }
    ConnectPane Input { margin-bottom: 1; width: 40; }
    """

    def compose(self) -> ComposeResult:
        yield Label("Connect to a server")
        yield Input(placeholder="hostname", id="connect-hostname")
        yield Button("Connect", variant="primary", id="connect-btn")
        yield Label("", id="connect-status")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "connect-btn":
            return
        hostname = self.query_one("#connect-hostname", Input).value.strip()
        status_label = self.query_one("#connect-status", Label)
        if not hostname:
            status_label.update("Enter a hostname.")
            return
        status_label.update(f"Launching connection to {hostname}…")
        # Delegate to the CLI connect command in a subprocess
        import subprocess
        import sys

        subprocess.Popen(
            [sys.executable, "-m", "cli.main", "connect", hostname],
        )
        self.app.exit()


class BastionTUI(App):
    """Main Bastion terminal user interface."""

    TITLE = "Bastion"
    SUB_TITLE = "SSH Bastion Host"
    CSS = """
    TabbedContent { height: 1fr; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("l", "logout", "Logout"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Connect", id="tab-connect"):
                yield ConnectPane()
            with TabPane("Sessions", id="tab-sessions"):
                yield SessionsPane()
        yield Footer()

    def on_mount(self) -> None:
        """Show login screen if no token is stored."""
        if not _TOKEN_FILE.exists() or not _TOKEN_FILE.read_text().strip():
            self.push_screen(LoginScreen())

    def action_refresh(self) -> None:
        """Refresh the active pane."""
        try:
            pane = self.query_one(SessionsPane)
            pane._refresh()
        except Exception:
            pass

    def action_logout(self) -> None:
        """Delete the stored token and show the login screen."""
        if _TOKEN_FILE.exists():
            _TOKEN_FILE.unlink()
        self.push_screen(LoginScreen())


def run_tui() -> None:
    """Entry point for the Bastion TUI."""
    BastionTUI().run()
