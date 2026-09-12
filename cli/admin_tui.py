"""Bastion Admin terminal user interface — launched when no subcommand is given."""

from __future__ import annotations

from pathlib import Path

import httpx
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import Screen
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

from bastion.logging import get_logger

_log = get_logger(__name__)
_ADMIN_SOCKET = Path("/opt/bastion/run/bastion-admin.sock")
_TOKEN_FILE = Path.home() / ".bastion" / "admin-token"


def _api_client() -> httpx.Client:
    """Return an httpx client connected to the bastion-admin Unix socket."""
    return httpx.Client(
        transport=httpx.HTTPTransport(uds=str(_ADMIN_SOCKET)),
        base_url="http://bastion",
    )


def _auth_headers() -> dict[str, str]:
    """Return the Bearer auth header from the stored admin token."""
    if _TOKEN_FILE.exists():
        return {"Authorization": f"Bearer {_TOKEN_FILE.read_text().strip()}"}
    return {}


class AdminLoginScreen(Screen):
    """Full-screen login form for the admin TUI."""

    CSS = """
    AdminLoginScreen { align: center middle; }
    #login-box { width: 50; height: auto; border: solid $accent; padding: 1 2; }
    #login-box Input { margin-bottom: 1; }
    #login-error { color: $error; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        with Container(id="login-box"):
            yield Label("🔐  Bastion Admin Login")
            yield Input(placeholder="Username", id="username")
            yield Input(placeholder="Password", password=True, id="password")
            yield Button("Login", variant="primary", id="login-btn")
            yield Label("", id="login-error")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "login-btn":
            return
        username = self.query_one("#username", Input).value.strip()
        password = self.query_one("#password", Input).value
        error_label = self.query_one("#login-error", Label)
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
        _TOKEN_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _TOKEN_FILE.write_text(data.get("access_token", ""))
        _TOKEN_FILE.chmod(0o600)
        self.app.pop_screen()


class UsersPane(Static):
    """Displays all users in a table."""

    def compose(self) -> ComposeResult:
        yield DataTable(id="users-table")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("ID", "Username", "Email", "Role", "Status", "MFA")
        self._refresh()

    def _refresh(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        try:
            with _api_client() as client:
                resp = client.get("/users/", headers=_auth_headers())
            if resp.status_code != 200:
                return
            for u in resp.json():
                table.add_row(
                    u["id"][:8],
                    u["username"],
                    u["email"],
                    u["role"],
                    u["status"],
                    u.get("mfa_method") or "—",
                )
        except Exception as exc:
            _log.debug("Admin TUI users pane refresh failed", error=str(exc))


class ServersPane(Static):
    """Displays all onboarded servers in a table."""

    def compose(self) -> ComposeResult:
        yield DataTable(id="servers-table")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("ID", "Hostname", "OS", "Status", "Hardened", "Last Seen")
        self._refresh()

    def _refresh(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        try:
            with _api_client() as client:
                resp = client.get("/servers/", headers=_auth_headers())
            if resp.status_code != 200:
                return
            for s in resp.json():
                last_seen = s["last_seen_at"][:10] if s.get("last_seen_at") else "—"
                table.add_row(
                    s["id"][:8],
                    s["hostname"],
                    s["os_family"],
                    s["status"],
                    "✓" if s["hardening_applied"] else "✗",
                    last_seen,
                )
        except Exception as exc:
            _log.debug("Admin TUI servers pane refresh failed", error=str(exc))


class AccessRequestsPane(Static):
    """Displays pending JIT access requests."""

    def compose(self) -> ComposeResult:
        yield DataTable(id="ar-table")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("ID", "User", "Server", "Duration", "Sudo", "Reason")
        self._refresh()

    def _refresh(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        try:
            with _api_client() as client:
                resp = client.get("/access-requests/?req_status=pending", headers=_auth_headers())
            if resp.status_code != 200:
                return
            for r in resp.json():
                table.add_row(
                    r["id"][:8],
                    r["username"],
                    r["server_hostname"],
                    f"{r['requested_duration_hours']}h",
                    "✓" if r["allow_sudo"] else "—",
                    r["reason"][:40],
                )
        except Exception as exc:
            _log.debug("Admin TUI access-requests pane refresh failed", error=str(exc))


class AuditPane(Static):
    """Displays recent audit log entries."""

    def compose(self) -> ComposeResult:
        yield DataTable(id="audit-table")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Time", "Action", "User", "Result")
        self._refresh()

    def _refresh(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        try:
            with _api_client() as client:
                resp = client.get("/audit/?limit=50", headers=_auth_headers())
            if resp.status_code != 200:
                return
            for e in resp.json():
                ts = e["created_at"][:16].replace("T", " ")
                table.add_row(
                    ts,
                    e["action"],
                    (e.get("user_id") or "—")[:8],
                    "✓" if e["success"] else "✗",
                )
        except Exception as exc:
            _log.debug("Admin TUI audit pane refresh failed", error=str(exc))


class BastionAdminTUI(App):
    """Main Bastion Admin terminal user interface."""

    TITLE = "Bastion Admin"
    SUB_TITLE = "Administrative Console"
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("l", "logout", "Logout"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Users", id="tab-users"):
                yield UsersPane()
            with TabPane("Servers", id="tab-servers"):
                yield ServersPane()
            with TabPane("Access Requests", id="tab-ar"):
                yield AccessRequestsPane()
            with TabPane("Audit Log", id="tab-audit"):
                yield AuditPane()
        yield Footer()

    def on_mount(self) -> None:
        if not _TOKEN_FILE.exists() or not _TOKEN_FILE.read_text().strip():
            self.push_screen(AdminLoginScreen())

    def action_refresh(self) -> None:
        """Refresh whichever pane is currently visible."""
        import contextlib

        for pane_cls in (UsersPane, ServersPane, AccessRequestsPane, AuditPane):
            with contextlib.suppress(Exception):
                self.query_one(pane_cls)._refresh()  # type: ignore[attr-defined]

    def action_logout(self) -> None:
        if _TOKEN_FILE.exists():
            _TOKEN_FILE.unlink()
        self.push_screen(AdminLoginScreen())


def run_admin_tui() -> None:
    """Entry point for the Bastion Admin TUI."""
    BastionAdminTUI().run()
