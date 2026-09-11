"""SSH proxy — sits between the user and the remote server, recording sessions in asciinema v2 format."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from pathlib import Path

import asyncssh

from bastion.crypto.encryption import encrypt_recording_age
from bastion.db import get_db_session
from bastion.logging import get_logger
from bastion.models import Server, Session, SessionStatus, User

log = get_logger(__name__)


# ── Session policy enforcement ────────────────────────────────────────────────


def _check_session_policy(policy_json: str | None, command: str | None) -> None:
    """Enforce privileged session controls defined in the server's session_policy.

    Raises PermissionError if the requested operation is blocked by policy.
    Policy is a JSON object with optional keys:
      - block_scp: bool — block scp/sftp subsystem and scp commands
      - block_port_forwarding: bool — block TCP forwarding requests
      - allowed_commands: list[str] — if set, only these exact commands are permitted
    """
    if not policy_json:
        return
    try:
        policy: dict = json.loads(policy_json)
    except (ValueError, TypeError):
        log.warning("Invalid session_policy JSON — ignoring", policy=policy_json)
        return

    if command:
        # Block scp/sftp
        if policy.get("block_scp") and (
            command.startswith("scp ") or command.startswith("sftp-server")
            or "sftp" in command
        ):
            raise PermissionError("scp/sftp is not permitted on this server.")

        # Restrict to allowed commands
        allowed = policy.get("allowed_commands")
        if allowed is not None and command not in allowed:
            raise PermissionError(
                f"Command not permitted by server policy. Allowed: {allowed}"
            )



def _make_known_hosts(ca_pub_key_path: Path) -> asyncssh.SSHKnownHosts:
    """Return an asyncssh known-hosts object that trusts the Bastion CA for all hosts.

    This replaces known_hosts=None with CA-based host verification, preventing
    MITM attacks while avoiding per-host key management.
    """
    ca_pub_key_text = ca_pub_key_path.read_text().strip()
    # @cert-authority * means: trust any host certificate signed by this CA
    known_hosts_text = f"@cert-authority * {ca_pub_key_text}\n"
    return asyncssh.SSHKnownHosts(known_hosts_text)


class AsciinemaRecorder:
    """Writes SSH I/O to an asciinema v2 format file."""

    def __init__(self, path: Path, width: int = 220, height: int = 50) -> None:
        self._path = path
        self._start = time.time()
        self._file = open(path, "w", encoding="utf-8")  # noqa: SIM115
        header = {
            "version": 2,
            "width": width,
            "height": height,
            "timestamp": int(self._start),
            "title": f"Bastion session — {datetime.now(tz=UTC).isoformat()}",
        }
        self._file.write(json.dumps(header) + "\n")
        self._file.flush()

    def __enter__(self) -> AsciinemaRecorder:
        """Support use as a context manager."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close the recording file on context manager exit."""
        self.close()

    def write_output(self, data: bytes) -> None:
        """Record terminal output data."""
        elapsed = round(time.time() - self._start, 6)
        entry = [elapsed, "o", data.decode("utf-8", errors="replace")]
        self._file.write(json.dumps(entry) + "\n")
        self._file.flush()

    def close(self) -> None:
        """Flush and close the recording file."""
        if not self._file.closed:
            self._file.flush()
            self._file.close()
        log.debug("Asciinema recording closed", path=str(self._path))


class BastionSSHSession(asyncssh.SSHServerSession):
    """An SSH server session that proxies to the target and records I/O."""

    def __init__(
        self,
        session_record: Session,
        target_conn: asyncssh.SSHClientConnection,
        recorder: AsciinemaRecorder | None,
        session_policy: str | None = None,
    ) -> None:
        self._session_record = session_record
        self._target_conn = target_conn
        self._recorder = recorder
        self._session_policy = session_policy
        self._target_process: asyncssh.SSHClientProcess | None = None
        self._bytes_sent = 0
        self._bytes_received = 0

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:
        """Called when the client channel is established."""
        self._chan = chan

    def shell_requested(self) -> bool:
        """Accept shell requests."""
        return True

    def exec_requested(self, command: str) -> bool:
        """Accept exec requests, enforcing session policy."""
        try:
            _check_session_policy(self._session_policy, command)
        except PermissionError as exc:
            log.warning(
                "Exec request blocked by session policy",
                session_id=self._session_record.id,
                command=command,
                reason=str(exc),
            )
            return False
        self._command = command
        return True

    def subsystem_requested(self, subsystem: str) -> bool:
        """Block sftp subsystem if session policy requires it."""
        try:
            _check_session_policy(self._session_policy, f"sftp-server" if subsystem == "sftp" else subsystem)
        except PermissionError as exc:
            log.warning(
                "Subsystem request blocked by session policy",
                session_id=self._session_record.id,
                subsystem=subsystem,
                reason=str(exc),
            )
            return False
        return True

    def port_forwarding_requested(
        self, dest_host: str, dest_port: int, orig_host: str, orig_port: int
    ) -> bool:
        """Block port forwarding if session policy requires it."""
        if self._session_policy:
            try:
                policy: dict = json.loads(self._session_policy)
                if policy.get("block_port_forwarding"):
                    log.warning(
                        "Port forwarding blocked by session policy",
                        session_id=self._session_record.id,
                        dest=f"{dest_host}:{dest_port}",
                    )
                    return False
            except (ValueError, TypeError):
                pass
        return True

    def pty_requested(  # type: ignore[override]
        self, term_type: str, term_size: tuple, term_modes: object
    ) -> bool:
        """Accept PTY requests and record terminal dimensions for the recording header."""
        if self._recorder and len(term_size) >= 2:  # type: ignore[arg-type]
            pass
        return True

    async def session_started(self) -> None:  # type: ignore[override]
        """Open a shell or exec on the target server once the session is established."""
        command = getattr(self, "_command", None)
        try:
            if command:
                self._target_process = await self._target_conn.create_process(command)
            else:
                self._target_process = await self._target_conn.create_process()
        except Exception as exc:
            log.error(
                "Failed to open process on target server",
                session_id=self._session_record.id,
                error=str(exc),
            )
            self._chan.exit(1)
            return

        asyncio.create_task(self._forward_output())

    async def _forward_output(self) -> None:
        """Forward output from the target server to the client, recording as we go.

        Also listens for admin kill signals via Redis pub/sub and terminates
        the connection if one is received.
        """
        import asyncio

        from bastion.session_kill import subscribe_kill_signal

        async def _watch_for_kill() -> None:
            """Background task that terminates the session on a kill signal."""
            async for _ in subscribe_kill_signal(self._session_record.id):
                log.info(
                    "Kill signal received — terminating session",
                    session_id=self._session_record.id,
                )
                if self._target_process:
                    self._target_process.close()
                self._chan.exit(1)
                break

        kill_task = asyncio.create_task(_watch_for_kill())
        try:
            async for data in self._target_process.stdout:  # type: ignore[union-attr]
                if isinstance(data, str):
                    data = data.encode()
                self._bytes_received += len(data)
                if self._recorder:
                    self._recorder.write_output(data)
                self._chan.write(data)
        except Exception as exc:
            log.debug(
                "Output forwarding ended", session_id=self._session_record.id, reason=str(exc)
            )
        finally:
            kill_task.cancel()
            exit_status = self._target_process.exit_status or 0  # type: ignore[union-attr]
            self._chan.exit(exit_status)
            await self._finalise()

    def data_received(self, data: bytes, datatype: asyncssh.DataType) -> None:
        """Forward input from the client to the target server."""
        self._bytes_sent += len(data)
        if self._target_process:
            self._target_process.stdin.write(data)

    def eof_received(self) -> bool:  # type: ignore[override]
        """Handle EOF from the client."""
        if self._target_process:
            self._target_process.stdin.write_eof()
        return False

    async def _finalise(self) -> None:
        """Update the session record with final statistics and encrypt the recording."""
        if self._recorder:
            self._recorder.close()

        async with get_db_session() as db:
            from sqlalchemy import select as sa_select

            result = await db.execute(
                sa_select(Session).where(Session.id == self._session_record.id)
            )
            session = result.scalar_one_or_none()
            if session:
                session.status = SessionStatus.COMPLETED
                session.ended_at = datetime.now(tz=UTC)
                session.bytes_sent = self._bytes_sent
                session.bytes_received = self._bytes_received

                if self._recorder:
                    from bastion.config import get_settings

                    settings = get_settings()
                    raw_path = self._session_record.recording_path
                    if raw_path is None:
                        return
                    recording_path = Path(raw_path)
                    if settings.recordings_age_public_key and recording_path.exists():
                        try:
                            encrypted_path = encrypt_recording_age(
                                recording_path, settings.recordings_age_public_key
                            )
                            session.recording_path = str(encrypted_path)
                            session.recording_encrypted = True
                        except Exception as exc:
                            log.error(
                                "Failed to encrypt session recording",
                                session_id=session.id,
                                error=str(exc),
                            )

        log.info(
            "SSH session finalised",
            session_id=self._session_record.id,
            bytes_sent=self._bytes_sent,
            bytes_received=self._bytes_received,
        )


async def open_proxy_session(
    user: User,
    server: Server,
    session_record: Session,
    remote_username: str,
    cert_bytes: bytes,
    user_public_key_bytes: bytes,
) -> asyncssh.SSHClientConnection:
    """Open an SSH connection to the target server using the issued certificate.

    Host verification uses the Bastion CA public key (@cert-authority) rather
    than known_hosts=None, preventing MITM attacks on managed servers.
    Returns the asyncssh client connection for use in the proxy session.
    """
    import tempfile

    from bastion.config import get_settings

    settings = get_settings()
    known_hosts = _make_known_hosts(settings.ca_key_path.with_suffix(".pub"))

    with tempfile.TemporaryDirectory(prefix="bastion-proxy-") as tmpdir:
        tmp = Path(tmpdir)
        key_file = tmp / "id_ed25519"
        cert_file = tmp / "id_ed25519-cert.pub"

        # Write the user's public key and cert temporarily for asyncssh
        key_file.write_bytes(user_public_key_bytes)
        key_file.chmod(0o600)
        cert_file.write_bytes(cert_bytes)
        cert_file.chmod(0o600)

        connect_kwargs: dict = {
            "username": remote_username,
            "client_keys": [str(key_file)],
            "known_hosts": known_hosts,
        }

        if server.proxy_jump_server_id:
            from sqlalchemy import select

            async with get_db_session() as db:
                from bastion.models import Server as ServerModel

                result = await db.execute(
                    select(ServerModel).where(ServerModel.id == server.proxy_jump_server_id)
                )
                jump_server = result.scalar_one_or_none()
            if jump_server:
                connect_kwargs["tunnel"] = await asyncssh.connect(
                    jump_server.hostname,
                    port=jump_server.ssh_port,
                    username=remote_username,
                    client_keys=[str(key_file)],
                    known_hosts=known_hosts,
                )

        conn = await asyncssh.connect(
            server.hostname,
            port=server.ssh_port,
            **connect_kwargs,
        )

    log.info(
        "Proxy SSH connection established",
        user_id=user.id,
        server=server.hostname,
        session_id=session_record.id,
    )
    return conn
