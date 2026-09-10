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

    def write_output(self, data: bytes) -> None:
        """Record terminal output data."""
        elapsed = round(time.time() - self._start, 6)
        entry = [elapsed, "o", data.decode("utf-8", errors="replace")]
        self._file.write(json.dumps(entry) + "\n")
        self._file.flush()

    def close(self) -> None:
        """Flush and close the recording file."""
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
    ) -> None:
        self._session_record = session_record
        self._target_conn = target_conn
        self._recorder = recorder
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
        """Accept exec requests."""
        self._command = command
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
        """Forward output from the target server to the client, recording as we go."""
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

    Returns the asyncssh client connection for use in the proxy session.
    """
    import tempfile

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
            "known_hosts": None,  # TODO: implement known_hosts verification
        }

        if server.proxy_jump_server_id:
            # Proxy jump via an intermediate host
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
                    known_hosts=None,
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
