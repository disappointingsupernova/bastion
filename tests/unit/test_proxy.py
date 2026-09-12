"""Unit tests for the proxy module — session policy enforcement and AsciinemaRecorder."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from bastion.proxy import AsciinemaRecorder, _check_session_policy


class TestCheckSessionPolicy:
    """Tests for _check_session_policy."""

    def test_no_policy_allows_everything(self):
        """With no policy JSON, all commands must be permitted."""
        _check_session_policy(None, "rm -rf /")  # must not raise

    def test_empty_policy_allows_everything(self):
        """An empty policy dict must allow all commands."""
        _check_session_policy("{}", "any-command")

    def test_block_scp_blocks_scp_command(self):
        """block_scp=true must raise PermissionError for scp commands."""
        policy = json.dumps({"block_scp": True})
        with pytest.raises(PermissionError, match="scp/sftp"):
            _check_session_policy(policy, "scp file user@host:/path")

    def test_block_scp_blocks_sftp_server(self):
        """block_scp=true must raise PermissionError for sftp-server subsystem."""
        policy = json.dumps({"block_scp": True})
        with pytest.raises(PermissionError, match="scp/sftp"):
            _check_session_policy(policy, "sftp-server")

    def test_block_scp_blocks_sftp_in_command(self):
        """block_scp=true must raise PermissionError when 'sftp' appears in command."""
        policy = json.dumps({"block_scp": True})
        with pytest.raises(PermissionError, match="scp/sftp"):
            _check_session_policy(policy, "internal-sftp")

    def test_block_scp_false_allows_scp(self):
        """block_scp=false must allow scp commands."""
        policy = json.dumps({"block_scp": False})
        _check_session_policy(policy, "scp file user@host:/path")  # must not raise

    def test_allowed_commands_permits_listed_command(self):
        """A command in allowed_commands must be permitted."""
        policy = json.dumps({"allowed_commands": ["ls -la", "whoami"]})
        _check_session_policy(policy, "ls -la")  # must not raise

    def test_allowed_commands_blocks_unlisted_command(self):
        """A command not in allowed_commands must raise PermissionError."""
        policy = json.dumps({"allowed_commands": ["ls -la"]})
        with pytest.raises(PermissionError, match="not permitted"):
            _check_session_policy(policy, "rm -rf /")

    def test_allowed_commands_empty_list_blocks_all(self):
        """An empty allowed_commands list must block all commands."""
        policy = json.dumps({"allowed_commands": []})
        with pytest.raises(PermissionError):
            _check_session_policy(policy, "ls")

    def test_invalid_json_policy_is_ignored(self):
        """Invalid JSON in policy must be silently ignored (no raise)."""
        _check_session_policy("not-valid-json", "any-command")

    def test_no_command_with_policy_does_not_raise(self):
        """A None command with a restrictive policy must not raise."""
        policy = json.dumps({"allowed_commands": ["ls"]})
        _check_session_policy(policy, None)  # must not raise


class TestAsciinemaRecorder:
    """Tests for AsciinemaRecorder."""

    def test_creates_file_with_header(self):
        """The recorder must create a file with a valid asciinema v2 header."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.cast"
            recorder = AsciinemaRecorder(path)
            recorder.close()

            lines = path.read_text().splitlines()
            assert len(lines) >= 1
            header = json.loads(lines[0])
            assert header["version"] == 2
            assert "width" in header
            assert "height" in header

    def test_write_output_appends_entry(self):
        """write_output must append a JSON entry to the recording file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.cast"
            recorder = AsciinemaRecorder(path)
            recorder.write_output(b"hello world")
            recorder.close()

            lines = path.read_text().splitlines()
            assert len(lines) == 2  # header + one entry
            entry = json.loads(lines[1])
            assert entry[1] == "o"
            assert "hello world" in entry[2]

    def test_write_output_handles_non_utf8(self):
        """write_output must handle non-UTF-8 bytes without raising."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.cast"
            recorder = AsciinemaRecorder(path)
            recorder.write_output(b"\xff\xfe invalid utf-8")
            recorder.close()
            # File must still be readable
            lines = path.read_text().splitlines()
            assert len(lines) == 2

    def test_context_manager_closes_file(self):
        """Using AsciinemaRecorder as a context manager must close the file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.cast"
            with AsciinemaRecorder(path) as recorder:
                recorder.write_output(b"data")
            assert recorder._file.closed

    def test_close_is_idempotent(self):
        """Calling close() twice must not raise."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.cast"
            recorder = AsciinemaRecorder(path)
            recorder.close()
            recorder.close()  # must not raise

    def test_elapsed_time_is_non_negative(self):
        """The elapsed time in each entry must be >= 0."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.cast"
            recorder = AsciinemaRecorder(path)
            recorder.write_output(b"test")
            recorder.close()

            lines = path.read_text().splitlines()
            entry = json.loads(lines[1])
            assert entry[0] >= 0.0
