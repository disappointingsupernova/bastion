"""Unit tests for session_kill and recordings Redis pub/sub and decrypt functions."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bastion.recordings import decrypt_recording, publish_live_output, subscribe_live_output
from bastion.session_kill import publish_kill_signal, subscribe_kill_signal


@pytest.mark.asyncio
class TestPublishKillSignal:
    """Tests for publish_kill_signal."""

    async def test_publishes_signed_message_to_correct_channel(self):
        """publish_kill_signal must publish a signed message to the session's kill channel."""
        from unittest.mock import MagicMock as MM

        mock_client = AsyncMock()
        mock_client.aclose = AsyncMock()

        mock_settings = MM()
        mock_settings.redis_url = "redis://localhost"
        mock_settings.secret_key = "a-secret-key-that-is-long-enough-xx"

        with (
            patch("bastion.session_kill.aioredis.from_url", return_value=mock_client),
            patch("bastion.session_kill.get_settings", return_value=mock_settings),
        ):
            await publish_kill_signal("session-abc")

        call_args = mock_client.publish.call_args
        assert call_args[0][0] == "bastion:session:kill:session-abc"
        message = call_args[0][1]
        parts = message.split(":")
        assert len(parts) == 3
        assert parts[0] == "kill"
        assert parts[1].isdigit()
        assert len(parts[2]) == 64

    async def test_closes_client_after_publish(self):
        """publish_kill_signal must close the Redis client after publishing."""
        from unittest.mock import MagicMock as MM

        mock_client = AsyncMock()
        mock_client.aclose = AsyncMock()

        mock_settings = MM()
        mock_settings.redis_url = "redis://localhost"
        mock_settings.secret_key = "a-secret-key-that-is-long-enough-xx"

        with (
            patch("bastion.session_kill.aioredis.from_url", return_value=mock_client),
            patch("bastion.session_kill.get_settings", return_value=mock_settings),
        ):
            await publish_kill_signal("session-xyz")

        mock_client.aclose.assert_called_once()

    async def test_closes_client_on_publish_error(self):
        """publish_kill_signal must close the Redis client even if publish raises."""
        from unittest.mock import MagicMock as MM

        mock_client = AsyncMock()
        mock_client.publish = AsyncMock(side_effect=RuntimeError("Redis down"))
        mock_client.aclose = AsyncMock()

        mock_settings = MM()
        mock_settings.redis_url = "redis://localhost"
        mock_settings.secret_key = "a-secret-key-that-is-long-enough-xx"

        with (
            patch("bastion.session_kill.aioredis.from_url", return_value=mock_client),
            patch("bastion.session_kill.get_settings", return_value=mock_settings),
            pytest.raises(RuntimeError),
        ):
            await publish_kill_signal("session-err")

        mock_client.aclose.assert_called_once()


@pytest.mark.asyncio
class TestSubscribeKillSignal:
    """Tests for subscribe_kill_signal."""

    async def test_yields_on_valid_signed_kill_message(self):
        """subscribe_kill_signal must yield when a valid signed kill message is received."""
        from unittest.mock import MagicMock as MM

        from bastion.session_kill import _sign_kill_message

        test_secret = "a-secret-key-that-is-long-enough-xx"
        signed = _sign_kill_message("session-123", test_secret)
        messages = [
            {"type": "subscribe", "data": 1},
            {"type": "message", "data": signed},
        ]

        mock_pubsub = AsyncMock()
        mock_pubsub.subscribe = AsyncMock()
        mock_pubsub.unsubscribe = AsyncMock()
        mock_pubsub.listen = MagicMock(return_value=_async_iter(messages))

        mock_client = AsyncMock()
        mock_client.pubsub = MagicMock(return_value=mock_pubsub)
        mock_client.aclose = AsyncMock()

        mock_settings = MM()
        mock_settings.redis_url = "redis://localhost"
        mock_settings.secret_key = test_secret

        with (
            patch("bastion.session_kill.aioredis.from_url", return_value=mock_client),
            patch("bastion.session_kill.get_settings", return_value=mock_settings),
        ):
            received = []
            async for msg in subscribe_kill_signal("session-123"):
                received.append(msg)

        assert len(received) == 1

    async def test_ignores_unsigned_kill_message(self):
        """subscribe_kill_signal must ignore unsigned 'kill' messages."""
        from unittest.mock import MagicMock as MM

        messages = [
            {"type": "subscribe", "data": 1},
            {"type": "message", "data": "kill"},
        ]

        mock_pubsub = AsyncMock()
        mock_pubsub.subscribe = AsyncMock()
        mock_pubsub.unsubscribe = AsyncMock()
        mock_pubsub.listen = MagicMock(return_value=_async_iter(messages))

        mock_client = AsyncMock()
        mock_client.pubsub = MagicMock(return_value=mock_pubsub)
        mock_client.aclose = AsyncMock()

        mock_settings = MM()
        mock_settings.redis_url = "redis://localhost"
        mock_settings.secret_key = "a-secret-key-that-is-long-enough-xx"

        with (
            patch("bastion.session_kill.aioredis.from_url", return_value=mock_client),
            patch("bastion.session_kill.get_settings", return_value=mock_settings),
        ):
            received = []
            async for msg in subscribe_kill_signal("session-456"):
                received.append(msg)

        assert received == []

    async def test_ignores_non_message_types(self):
        """subscribe_kill_signal must ignore subscribe/unsubscribe type messages."""
        from unittest.mock import MagicMock as MM

        messages = [
            {"type": "subscribe", "data": 1},
            {"type": "psubscribe", "data": 1},
        ]

        mock_pubsub = AsyncMock()
        mock_pubsub.subscribe = AsyncMock()
        mock_pubsub.unsubscribe = AsyncMock()
        mock_pubsub.listen = MagicMock(return_value=_async_iter(messages))

        mock_client = AsyncMock()
        mock_client.pubsub = MagicMock(return_value=mock_pubsub)
        mock_client.aclose = AsyncMock()

        mock_settings = MM()
        mock_settings.redis_url = "redis://localhost"
        mock_settings.secret_key = "a-secret-key-that-is-long-enough-xx"

        with (
            patch("bastion.session_kill.aioredis.from_url", return_value=mock_client),
            patch("bastion.session_kill.get_settings", return_value=mock_settings),
        ):
            received = []
            async for msg in subscribe_kill_signal("session-456"):
                received.append(msg)

        assert received == []


@pytest.mark.asyncio
class TestPublishLiveOutput:
    """Tests for publish_live_output."""

    async def test_publishes_to_live_channel(self):
        """publish_live_output must publish data to the live session channel."""
        mock_client = AsyncMock()
        mock_client.aclose = AsyncMock()

        with patch("bastion.recordings.aioredis.from_url", return_value=mock_client):
            await publish_live_output("session-abc", "some output")

        mock_client.publish.assert_called_once_with(
            "bastion:session:live:session-abc", "some output"
        )

    async def test_closes_client_after_publish(self):
        """publish_live_output must close the Redis client after publishing."""
        mock_client = AsyncMock()
        mock_client.aclose = AsyncMock()

        with patch("bastion.recordings.aioredis.from_url", return_value=mock_client):
            await publish_live_output("session-abc", "data")

        mock_client.aclose.assert_called_once()


@pytest.mark.asyncio
class TestSubscribeLiveOutput:
    """Tests for subscribe_live_output."""

    async def test_yields_output_chunks(self):
        """subscribe_live_output must yield data chunks until __END__ is received."""
        messages = [
            {"type": "subscribe", "data": 1},
            {"type": "message", "data": "chunk1"},
            {"type": "message", "data": "chunk2"},
            {"type": "message", "data": "__END__"},
        ]

        mock_pubsub = AsyncMock()
        mock_pubsub.subscribe = AsyncMock()
        mock_pubsub.unsubscribe = AsyncMock()
        mock_pubsub.listen = MagicMock(return_value=_async_iter(messages))

        mock_client = AsyncMock()
        mock_client.pubsub = MagicMock(return_value=mock_pubsub)
        mock_client.aclose = AsyncMock()

        with patch("bastion.recordings.aioredis.from_url", return_value=mock_client):
            chunks = []
            async for chunk in subscribe_live_output("session-abc"):
                chunks.append(chunk)

        assert chunks == ["chunk1", "chunk2"]

    async def test_stops_at_end_sentinel(self):
        """subscribe_live_output must stop yielding after __END__ is received."""
        messages = [
            {"type": "message", "data": "__END__"},
            {"type": "message", "data": "should-not-appear"},
        ]

        mock_pubsub = AsyncMock()
        mock_pubsub.subscribe = AsyncMock()
        mock_pubsub.unsubscribe = AsyncMock()
        mock_pubsub.listen = MagicMock(return_value=_async_iter(messages))

        mock_client = AsyncMock()
        mock_client.pubsub = MagicMock(return_value=mock_pubsub)
        mock_client.aclose = AsyncMock()

        with patch("bastion.recordings.aioredis.from_url", return_value=mock_client):
            chunks = []
            async for chunk in subscribe_live_output("session-abc"):
                chunks.append(chunk)

        assert chunks == []


class TestDecryptRecording:
    """Tests for decrypt_recording."""

    def test_raises_runtime_error_on_age_failure(self):
        """decrypt_recording must raise RuntimeError when age returns non-zero exit code."""
        with tempfile.TemporaryDirectory() as tmpdir:
            enc_path = Path(tmpdir) / "recording.cast.age"
            enc_path.write_bytes(b"fake encrypted content")

            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_result.stderr = b"age: decryption failed"

            with (
                patch("bastion.recordings.subprocess.run", return_value=mock_result),
                pytest.raises(RuntimeError, match="age decryption failed"),
            ):
                decrypt_recording(enc_path, "AGE-SECRET-KEY-1fake")

    def test_returns_plaintext_on_success(self):
        """decrypt_recording must return the stdout bytes on success."""
        with tempfile.TemporaryDirectory() as tmpdir:
            enc_path = Path(tmpdir) / "recording.cast.age"
            enc_path.write_bytes(b"fake encrypted content")

            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = b'{"version":2}\n[0.1,"o","hello"]'

            with patch("bastion.recordings.subprocess.run", return_value=mock_result):
                result = decrypt_recording(enc_path, "AGE-SECRET-KEY-1fake")

        assert result == b'{"version":2}\n[0.1,"o","hello"]'

    def test_identity_file_not_accessible_after_use(self):
        """The temporary identity file must not be accessible after decryption completes.

        With delete=True on NamedTemporaryFile the OS removes the file on close,
        so we verify the subprocess is called and the function returns successfully
        without leaving any key material in the system temp directory.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            enc_path = Path(tmpdir) / "recording.cast.age"
            enc_path.write_bytes(b"fake")

            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = b"plaintext"

            identity_paths_used: list[str] = []

            original_run = __import__("subprocess").run

            def capture_identity(args, **kwargs):
                # Record the identity file path passed to age
                if "--identity" in args:
                    idx = args.index("--identity")
                    identity_paths_used.append(args[idx + 1])
                return mock_result

            with patch("bastion.recordings.subprocess.run", side_effect=capture_identity):
                result = decrypt_recording(enc_path, "AGE-SECRET-KEY-1fake")

        assert result == b"plaintext"
        # The identity file must have been passed to age
        assert len(identity_paths_used) == 1
        # The identity file must no longer exist after the call
        assert not Path(identity_paths_used[0]).exists()


# ── Async iterator helper ─────────────────────────────────────────────────────


async def _async_iter(items):
    """Yield items from a list as an async iterator."""
    for item in items:
        yield item
