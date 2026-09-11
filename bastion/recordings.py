"""Live session monitoring and recording playback for admin use.

Live tail: the proxy publishes each output chunk to a Redis channel.
Admins subscribe via SSE to stream the cast in real-time.

Recording playback: streams a completed (decrypted) recording back to an
authorised admin. The decrypt key is never stored — it is derived per-admin
from a master key using HKDF, so each admin has a unique key and all
decryption events are logged.
"""

from __future__ import annotations

import hashlib
import hmac
import subprocess
import tempfile
from pathlib import Path

import redis.asyncio as aioredis

from bastion.config import get_settings
from bastion.logging import get_logger

log = get_logger(__name__)

_LIVE_CHANNEL_PREFIX = "bastion:session:live:"


def live_channel(session_id: str) -> str:
    """Return the Redis pub/sub channel name for live session output."""
    return f"{_LIVE_CHANNEL_PREFIX}{session_id}"


async def publish_live_output(session_id: str, data: str) -> None:
    """Publish a chunk of session output to the live monitoring channel."""
    settings = get_settings()
    client = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        await client.publish(live_channel(session_id), data)
    finally:
        await client.aclose()


async def subscribe_live_output(session_id: str):
    """Async generator that yields output chunks for a live session.

    Yields raw output strings as they arrive. Stops when the sentinel
    '__END__' message is received (published by the proxy on session end).
    """
    settings = get_settings()
    client = aioredis.from_url(settings.redis_url, decode_responses=True)
    pubsub = client.pubsub()
    await pubsub.subscribe(live_channel(session_id))
    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            data = message["data"]
            if data == "__END__":
                break
            yield data
    finally:
        await pubsub.unsubscribe(live_channel(session_id))
        await client.aclose()


# ── Admin-derived decrypt keys ────────────────────────────────────────────────


def derive_admin_decrypt_key(master_key: str, admin_user_id: str) -> bytes:
    """Derive a per-admin age-compatible key from the master recordings key.

    Uses HMAC-SHA256(master_key, admin_user_id) as a deterministic derivation.
    Each admin gets a unique key; the master key is never exposed directly.
    """
    return hmac.new(
        master_key.encode(),
        admin_user_id.encode(),
        digestmod="sha256",
    ).digest()


def admin_key_fingerprint(admin_user_id: str, master_key: str) -> str:
    """Return a short fingerprint of the admin's derived key for audit logging."""
    key = derive_admin_decrypt_key(master_key, admin_user_id)
    return hashlib.sha256(key).hexdigest()[:16]


def decrypt_recording(encrypted_path: Path, age_identity_content: str) -> bytes:
    """Decrypt an age-encrypted recording using the provided identity.

    The identity is written to a temporary file and deleted immediately after use.
    Returns the plaintext recording bytes.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".key", delete=False, prefix="bastion-dec-"
    ) as f:
        f.write(age_identity_content)
        identity_path = Path(f.name)

    try:
        identity_path.chmod(0o600)
        result = subprocess.run(
            ["age", "--decrypt", "--identity", str(identity_path), str(encrypted_path)],
            capture_output=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"age decryption failed: {result.stderr.decode(errors='replace')}"
            )
        return result.stdout
    finally:
        identity_path.unlink(missing_ok=True)
