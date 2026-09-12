"""Session kill signal mechanism using Redis pub/sub.

When an admin terminates a session via the API, a kill signal is published to
a Redis channel. The proxy process subscribes to its session's channel and
terminates the connection when it receives the signal.

The kill message is signed with HMAC-SHA256 keyed to the application SECRET_KEY
so that only the bastion service itself can publish valid kill signals.
"""

from __future__ import annotations

import hmac
import time

import redis.asyncio as aioredis

from bastion.config import get_settings
from bastion.logging import get_logger

log = get_logger(__name__)

_KILL_CHANNEL_PREFIX = "bastion:session:kill:"
_KILL_MESSAGE_TTL = 30  # seconds — reject messages older than this


def _kill_channel(session_id: str) -> str:
    """Return the Redis pub/sub channel name for a session kill signal."""
    return f"{_KILL_CHANNEL_PREFIX}{session_id}"


def _sign_kill_message(session_id: str, secret_key: str) -> str:
    """Return a signed kill message: 'kill:<timestamp>:<hmac>'."""
    ts = str(int(time.time()))
    sig = hmac.new(
        secret_key.encode(),
        f"kill:{session_id}:{ts}".encode(),
        digestmod="sha256",
    ).hexdigest()
    return f"kill:{ts}:{sig}"


def _verify_kill_message(message: str, session_id: str, secret_key: str) -> bool:
    """Verify a kill message signature and timestamp.

    Returns True only if the HMAC is valid and the message is not older than
    _KILL_MESSAGE_TTL seconds, preventing replay attacks.
    """
    try:
        parts = message.split(":")
        if len(parts) != 3 or parts[0] != "kill":
            return False
        ts = int(parts[1])
        received_sig = parts[2]
    except (ValueError, IndexError):
        return False

    if abs(time.time() - ts) > _KILL_MESSAGE_TTL:
        log.warning(
            "Kill signal rejected — message timestamp outside acceptable window",
            session_id=session_id,
            age_seconds=int(time.time() - ts),
        )
        return False

    expected_sig = hmac.new(
        secret_key.encode(),
        f"kill:{session_id}:{ts}".encode(),
        digestmod="sha256",
    ).hexdigest()
    return hmac.compare_digest(expected_sig, received_sig)


async def publish_kill_signal(session_id: str) -> None:
    """Publish a signed kill signal for the given session to Redis.

    The message is signed with HMAC-SHA256 so that only the bastion service
    can publish valid kill signals, preventing denial-of-service via Redis.
    """
    settings = get_settings()
    message = _sign_kill_message(session_id, settings.secret_key)
    client = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        await client.publish(_kill_channel(session_id), message)
        log.info("Session kill signal published", session_id=session_id)
    finally:
        await client.aclose()


async def subscribe_kill_signal(session_id: str):
    """Async generator that yields when a valid signed kill signal is received.

    Ignores messages that fail HMAC verification or are outside the replay window.
    """
    settings = get_settings()
    client = aioredis.from_url(settings.redis_url, decode_responses=True)
    pubsub = client.pubsub()
    await pubsub.subscribe(_kill_channel(session_id))
    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            data = message["data"]
            if _verify_kill_message(data, session_id, settings.secret_key):
                log.info("Session kill signal received and verified", session_id=session_id)
                yield message
                break
            else:
                log.warning(
                    "Kill signal rejected — invalid HMAC or replayed message",
                    session_id=session_id,
                )
    finally:
        await pubsub.unsubscribe(_kill_channel(session_id))
        await client.aclose()
