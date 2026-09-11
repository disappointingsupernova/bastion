"""Session kill signal mechanism using Redis pub/sub.

When an admin terminates a session via the API, a kill signal is published to
a Redis channel. The proxy process subscribes to its session's channel and
terminates the connection when it receives the signal.
"""

from __future__ import annotations

import redis.asyncio as aioredis

from bastion.config import get_settings
from bastion.logging import get_logger

log = get_logger(__name__)

_KILL_CHANNEL_PREFIX = "bastion:session:kill:"


def _kill_channel(session_id: str) -> str:
    """Return the Redis pub/sub channel name for a session kill signal."""
    return f"{_KILL_CHANNEL_PREFIX}{session_id}"


async def publish_kill_signal(session_id: str) -> None:
    """Publish a kill signal for the given session to Redis.

    The proxy process holding that session subscribes to this channel and
    will terminate the SSH connection on receipt.
    """
    settings = get_settings()
    client = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        await client.publish(_kill_channel(session_id), "kill")
        log.info("Session kill signal published", session_id=session_id)
    finally:
        await client.aclose()


async def subscribe_kill_signal(session_id: str):
    """Async generator that yields when a kill signal is received for this session.

    Usage in the proxy:
        async for _ in subscribe_kill_signal(session_id):
            # terminate the connection
            break
    """
    settings = get_settings()
    client = aioredis.from_url(settings.redis_url, decode_responses=True)
    pubsub = client.pubsub()
    await pubsub.subscribe(_kill_channel(session_id))
    try:
        async for message in pubsub.listen():
            if message["type"] == "message" and message["data"] == "kill":
                log.info("Session kill signal received", session_id=session_id)
                yield message
                break
    finally:
        await pubsub.unsubscribe(_kill_channel(session_id))
        await client.aclose()
