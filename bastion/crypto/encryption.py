"""Encryption utilities — age for session recordings, Fernet for secrets at rest."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import subprocess
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from bastion.logging import get_logger

log = get_logger(__name__)

# ── Fernet (secrets at rest) ──────────────────────────────────────────────────

# Salt version tag — increment this if the derivation scheme ever changes,
# which will invalidate all existing encrypted secrets (requiring re-encryption).
_SALT_VERSION = b"bastion-fernet-v2"


def _derive_fernet_key(secret_key: str) -> bytes:
    """Derive a Fernet key from the application secret key using PBKDF2.

    The salt is derived from SECRET_KEY itself via HMAC-SHA256, making it
    unique per installation without requiring separate storage. This eliminates
    the fixed-salt weakness while keeping the derivation deterministic.
    """
    # Derive a per-installation salt from the secret key — unique per deployment
    salt = hmac.new(
        secret_key.encode(),
        _SALT_VERSION,
        digestmod="sha256",
    ).digest()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))


def get_fernet(secret_key: str) -> Fernet:
    """Return a Fernet instance derived from the application secret key."""
    return Fernet(_derive_fernet_key(secret_key))


def encrypt_secret(plaintext: str, secret_key: str) -> str:
    """Encrypt a secret string for storage in the database. Returns a base64 token."""
    f = get_fernet(secret_key)
    return f.encrypt(plaintext.encode()).decode()


def decrypt_secret(token: str, secret_key: str) -> str:
    """Decrypt a secret string retrieved from the database."""
    f = get_fernet(secret_key)
    return f.decrypt(token.encode()).decode()


# ── age (session recording encryption) ───────────────────────────────────────


def encrypt_recording_age(plaintext_path: Path, age_public_key: str) -> Path:
    """Encrypt a session recording file using age with the configured public key.

    The encrypted file is written alongside the original with a .age extension.
    The original plaintext file is deleted after encryption. On modern filesystems
    (SSD, CoW) overwrite-based erasure is not reliable; the primary protection is
    age encryption — the plaintext is removed as promptly as possible.
    Returns the path to the encrypted file.
    """
    encrypted_path = plaintext_path.with_suffix(plaintext_path.suffix + ".age")

    result = subprocess.run(
        [
            "age",
            "--recipient",
            age_public_key,
            "--output",
            str(encrypted_path),
            str(plaintext_path),
        ],
        capture_output=True,
        timeout=60,
    )

    if result.returncode != 0:
        log.error(
            "age encryption failed",
            path=str(plaintext_path),
            stderr=result.stderr.decode(),
        )
        raise RuntimeError(f"age encryption failed: {result.stderr.decode()}")

    _delete_plaintext(plaintext_path)
    log.info("Session recording encrypted", path=str(encrypted_path))
    return encrypted_path


def _delete_plaintext(path: Path) -> None:
    """Delete a plaintext recording file.

    Note: on SSDs and CoW filesystems (btrfs, ZFS, APFS) overwriting bytes does
    not guarantee erasure due to wear levelling and copy-on-write semantics.
    The primary security control is age asymmetric encryption applied before
    this deletion. We attempt a best-effort overwrite then unlink.
    """
    try:
        size = path.stat().st_size
        with open(path, "r+b") as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    except OSError as exc:
        log.warning("Could not overwrite plaintext recording before deletion", error=str(exc))
    path.unlink(missing_ok=True)
    log.debug("Plaintext recording deleted", path=str(path))
