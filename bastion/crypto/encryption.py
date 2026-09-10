"""Encryption utilities — age for session recordings, Fernet for secrets at rest."""

from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from bastion.logging import get_logger

log = get_logger(__name__)

# ── Fernet (secrets at rest) ──────────────────────────────────────────────────


def _derive_fernet_key(secret_key: str) -> bytes:
    """Derive a Fernet key from the application secret key using PBKDF2."""
    salt = b"bastion-secret-v1"  # Fixed salt — key derivation only, not password hashing
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
    The original plaintext file is securely deleted after encryption.
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

    _secure_delete(plaintext_path)
    log.info("Session recording encrypted", path=str(encrypted_path))
    return encrypted_path


def _secure_delete(path: Path) -> None:
    """Overwrite a file with random bytes before deletion to prevent recovery."""
    size = path.stat().st_size
    with open(path, "r+b") as f:
        f.write(os.urandom(size))
        f.flush()
        os.fsync(f.fileno())
    path.unlink()
    log.debug("Plaintext file securely deleted", path=str(path))
