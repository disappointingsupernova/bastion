"""SSH Certificate Authority — key generation, certificate issuance, and KRL management."""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bastion.config import get_settings
from bastion.logging import get_logger
from bastion.models import CertSerial, CertStatus, SshCertificate

log = get_logger(__name__)


def generate_ca_keypair(ca_key_path: Path) -> None:
    """Generate an Ed25519 CA keypair and write to disk.

    The private key is written with mode 0600, the public key with 0644.
    This should only be called once during initial setup.
    """
    ca_key_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_openssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )

    ca_key_path.write_bytes(private_pem)
    ca_key_path.chmod(0o600)

    pub_path = ca_key_path.with_suffix(".pub")
    pub_path.write_bytes(public_openssh + b"\n")
    pub_path.chmod(0o644)

    log.info("CA keypair generated", path=str(ca_key_path))


def _load_ca_private_key() -> Ed25519PrivateKey:
    """Load the CA private key from disk."""
    settings = get_settings()
    key_data = settings.ca_key_path.read_bytes()
    return serialization.load_ssh_private_key(key_data, password=None)  # type: ignore[return-value]


async def _next_serial(db: AsyncSession) -> int:
    """Atomically increment and return the next certificate serial number."""
    entry = CertSerial()
    db.add(entry)
    await db.flush()
    return entry.id


async def issue_certificate(
    db: AsyncSession,
    user_id: str,
    username: str,
    public_key_bytes: bytes,
    principals: list[str],
    validity_hours: int | None = None,
    issued_from_ip: str | None = None,
) -> tuple[bytes, SshCertificate]:
    """Issue a signed SSH user certificate for the given public key.

    Returns the raw certificate bytes and the database record.
    The certificate is never written to disk — it is returned to the caller only.
    """
    import subprocess
    import tempfile

    settings = get_settings()
    hours = validity_hours or settings.ssh_cert_validity_hours
    serial = await _next_serial(db)

    now = int(time.time())
    valid_after = datetime.fromtimestamp(now, tz=UTC)
    valid_before_ts = now + (hours * 3600)
    valid_before = datetime.fromtimestamp(valid_before_ts, tz=UTC)

    key_id = f"bastion-{username}-{serial}"
    principals_str = ",".join(principals)

    with tempfile.TemporaryDirectory(prefix="bastion-cert-") as tmpdir:
        tmp = Path(tmpdir)
        pub_key_file = tmp / "user.pub"
        pub_key_file.write_bytes(public_key_bytes)
        pub_key_file.chmod(0o600)

        cert_file = tmp / "user-cert.pub"

        result = subprocess.run(
            [
                "ssh-keygen",
                "-s",
                str(settings.ca_key_path),
                "-I",
                key_id,
                "-n",
                principals_str,
                "-V",
                f"+{hours}h",
                "-z",
                str(serial),
                str(pub_key_file),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            log.error(
                "Certificate issuance failed",
                user_id=user_id,
                stderr=result.stderr,
            )
            raise RuntimeError(f"ssh-keygen failed: {result.stderr}")

        cert_bytes = cert_file.read_bytes()

    record = SshCertificate(
        user_id=user_id,
        serial=serial,
        key_id=key_id,
        principals=json.dumps(principals),
        valid_after=valid_after,
        valid_before=valid_before,
        status=CertStatus.ACTIVE,
        issued_from_ip=issued_from_ip,
    )
    db.add(record)
    await db.flush()

    log.info(
        "SSH certificate issued",
        user_id=user_id,
        serial=serial,
        key_id=key_id,
        principals=principals,
        valid_hours=hours,
    )
    return cert_bytes, record


async def revoke_certificate(
    db: AsyncSession,
    cert_id: str,
    reason: str,
    revoked_by_user_id: str,
) -> None:
    """Revoke a certificate by ID, update the KRL, and mark the DB record."""
    result = await db.execute(select(SshCertificate).where(SshCertificate.id == cert_id))
    cert = result.scalar_one_or_none()
    if cert is None:
        raise ValueError(f"Certificate {cert_id} not found")
    if cert.status == CertStatus.REVOKED:
        log.warning("Certificate already revoked", cert_id=cert_id)
        return

    cert.status = CertStatus.REVOKED
    cert.revoked_at = datetime.now(tz=UTC)
    cert.revocation_reason = reason
    await db.flush()

    await _rebuild_krl(db)

    log.info(
        "Certificate revoked",
        cert_id=cert_id,
        serial=cert.serial,
        reason=reason,
        revoked_by=revoked_by_user_id,
    )


async def _rebuild_krl(db: AsyncSession) -> None:
    """Rebuild the KRL file from all revoked certificates in the database."""
    import subprocess

    settings = get_settings()
    result = await db.execute(
        select(SshCertificate).where(SshCertificate.status == CertStatus.REVOKED)
    )
    revoked = result.scalars().all()

    if not revoked:
        log.debug("No revoked certificates — KRL will be empty")

    serials = [str(c.serial) for c in revoked]

    krl_path = settings.krl_path
    krl_path.parent.mkdir(parents=True, exist_ok=True)

    if not serials:
        # Create an empty KRL
        subprocess.run(
            ["ssh-keygen", "-k", "-f", str(krl_path), "-u"],
            input=b"",
            capture_output=True,
            timeout=10,
        )
        return

    # Write serials to a temp file and build KRL
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".serials", delete=False) as f:
        f.write("\n".join(f"serial:{s}" for s in serials))
        serial_file = f.name

    try:
        subprocess.run(
            [
                "ssh-keygen",
                "-k",
                "-f",
                str(krl_path),
                "-s",
                str(settings.ca_key_path) + ".pub",
                serial_file,
            ],
            capture_output=True,
            timeout=10,
            check=True,
        )
    finally:
        os.unlink(serial_file)

    log.info("KRL rebuilt", revoked_count=len(serials), krl_path=str(krl_path))
