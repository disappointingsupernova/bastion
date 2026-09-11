"""SSH Certificate Authority — key generation, certificate issuance, and KRL management."""

from __future__ import annotations

import json
import os
import re
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

# Allowed characters in a certificate principal (Unix username rules)
_PRINCIPAL_RE = re.compile(r"^[a-z_][a-z0-9_\-]{0,31}$")
# Allowed characters in a key ID (alphanumeric, hyphens, underscores)
_KEY_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")


def _validate_principal(principal: str) -> str:
    """Validate a certificate principal is a safe Unix username.

    Raises ValueError if the principal contains unsafe characters.
    """
    if not _PRINCIPAL_RE.match(principal):
        raise ValueError(f"Invalid principal {principal!r} — must match Unix username rules")
    return principal


def generate_ca_keypair(ca_key_path: Path, passphrase: bytes) -> None:
    """Generate an Ed25519 CA keypair and write to disk, encrypted with a passphrase.

    The private key is encrypted with BestAvailableEncryption and written with
    mode 0600. The public key is written with 0644.
    This should only be called once during initial setup.
    """
    ca_key_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
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
    """Load the CA private key from disk, decrypting with the configured passphrase."""
    settings = get_settings()
    key_data = settings.ca_key_path.read_bytes()
    passphrase = settings.ca_key_passphrase.encode() if settings.ca_key_passphrase else None
    return serialization.load_ssh_private_key(  # type: ignore[return-value]
        key_data, password=passphrase
    )


async def _next_serial(db: AsyncSession) -> int:
    """Atomically increment and return the next certificate serial number."""
    entry = CertSerial()
    db.add(entry)
    await db.flush()
    return entry.id


def _validate_public_key(public_key_bytes: bytes) -> None:
    """Validate that the submitted public key is a recognised OpenSSH key type.

    Raises ValueError if the key does not start with a known OpenSSH key type prefix.
    """
    allowed_prefixes = (
        b"ssh-ed25519 ",
        b"ecdsa-sha2-nistp256 ",
        b"ecdsa-sha2-nistp384 ",
        b"ecdsa-sha2-nistp521 ",
        b"ssh-rsa ",
    )
    if not any(public_key_bytes.startswith(p) for p in allowed_prefixes):
        raise ValueError("Submitted public key is not a recognised OpenSSH key type")
    if len(public_key_bytes) > 8192:
        raise ValueError("Submitted public key exceeds maximum permitted size")


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

    # Validate all user-supplied values before they touch the shell
    _validate_public_key(public_key_bytes)
    validated_principals = [_validate_principal(p) for p in principals]

    settings = get_settings()
    hours = validity_hours or settings.ssh_cert_validity_hours
    serial = await _next_serial(db)

    now = int(time.time())
    valid_after = datetime.fromtimestamp(now, tz=UTC)
    valid_before_ts = now + (hours * 3600)
    valid_before = datetime.fromtimestamp(valid_before_ts, tz=UTC)

    # key_id is internal — built from serial only, not from user input
    key_id = f"bastion-{serial}"
    if not _KEY_ID_RE.match(key_id):
        raise ValueError(f"Generated key_id {key_id!r} contains unsafe characters")

    principals_str = ",".join(validated_principals)

    with tempfile.TemporaryDirectory(prefix="bastion-cert-") as tmpdir:
        tmp = Path(tmpdir)
        pub_key_file = tmp / "user.pub"
        pub_key_file.write_bytes(public_key_bytes)
        pub_key_file.chmod(0o600)

        cert_file = tmp / "user-cert.pub"

        # All arguments are passed as a list — no shell interpolation
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
        principals=json.dumps(validated_principals),
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
        principals=validated_principals,
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

    # Terminate any active sessions that were issued with this certificate (fix #26)
    from bastion.models import Session, SessionStatus

    session_result = await db.execute(
        select(Session).where(
            Session.certificate_id == cert_id,
            Session.status == SessionStatus.ACTIVE,
        )
    )
    active_sessions = session_result.scalars().all()
    for session in active_sessions:
        session.status = SessionStatus.REVOKED
        session.ended_at = datetime.now(tz=UTC)
        session.termination_reason = f"Certificate revoked: {reason}"
        log.warning(
            "Active session terminated due to certificate revocation",
            session_id=session.id,
            cert_id=cert_id,
        )
    if active_sessions:
        await db.flush()

    await _rebuild_krl(db)

    # Queue KRL distribution to all managed servers
    try:
        from celery import current_app as celery_app
        celery_app.send_task("workers.tasks.notifications.distribute_krl")
        log.info("KRL distribution task queued after revocation", cert_id=cert_id)
    except Exception as exc:
        log.warning("Could not queue KRL distribution task", error=str(exc))

    log.info(
        "Certificate revoked",
        cert_id=cert_id,
        serial=cert.serial,
        reason=reason,
        revoked_by=revoked_by_user_id,
    )


async def issue_host_certificate(
    db: AsyncSession,
    server_hostname: str,
    host_public_key_bytes: bytes,
    validity_hours: int | None = None,
) -> bytes:
    """Issue a signed SSH host certificate for a managed server.

    Host certificates allow remote servers to prove their identity to clients
    using the Bastion CA, eliminating the known_hosts problem on first connect.
    Returns the raw certificate bytes — never written to disk on the bastion.
    """
    import subprocess
    import tempfile

    _validate_public_key(host_public_key_bytes)

    settings = get_settings()
    hours = validity_hours or (settings.ssh_cert_validity_hours * 24)  # default 8 days for hosts
    serial = await _next_serial(db)

    # key_id is built from serial only — no user input
    key_id = f"bastion-host-{serial}"
    # Principals for a host cert are the hostnames/IPs the cert is valid for
    principal = server_hostname
    if not _PRINCIPAL_RE.match(principal.replace(".", "").replace("-", "")):
        # Hostnames may contain dots — use a relaxed check for host certs
        if not all(c.isalnum() or c in ".-_" for c in principal):
            raise ValueError(f"Invalid hostname {principal!r} for host certificate")

    with tempfile.TemporaryDirectory(prefix="bastion-hostcert-") as tmpdir:
        tmp = Path(tmpdir)
        pub_key_file = tmp / "host.pub"
        pub_key_file.write_bytes(host_public_key_bytes)
        pub_key_file.chmod(0o600)

        result = subprocess.run(
            [
                "ssh-keygen",
                "-s", str(settings.ca_key_path),
                "-I", key_id,
                "-h",  # host certificate flag
                "-n", principal,
                "-V", f"+{hours}h",
                "-z", str(serial),
                str(pub_key_file),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            log.error("Host certificate issuance failed", hostname=server_hostname, stderr=result.stderr)
            raise RuntimeError(f"ssh-keygen failed: {result.stderr}")

        cert_file = pub_key_file.with_name("host-cert.pub")
        cert_bytes = cert_file.read_bytes()

    log.info("SSH host certificate issued", hostname=server_hostname, serial=serial, key_id=key_id)
    return cert_bytes


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
        subprocess.run(
            ["ssh-keygen", "-k", "-f", str(krl_path), "-u"],
            input=b"",
            capture_output=True,
            timeout=10,
        )
        return

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
