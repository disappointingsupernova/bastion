"""Remote server provisioning — user creation, SSH hardening, sudo, and package management."""

from __future__ import annotations

import asyncio

import asyncssh

from bastion.logging import get_logger

log = get_logger(__name__)

# ── SSH hardening configuration applied to remote servers ─────────────────────
SSH_HARDENING_CONFIG = """
# Applied by Bastion — do not edit manually
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
AllowGroups bastion-users
TrustedUserCAKeys /etc/ssh/bastion_ca.pub
AuthorizedPrincipalsCommand /usr/bin/bastion-principals %u
AuthorizedPrincipalsCommandUser nobody
"""


async def _run(
    conn: asyncssh.SSHClientConnection, command: str, check: bool = True
) -> asyncssh.SSHCompletedProcess:
    """Run a command on the remote server and return the result."""
    result = await conn.run(command, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Remote command failed (exit {result.returncode}): {command!r}\n{result.stderr}"
        )
    log.debug("Remote command executed", command=command, exit_code=result.returncode)
    return result


async def provision_user(
    conn: asyncssh.SSHClientConnection,
    username: str,
    uid: int | None,
    allow_sudo: bool,
    ca_public_key: str,
) -> None:
    """Create a Unix account on the remote server and configure SSH certificate authentication.

    Creates the bastion-users group if it does not exist, adds the user to it,
    and optionally grants passwordless sudo.
    """
    log.info("Provisioning user on remote server", username=username, allow_sudo=allow_sudo)

    # Ensure bastion-users group exists
    await _run(conn, "getent group bastion-users || groupadd bastion-users")

    # Create user if not present
    uid_flag = f"--uid {uid}" if uid else ""
    await _run(
        conn,
        f"id {username} &>/dev/null || useradd --create-home --shell /bin/bash "
        f"--groups bastion-users {uid_flag} {username}",
    )

    # Add to bastion-users group (idempotent)
    await _run(conn, f"usermod -aG bastion-users {username}")

    # Install the CA public key so the server trusts Bastion-issued certs
    await _run(conn, f"echo '{ca_public_key}' > /etc/ssh/bastion_ca.pub")
    await _run(conn, "chmod 644 /etc/ssh/bastion_ca.pub")

    # Configure sudoers if required
    sudoers_file = f"/etc/sudoers.d/bastion-{username}"
    if allow_sudo:
        await _run(
            conn,
            f"echo '{username} ALL=(ALL) NOPASSWD:ALL' > {sudoers_file} && "
            f"chmod 440 {sudoers_file}",
        )
        log.info("Passwordless sudo granted", username=username)
    else:
        # Remove sudo access if it was previously granted
        await _run(conn, f"rm -f {sudoers_file}")

    log.info("User provisioned successfully", username=username)


async def deprovision_user(
    conn: asyncssh.SSHClientConnection,
    username: str,
) -> None:
    """Remove a user account and their sudo configuration from the remote server."""
    log.info("Deprovisioning user from remote server", username=username)
    await _run(conn, f"rm -f /etc/sudoers.d/bastion-{username}")
    await _run(conn, f"userdel --remove {username}", check=False)
    log.info("User deprovisioned", username=username)


async def apply_ssh_hardening(
    conn: asyncssh.SSHClientConnection,
    ca_public_key: str,
) -> None:
    """Apply SSH hardening configuration to the remote server.

    Writes a Bastion-managed sshd_config drop-in and restarts sshd.
    """
    log.info("Applying SSH hardening to remote server")

    config_content = SSH_HARDENING_CONFIG.strip()
    escaped = config_content.replace("'", "'\\''")
    await _run(conn, f"echo '{escaped}' > /etc/ssh/sshd_config.d/99-bastion.conf")
    await _run(conn, "chmod 600 /etc/ssh/sshd_config.d/99-bastion.conf")
    await _run(conn, f"echo '{ca_public_key}' > /etc/ssh/bastion_ca.pub")
    await _run(conn, "chmod 644 /etc/ssh/bastion_ca.pub")

    # Validate config before restarting
    result = await _run(conn, "sshd -t", check=False)
    if result.returncode != 0:
        raise RuntimeError(f"sshd config validation failed: {result.stderr}")

    await _run(conn, "systemctl restart sshd")
    log.info("SSH hardening applied and sshd restarted")


async def get_available_updates(
    conn: asyncssh.SSHClientConnection,
    os_family: str,
) -> list[dict[str, str]]:
    """Query the remote server for available package updates.

    Returns a list of dicts with 'name', 'installed_version', and 'available_version'.
    """
    if os_family == "debian":
        await _run(conn, "apt-get update -qq")
        result = await _run(
            conn,
            "apt list --upgradable 2>/dev/null | grep -v 'Listing...' | "
            "awk -F'[/ ]' '{print $1\"|\"$3\"|\"$5}'",
        )
        packages = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("|")
            if len(parts) == 3:
                packages.append(
                    {
                        "name": parts[0],
                        "available_version": parts[1],
                        "installed_version": parts[2],
                    }
                )
        return packages

    elif os_family == "rhel":
        result = await _run(
            conn,
            "yum check-update --quiet 2>/dev/null | awk 'NF==3 {print $1\"|\"$2}' || true",
        )
        packages = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("|")
            if len(parts) == 2:
                packages.append(
                    {
                        "name": parts[0],
                        "available_version": parts[1],
                        "installed_version": "",
                    }
                )
        return packages

    log.warning("Unknown OS family — cannot check for updates", os_family=os_family)
    return []


async def apply_updates(
    conn: asyncssh.SSHClientConnection,
    os_family: str,
    package_names: list[str] | None = None,
) -> str:
    """Apply available updates on the remote server.

    If package_names is provided, only those packages are updated.
    Returns the command output.
    """
    if os_family == "debian":
        if package_names:
            pkgs = " ".join(package_names)
            cmd = f"DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y {pkgs}"
        else:
            cmd = "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
    elif os_family == "rhel":
        if package_names:
            pkgs = " ".join(package_names)
            cmd = f"yum update -y {pkgs}"
        else:
            cmd = "yum update -y"
    else:
        raise ValueError(f"Unsupported OS family: {os_family}")

    result = await _run(conn, cmd)
    log.info("Package updates applied", os_family=os_family, packages=package_names)
    return result.stdout


async def reboot_server(conn: asyncssh.SSHClientConnection, delay_seconds: int = 60) -> None:
    """Schedule a reboot on the remote server."""
    await _run(conn, f"shutdown -r +{delay_seconds // 60} 'Bastion-initiated reboot'")
    log.info("Remote server reboot scheduled", delay_seconds=delay_seconds)


async def check_connectivity(hostname: str, port: int = 22, timeout: float = 5.0) -> bool:
    """Check whether a remote server is reachable on its SSH port."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port),
            timeout=timeout,
        )
        writer.close()
        return True
    except Exception:
        return False
