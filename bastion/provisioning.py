"""Remote server provisioning — user creation, SSH hardening, sudo, and package management."""

from __future__ import annotations

import asyncio
import re
import shlex

import asyncssh

from bastion.logging import get_logger

log = get_logger(__name__)

# ── Input validation ──────────────────────────────────────────────────────────

_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_\-]{0,31}$")
_PACKAGE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\.\-\+\_]{0,127}$")


def _validate_username(username: str) -> str:
    """Validate a Unix username. Raises ValueError on unsafe input."""
    if not _USERNAME_RE.match(username):
        raise ValueError(f"Invalid username {username!r} — must match Unix username rules")
    return username


def _validate_package_name(name: str) -> str:
    """Validate a package name. Raises ValueError on unsafe input."""
    if not _PACKAGE_NAME_RE.match(name):
        raise ValueError(f"Invalid package name {name!r}")
    return name


# ── SSH hardening configuration applied to remote servers ─────────────────────
SSH_HARDENING_CONFIG = """\
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
    """Run a command on the remote server and return the result.

    The command string must be a static string or built from validated,
    shell-quoted values only. Never interpolate raw user input here.
    """
    result = await conn.run(command, check=False)
    if check and result.returncode != 0:
        stderr = result.stderr
        raise RuntimeError(
            f"Remote command failed (exit {result.returncode}): {command!r}\n"
            f"{stderr.decode() if isinstance(stderr, bytes) else stderr}"
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

    All user-supplied values are validated and shell-quoted before use.
    Creates the bastion-users group if it does not exist, adds the user to it,
    and optionally grants passwordless sudo.
    """
    safe_username = _validate_username(username)
    log.info("Provisioning user on remote server", username=safe_username, allow_sudo=allow_sudo)

    # Ensure bastion-users group exists
    await _run(conn, "getent group bastion-users || groupadd bastion-users")

    # Create user if not present — all values shell-quoted
    uid_flag = f"--uid {int(uid)}" if uid else ""
    quoted_username = shlex.quote(safe_username)
    await _run(
        conn,
        f"id {quoted_username} &>/dev/null || useradd --create-home --shell /bin/bash "
        f"--groups bastion-users {uid_flag} {quoted_username}",
    )

    # Add to bastion-users group (idempotent)
    await _run(conn, f"usermod -aG bastion-users {quoted_username}")

    # Write the CA public key via stdin to avoid any shell interpretation of its content
    await conn.run(
        "cat > /etc/ssh/bastion_ca.pub && chmod 644 /etc/ssh/bastion_ca.pub",
        input=ca_public_key.encode() + b"\n",
        check=True,
    )

    # Configure sudoers if required — write via stdin, never interpolate into shell
    sudoers_file = f"/etc/sudoers.d/bastion-{safe_username}"
    if allow_sudo:
        sudoers_line = f"{safe_username} ALL=(ALL) NOPASSWD:ALL\n"
        await conn.run(
            f"cat > {shlex.quote(sudoers_file)} && chmod 440 {shlex.quote(sudoers_file)}",
            input=sudoers_line.encode(),
            check=True,
        )
        log.info("Passwordless sudo granted", username=safe_username)
    else:
        await _run(conn, f"rm -f {shlex.quote(sudoers_file)}")

    log.info("User provisioned successfully", username=safe_username)


async def deprovision_user(
    conn: asyncssh.SSHClientConnection,
    username: str,
) -> None:
    """Remove a user account and their sudo configuration from the remote server."""
    safe_username = _validate_username(username)
    log.info("Deprovisioning user from remote server", username=safe_username)
    quoted = shlex.quote(safe_username)
    await _run(conn, f"rm -f /etc/sudoers.d/bastion-{quoted}")
    await _run(conn, f"userdel --remove {quoted}", check=False)
    log.info("User deprovisioned", username=safe_username)


async def apply_ssh_hardening(
    conn: asyncssh.SSHClientConnection,
    ca_public_key: str,
) -> None:
    """Apply SSH hardening configuration to the remote server.

    Writes a Bastion-managed sshd_config drop-in and restarts sshd.
    The CA public key is written via stdin to avoid shell interpretation.
    """
    log.info("Applying SSH hardening to remote server")

    # Write hardening config via stdin — no shell interpolation of content
    await conn.run(
        "cat > /etc/ssh/sshd_config.d/99-bastion.conf && "
        "chmod 600 /etc/ssh/sshd_config.d/99-bastion.conf",
        input=SSH_HARDENING_CONFIG.encode(),
        check=True,
    )

    # Write CA public key via stdin
    await conn.run(
        "cat > /etc/ssh/bastion_ca.pub && chmod 644 /etc/ssh/bastion_ca.pub",
        input=ca_public_key.encode() + b"\n",
        check=True,
    )

    # Validate config before restarting
    result = await _run(conn, "sshd -t", check=False)
    if result.returncode != 0:
        stderr = result.stderr
        raise RuntimeError(
            f"sshd config validation failed: "
            f"{stderr.decode() if isinstance(stderr, bytes) else stderr}"
        )

    await _run(conn, "systemctl restart sshd")
    log.info("SSH hardening applied and sshd restarted")


async def get_available_updates(
    conn: asyncssh.SSHClientConnection,
    os_family: str,
) -> list[dict[str, str]]:
    """Query the remote server for available package updates.

    Returns a list of dicts with 'name', 'installed_version', and 'available_version'.
    """
    packages: list[dict[str, str]] = []

    if os_family == "debian":
        await _run(conn, "apt-get update -qq")
        result = await _run(
            conn,
            "apt list --upgradable 2>/dev/null | grep -v 'Listing...' | "
            "awk -F'[/ ]' '{print $1\"|\"$3\"|\"$5}'",
        )
        stdout = result.stdout
        if stdout is None:
            return packages
        text = stdout.decode() if isinstance(stdout, bytes) else stdout
        for line in text.strip().splitlines():
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

    if os_family == "rhel":
        result = await _run(
            conn,
            "yum check-update --quiet 2>/dev/null | awk 'NF==3 {print $1\"|\"$2}' || true",
        )
        stdout = result.stdout
        if stdout is None:
            return packages
        text = stdout.decode() if isinstance(stdout, bytes) else stdout
        for line in text.strip().splitlines():
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
    return packages


async def apply_updates(
    conn: asyncssh.SSHClientConnection,
    os_family: str,
    package_names: list[str] | None = None,
) -> str:
    """Apply available updates on the remote server.

    Package names are validated against a strict allowlist regex before use.
    If package_names is provided, only those packages are updated.
    Returns the command output.
    """
    if package_names is not None:
        # Validate every package name before it touches the shell
        safe_packages = [_validate_package_name(p) for p in package_names]
        # Shell-quote each name and join — belt-and-braces after validation
        pkgs_arg = " ".join(shlex.quote(p) for p in safe_packages)
    else:
        pkgs_arg = None

    if os_family == "debian":
        if pkgs_arg:
            cmd = f"DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y {pkgs_arg}"
        else:
            cmd = "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
    elif os_family == "rhel":
        if pkgs_arg:
            cmd = f"yum update -y {pkgs_arg}"
        else:
            cmd = "yum update -y"
    else:
        raise ValueError(f"Unsupported OS family: {os_family}")

    result = await _run(conn, cmd)
    log.info("Package updates applied", os_family=os_family, packages=package_names)
    stdout = result.stdout
    if stdout is None:
        return ""
    return stdout.decode() if isinstance(stdout, bytes) else stdout


async def reboot_server(conn: asyncssh.SSHClientConnection, delay_seconds: int = 60) -> None:
    """Schedule a reboot on the remote server."""
    # delay_seconds is validated at the API layer (ge=0, le=3600)
    delay_minutes = max(0, int(delay_seconds) // 60)
    await _run(conn, f"shutdown -r +{delay_minutes} 'Bastion-initiated reboot'")
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
