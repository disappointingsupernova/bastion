"""IP allowlist enforcement — validate source IPs against per-user and per-server CIDR lists."""

from __future__ import annotations

import ipaddress
import json

from bastion.logging import get_logger

log = get_logger(__name__)


def check_ip_allowed(source_ip: str, allowlist_json: str | None) -> bool:
    """Return True if source_ip is permitted by the allowlist.

    If allowlist_json is None or empty, all IPs are permitted.
    allowlist_json must be a JSON array of CIDR strings (e.g. ["10.0.0.0/8", "192.168.1.5/32"]).
    """
    if not allowlist_json:
        return True

    try:
        cidrs: list[str] = json.loads(allowlist_json)
    except (ValueError, TypeError):
        log.error("Invalid IP allowlist JSON — denying access", allowlist=allowlist_json)
        return False

    if not cidrs:
        return True

    try:
        addr = ipaddress.ip_address(source_ip)
    except ValueError:
        log.warning("Cannot parse source IP for allowlist check", source_ip=source_ip)
        return False

    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            log.warning("Invalid CIDR in allowlist — skipping", cidr=cidr)

    log.warning(
        "IP not in allowlist — access denied",
        source_ip=source_ip,
        allowlist=cidrs,
    )
    return False
