#!/usr/bin/python
"""Ansible module for managing Bastion SSH bastion resources.

DOCUMENTATION:
    module: bastion_resource
    short_description: Manage Bastion users, servers, and access grants
    description:
        - Create, update, or delete Bastion users, servers, and access grants
          via the Bastion admin API client library.
        - Must be run on the bastion host or with the admin socket accessible.
    options:
        resource:
            description: Resource type to manage.
            required: true
            choices: [user, server, access_grant, group, group_member]
        state:
            description: Desired state.
            default: present
            choices: [present, absent]
        token:
            description: Admin JWT. Falls back to BASTION_TOKEN environment variable.
            required: false
        socket_path:
            description: Path to the bastion-admin Unix socket.
            default: /opt/bastion/run/bastion-admin.sock
        username:
            description: Username (for user resource).
        email:
            description: Email address (for user resource).
        password:
            description: Password (for user resource, create only).
        role:
            description: User role.
            default: user
            choices: [admin, user, auditor, read_only]
        full_name:
            description: Full name (for user resource).
        user_id:
            description: User ID (for access_grant and group_member resources).
        hostname:
            description: Server hostname (for server resource).
        server_id:
            description: Server ID (for access_grant resource).
        ssh_port:
            description: SSH port (for server resource).
            default: 22
        environment:
            description: Server environment tag (for server resource).
        allow_sudo:
            description: Grant sudo access (for access_grant resource).
            default: false
        group_name:
            description: Group name (for group resource).
        group_id:
            description: Group ID (for group_member resource).
"""

from __future__ import annotations

import os
import traceback

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import]


def run_module() -> None:
    """Entry point for the Ansible module."""
    module_args = {
        "resource": {
            "type": "str",
            "required": True,
            "choices": ["user", "server", "access_grant", "group", "group_member"],
        },
        "state": {"type": "str", "default": "present", "choices": ["present", "absent"]},
        "token": {"type": "str", "no_log": True, "default": ""},
        "socket_path": {"type": "str", "default": "/opt/bastion/run/bastion-admin.sock"},
        "username": {"type": "str"},
        "email": {"type": "str"},
        "password": {"type": "str", "no_log": True},
        "role": {
            "type": "str",
            "default": "user",
            "choices": ["admin", "user", "auditor", "read_only"],
        },
        "full_name": {"type": "str"},
        "user_id": {"type": "str"},
        "hostname": {"type": "str"},
        "server_id": {"type": "str"},
        "ssh_port": {"type": "int", "default": 22},
        "environment": {"type": "str"},
        "allow_sudo": {"type": "bool", "default": False},
        "group_name": {"type": "str"},
        "group_id": {"type": "str"},
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=False)

    token = module.params["token"] or os.environ.get("BASTION_TOKEN", "")
    if not token:
        module.fail_json(msg="token is required (or set BASTION_TOKEN environment variable)")

    try:
        from bastion.client import BastionClient, BastionClientError
    except ImportError:
        module.fail_json(msg="bastion Python package is not installed on this host")
        return

    client = BastionClient(token=token, socket_path=module.params["socket_path"])
    resource = module.params["resource"]
    state = module.params["state"]

    try:
        result = _dispatch(client, resource, state, module.params)
    except BastionClientError as exc:
        if exc.status_code == 409 and state == "present":
            # Already exists — idempotent
            module.exit_json(changed=False, msg=f"{resource} already exists")
            return
        if exc.status_code == 404 and state == "absent":
            module.exit_json(changed=False, msg=f"{resource} not found — nothing to remove")
            return
        module.fail_json(msg=str(exc))
        return
    except Exception as exc:
        module.fail_json(msg=str(exc), exception=traceback.format_exc())
        return

    module.exit_json(changed=True, **result)


def _dispatch(client: object, resource: str, state: str, params: dict) -> dict:
    """Route to the appropriate client method based on resource and state."""
    from bastion.client import BastionClient

    assert isinstance(client, BastionClient)

    if resource == "user":
        if state == "present":
            user = client.create_user(
                username=params["username"],
                email=params["email"],
                password=params.get("password") or __import__("secrets").token_urlsafe(16),
                full_name=params.get("full_name"),
                role=params.get("role", "user"),
            )
            return {"user": user}
        else:
            # Find user by username then delete
            users = client.list_users()
            match = next((u for u in users if u["username"] == params["username"]), None)
            if match:
                client.delete_user(match["id"])
            return {}

    if resource == "server":
        if state == "present":
            server = client.onboard_server(
                hostname=params["hostname"],
                ssh_port=params.get("ssh_port", 22),
                environment=params.get("environment"),
            )
            return {"server": server}
        else:
            servers = client.list_servers()
            match = next((s for s in servers if s["hostname"] == params["hostname"]), None)
            if match:
                client.delete_server(match["id"])
            return {}

    if resource == "access_grant":
        if state == "present":
            result = client.grant_access(
                server_id=params["server_id"],
                user_id=params["user_id"],
                allow_sudo=params.get("allow_sudo", False),
            )
            return {"access_grant": result}
        else:
            client.revoke_access(
                server_id=params["server_id"],
                user_id=params["user_id"],
            )
            return {}

    if resource == "group":
        if state == "present":
            group = client.create_group(name=params["group_name"])
            return {"group": group}
        # No delete endpoint yet — return no-op
        return {}

    if resource == "group_member":
        if state == "present":
            client.add_group_member(
                group_id=params["group_id"],
                user_id=params["user_id"],
            )
        else:
            client.remove_group_member(
                group_id=params["group_id"],
                user_id=params["user_id"],
            )
        return {}

    raise ValueError(f"Unknown resource: {resource}")


if __name__ == "__main__":
    run_module()
