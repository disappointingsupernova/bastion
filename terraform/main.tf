# Bastion Terraform resources
#
# Each resource uses a null_resource with local-exec provisioners that call
# the bastion.client Python library. The BASTION_TOKEN environment variable
# must be set to a valid admin JWT before running terraform apply.

variable "bastion_socket" {
  description = "Path to the bastion-admin Unix socket."
  type        = string
  default     = "/opt/bastion/run/bastion-admin.sock"
}

# ── Data sources ──────────────────────────────────────────────────────────────

data "external" "bastion_users" {
  program = [
    "python3", "-c",
    <<-PYTHON
import json, os, sys
from bastion.client import BastionClient
token = os.environ.get("BASTION_TOKEN", "")
client = BastionClient(token=token, socket_path="${var.bastion_socket}")
users = client.list_users()
# external data source requires a flat string map
print(json.dumps({"users": json.dumps(users)}))
PYTHON
  ]
}

data "external" "bastion_servers" {
  program = [
    "python3", "-c",
    <<-PYTHON
import json, os, sys
from bastion.client import BastionClient
token = os.environ.get("BASTION_TOKEN", "")
client = BastionClient(token=token, socket_path="${var.bastion_socket}")
servers = client.list_servers()
print(json.dumps({"servers": json.dumps(servers)}))
PYTHON
  ]
}

# ── User resource ─────────────────────────────────────────────────────────────

resource "null_resource" "bastion_user" {
  for_each = var.bastion_users

  triggers = {
    username  = each.value.username
    email     = each.value.email
    role      = lookup(each.value, "role", "user")
    full_name = lookup(each.value, "full_name", "")
  }

  provisioner "local-exec" {
    # All user-supplied values are passed as environment variables and read
    # inside Python — never interpolated into the script string to prevent
    # shell injection via values containing quotes or backslashes.
    command = "python3 -c 'import os; from bastion.client import BastionClient; c = BastionClient(token=os.environ[\"BASTION_TOKEN\"], socket_path=os.environ[\"BASTION_SOCKET\"]); c.create_user(username=os.environ[\"B_USERNAME\"], email=os.environ[\"B_EMAIL\"], password=os.environ.get(\"B_PASSWORD\") or __import__(\"secrets\").token_urlsafe(16), full_name=os.environ.get(\"B_FULL_NAME\", \"\"), role=os.environ.get(\"B_ROLE\", \"user\")); print(\"Created user\", os.environ[\"B_USERNAME\"])'"
    environment = {
      BASTION_TOKEN  = var.bastion_token
      BASTION_SOCKET = var.bastion_socket
      B_USERNAME     = each.value.username
      B_EMAIL        = each.value.email
      B_FULL_NAME    = lookup(each.value, "full_name", "")
      B_ROLE         = lookup(each.value, "role", "user")
    }
    on_failure = fail
  }
}

# ── Server resource ───────────────────────────────────────────────────────────

resource "null_resource" "bastion_server" {
  for_each = var.bastion_servers

  triggers = {
    hostname    = each.value.hostname
    environment = lookup(each.value, "environment", "")
    ssh_port    = lookup(each.value, "ssh_port", "22")
  }

  provisioner "local-exec" {
    command = "python3 -c 'import os; from bastion.client import BastionClient; c = BastionClient(token=os.environ[\"BASTION_TOKEN\"], socket_path=os.environ[\"BASTION_SOCKET\"]); c.onboard_server(hostname=os.environ[\"B_HOSTNAME\"], display_name=os.environ.get(\"B_DISPLAY_NAME\") or os.environ[\"B_HOSTNAME\"], ssh_port=int(os.environ.get(\"B_SSH_PORT\", \"22\")), environment=os.environ.get(\"B_ENVIRONMENT\", \"\")); print(\"Onboarded server\", os.environ[\"B_HOSTNAME\"])'"
    environment = {
      BASTION_TOKEN   = var.bastion_token
      BASTION_SOCKET  = var.bastion_socket
      B_HOSTNAME      = each.value.hostname
      B_DISPLAY_NAME  = lookup(each.value, "display_name", "")
      B_SSH_PORT      = tostring(lookup(each.value, "ssh_port", 22))
      B_ENVIRONMENT   = lookup(each.value, "environment", "")
    }
    on_failure = fail
  }
}

# ── Access grant resource ─────────────────────────────────────────────────────

resource "null_resource" "bastion_access" {
  for_each = var.bastion_access_grants

  triggers = {
    user_id    = each.value.user_id
    server_id  = each.value.server_id
    allow_sudo = lookup(each.value, "allow_sudo", "false")
  }

  provisioner "local-exec" {
    command = "python3 -c 'import os; from bastion.client import BastionClient; c = BastionClient(token=os.environ[\"BASTION_TOKEN\"], socket_path=os.environ[\"BASTION_SOCKET\"]); c.grant_access(server_id=os.environ[\"B_SERVER_ID\"], user_id=os.environ[\"B_USER_ID\"], allow_sudo=os.environ.get(\"B_ALLOW_SUDO\", \"false\").lower() == \"true\"); print(\"Granted access: user=\", os.environ[\"B_USER_ID\"], \"server=\", os.environ[\"B_SERVER_ID\"])'"
    environment = {
      BASTION_TOKEN  = var.bastion_token
      BASTION_SOCKET = var.bastion_socket
      B_SERVER_ID    = each.value.server_id
      B_USER_ID      = each.value.user_id
      B_ALLOW_SUDO   = tostring(lookup(each.value, "allow_sudo", false))
    }
    on_failure = fail
  }
}

# ── Variables ─────────────────────────────────────────────────────────────────

variable "bastion_token" {
  description = "Admin JWT for the Bastion API. Set via TF_VAR_bastion_token or BASTION_TOKEN."
  type        = string
  sensitive   = true
  default     = ""
}

variable "bastion_users" {
  description = "Map of users to create. Key is an arbitrary label."
  type = map(object({
    username  = string
    email     = string
    role      = optional(string, "user")
    full_name = optional(string, "")
  }))
  default = {}
}

variable "bastion_servers" {
  description = "Map of servers to onboard. Key is an arbitrary label."
  type = map(object({
    hostname     = string
    display_name = optional(string, "")
    ssh_port     = optional(number, 22)
    environment  = optional(string, "")
  }))
  default = {}
}

variable "bastion_access_grants" {
  description = "Map of access grants. Key is an arbitrary label."
  type = map(object({
    user_id    = string
    server_id  = string
    allow_sudo = optional(bool, false)
  }))
  default = {}
}
