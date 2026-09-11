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
    command = <<-CMD
      python3 -c "
from bastion.client import BastionClient
import os
client = BastionClient(token=os.environ['BASTION_TOKEN'], socket_path='${var.bastion_socket}')
client.create_user(
    username='${each.value.username}',
    email='${each.value.email}',
    password=os.environ.get('BASTION_USER_PASSWORD_${upper(each.key)}', __import__('secrets').token_urlsafe(16)),
    full_name='${lookup(each.value, "full_name", "")}',
    role='${lookup(each.value, "role", "user")}',
)
print('Created user ${each.value.username}')
"
    CMD
    environment = {
      BASTION_TOKEN = var.bastion_token
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
    command = <<-CMD
      python3 -c "
from bastion.client import BastionClient
import os
client = BastionClient(token=os.environ['BASTION_TOKEN'], socket_path='${var.bastion_socket}')
client.onboard_server(
    hostname='${each.value.hostname}',
    display_name='${lookup(each.value, "display_name", each.value.hostname)}',
    ssh_port=${lookup(each.value, "ssh_port", 22)},
    environment='${lookup(each.value, "environment", "")}',
)
print('Onboarded server ${each.value.hostname}')
"
    CMD
    environment = {
      BASTION_TOKEN = var.bastion_token
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
    command = <<-CMD
      python3 -c "
from bastion.client import BastionClient
import os
client = BastionClient(token=os.environ['BASTION_TOKEN'], socket_path='${var.bastion_socket}')
client.grant_access(
    server_id='${each.value.server_id}',
    user_id='${each.value.user_id}',
    allow_sudo=${title(lookup(each.value, "allow_sudo", "false"))},
)
print('Granted access: user=${each.value.user_id} server=${each.value.server_id}')
"
    CMD
    environment = {
      BASTION_TOKEN = var.bastion_token
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
