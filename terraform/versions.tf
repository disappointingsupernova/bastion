# Bastion Terraform Provider
#
# This provider manages Bastion users, servers, and access grants via the
# Bastion API client library. It uses the `external` data source and
# `null_resource` with local-exec provisioners to call the Python client.
#
# Prerequisites:
#   - bastion Python package installed in the environment running Terraform
#   - BASTION_TOKEN environment variable set to a valid admin JWT
#   - Running on the bastion host (or with the admin socket forwarded)
#
# Usage:
#   terraform init
#   BASTION_TOKEN=<token> terraform apply

terraform {
  required_providers {
    bastion = {
      source  = "local/bastion"
      version = "0.1.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.0"
    }
  }
}
