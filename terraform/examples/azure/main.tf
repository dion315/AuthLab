terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
}

module "authlab" {
  source = "../../modules/azure"

  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  name_prefix         = var.name_prefix

  image           = var.image
  registry_server = var.registry_server

  app_secret_key           = var.app_secret_key
  bootstrap_admin_email    = var.bootstrap_admin_email
  bootstrap_admin_password = var.bootstrap_admin_password

  # First apply: leave empty. Then set it to the app_url output and apply
  # again so redirect URIs and the SCIM tenant URL are correct.
  base_url_override = var.base_url_override

  # Ask the browser for a client certificate, so certificate-based sign-in
  # can be tested against this deployment. "ignore" by default.
  client_certificate_mode = var.client_certificate_mode
}

output "app_url" { value = module.authlab.app_url }
output "scim_base_url" { value = module.authlab.scim_base_url }
output "redirect_uri_pattern" { value = module.authlab.redirect_uri_pattern }

output "next_step" {
  value = module.authlab.needs_second_apply ? format(
    "Set base_url_override = \"%s\" in terraform.tfvars and apply again.",
    module.authlab.app_url,
  ) : "BASE_URL is correct. Sign in at ${module.authlab.app_url}/login"
}
