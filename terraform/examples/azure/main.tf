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

  # Container Apps composes the app FQDN from the environment's domain, which
  # exists before the app does — so the URL is known up front and one apply is
  # enough. Leave these empty unless you are pointing a domain you own at it.
  base_url_override = var.base_url_override
  custom_domain     = var.custom_domain
}

output "generated_url" { value = module.authlab.generated_url }
output "url_is_predictable" { value = module.authlab.url_is_predictable }
output "custom_domain_dns" { value = module.authlab.custom_domain_dns }

output "app_url" { value = module.authlab.app_url }
output "login_url" { value = module.authlab.login_url }
output "idp_configuration" { value = module.authlab.idp_configuration }
output "next_step" { value = module.authlab.next_step }

