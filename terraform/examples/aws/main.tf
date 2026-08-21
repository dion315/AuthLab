terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

module "authlab" {
  source = "../../modules/aws"

  name_prefix  = var.name_prefix
  image        = var.image
  image_is_ecr = var.image_is_ecr

  app_secret_key           = var.app_secret_key
  bootstrap_admin_email    = var.bootstrap_admin_email
  bootstrap_admin_password = var.bootstrap_admin_password

  base_url_override = var.base_url_override
  custom_domain     = var.custom_domain
}

output "app_url" { value = module.authlab.app_url }
output "login_url" { value = module.authlab.login_url }
output "generated_url" { value = module.authlab.generated_url }
output "url_is_predictable" { value = module.authlab.url_is_predictable }
output "custom_domain_dns" { value = module.authlab.custom_domain_dns }
output "idp_configuration" { value = module.authlab.idp_configuration }
output "next_step" { value = module.authlab.next_step }
