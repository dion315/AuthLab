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
