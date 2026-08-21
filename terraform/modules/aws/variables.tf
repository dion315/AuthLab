variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
  default     = "authlab"
}

variable "image" {
  description = "Container image URI, e.g. 123456789012.dkr.ecr.us-east-1.amazonaws.com/authlab:1.0.0"
  type        = string
}

variable "image_is_ecr" {
  description = "True for a private ECR image (adds the ECR access role), false for ECR Public."
  type        = bool
  default     = true
}

variable "app_secret_key" {
  description = <<-EOT
    Signs session cookies and derives the key encrypting stored IdP secrets.
    Generate with: python -c "import secrets; print(secrets.token_urlsafe(48))"
  EOT
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.app_secret_key) >= 32
    error_message = "app_secret_key must be at least 32 characters."
  }
}

variable "bootstrap_admin_email" {
  description = "Email for the first local administrator account."
  type        = string
  default     = "admin@authlab.local"
}

variable "bootstrap_admin_password" {
  description = "Password for the first local administrator. Empty generates one and prints it to the log on first start."
  type        = string
  sensitive   = true
  default     = ""
}

variable "base_url_override" {
  description = <<-EOT
    Public URL of the app.

    App Runner mints a random subdomain at creation and there is nothing to
    compute it from, so this is the one cloud of the three that genuinely needs
    two passes: apply, read the generated_url output, set it here, apply again.
    Until you do, redirect URIs and the SCIM tenant URL will be wrong.

    Setting custom_domain instead avoids the second pass and gives you a URL
    that survives the service being recreated.
  EOT
  type        = string
  default     = ""
}

variable "custom_domain" {
  description = <<-EOT
    A domain you own and will point at the app, e.g. "authlab.contoso.com".

    Recommended for anything beyond a one-off test. It survives the service
    being recreated, it is something you can circulate to colleagues without
    explanation, and it means the redirect URIs you registered at an identity
    provider stay valid.

    This setting only tells the app what to call itself. Terraform does not
    create the DNS records or the certificate binding, because the zone is
    usually managed elsewhere and a record pointed at the wrong place is worse
    than no record. The custom_domain_dns output lists exactly what to create;
    until it resolves, the app will be advertising a URL that does not reach it.
  EOT
  type        = string
  default     = ""
}

variable "database_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "database_allowed_cidrs" {
  description = <<-EOT
    CIDRs allowed to reach Postgres. The default is open because App Runner
    without a VPC connector egresses from public AWS ranges. Narrow this, or
    add a VPC connector, for anything beyond a lab.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "cpu" {
  description = "App Runner vCPU."
  type        = string
  default     = "0.5 vCPU"
}

variable "memory" {
  description = "App Runner memory."
  type        = string
  default     = "1 GB"
}
