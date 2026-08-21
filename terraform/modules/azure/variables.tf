variable "name_prefix" {
  description = "Prefix for all resource names. Keep it short — Key Vault names cap at 24 characters."
  type        = string
  default     = "authlab"
}

variable "resource_group_name" {
  description = "Existing resource group to deploy into."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "eastus"
}

variable "image" {
  description = "Container image, e.g. myregistry.azurecr.io/authlab:1.0.0"
  type        = string
}

variable "registry_server" {
  description = "Private registry login server. Leave empty for a public image."
  type        = string
  default     = ""
}

variable "app_secret_key" {
  description = <<-EOT
    Signs session cookies and derives the key encrypting stored IdP secrets.
    Generate with: python -c "import secrets; print(secrets.token_urlsafe(48))"
    Rotating it signs everyone out and makes stored IdP secrets unreadable.
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
  description = "Password for the first local administrator. Leave empty to have one generated and printed to the container log on first start."
  type        = string
  sensitive   = true
  default     = ""
}

variable "base_url_override" {
  description = <<-EOT
    Public URL of the app. Normally leave this empty.

    Container Apps composes an app's FQDN from the app name and the *environment*
    domain, and the environment is created first — so the module computes the URL
    up front and a first deployment is a single apply. Set this only if the
    url_is_predictable output comes back false, or to pin a URL deliberately.
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

variable "database_sku" {
  description = "Postgres Flexible Server SKU."
  type        = string
  default     = "B_Standard_B1ms"
}

variable "min_replicas" {
  description = "0 scales to zero and costs nothing when idle, at the price of a cold start on the next request."
  type        = number
  default     = 0
}
