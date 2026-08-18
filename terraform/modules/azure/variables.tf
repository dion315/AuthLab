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
    Public URL of the app. Container Apps only reveals its FQDN after creation,
    so leave this empty on the first apply, then set it to the app_url output
    and apply again. Setting custom_domain instead avoids the second pass.
  EOT
  type        = string
  default     = ""
}

variable "custom_domain" {
  description = "Custom domain, if you have one. Removes the need for a second apply."
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

variable "client_certificate_mode" {
  description = <<-EOT
    Whether the ingress requests a client certificate from the browser, which is
    what makes certificate-based sign-in testable on this deployment.

      ignore   no certificate is requested (default)
      accept   requested, but a caller without one is still served
      require  no certificate, no connection — this also blocks local sign-in,
               so keep a way in before setting it

    Container Apps forwards the certificate as x-forwarded-client-cert.
  EOT
  type        = string
  default     = "ignore"

  validation {
    condition     = contains(["ignore", "accept", "require"], var.client_certificate_mode)
    error_message = "client_certificate_mode must be ignore, accept, or require."
  }
}
