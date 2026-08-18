variable "subscription_id" {
  description = "Azure subscription ID."
  type        = string
}

variable "resource_group_name" {
  type    = string
  default = "rg-authlab"
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "name_prefix" {
  type    = string
  default = "authlab"
}

variable "image" {
  description = "Container image, e.g. myregistry.azurecr.io/authlab:1.0.0"
  type        = string
}

variable "registry_server" {
  description = "Private registry login server. Empty for a public image."
  type        = string
  default     = ""
}

variable "app_secret_key" {
  type      = string
  sensitive = true
}

variable "bootstrap_admin_email" {
  type    = string
  default = "admin@authlab.local"
}

variable "bootstrap_admin_password" {
  type      = string
  sensitive = true
  default   = ""
}

variable "base_url_override" {
  description = "Leave empty on the first apply; set to the app_url output for the second."
  type        = string
  default     = ""
}

variable "client_certificate_mode" {
  description = <<-EOT
    Request a client certificate at the ingress: ignore, accept, or require.
    "accept" is what you want for testing — it asks for a certificate but still
    serves browsers that have none, so local, OIDC, and SAML sign-in keep
    working. "require" refuses every connection without one, including the
    local sign-in you would need to undo it.
  EOT
  type        = string
  default     = "ignore"
}
