variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
  default     = "authlab"
}

variable "region" {
  description = "GCP region."
  type        = string
  default     = "us-central1"
}

variable "image" {
  description = "Container image, e.g. us-central1-docker.pkg.dev/my-project/authlab/authlab:1.0.0"
  type        = string
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
    Public URL of the app. Cloud Run generates its URL at creation, so leave
    this empty on the first apply, then set it to the app_url output and apply
    again. Setting custom_domain instead avoids the second pass.
  EOT
  type        = string
  default     = ""
}

variable "custom_domain" {
  description = "Custom domain, if you have one."
  type        = string
  default     = ""
}

variable "database_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-f1-micro"
}

variable "min_instances" {
  description = "0 scales to zero and costs nothing when idle, at the price of a cold start."
  type        = number
  default     = 0
}

variable "cpu" {
  description = "Cloud Run CPU limit."
  type        = string
  default     = "1"
}

variable "memory" {
  description = "Cloud Run memory limit."
  type        = string
  default     = "512Mi"
}
