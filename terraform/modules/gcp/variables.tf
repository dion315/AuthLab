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
    Public URL of the app. Normally leave this empty.

    Cloud Run issues deterministic URLs built from the service name, project
    number, and region, all of which are known before the service exists — so the
    module computes the URL up front and a first deployment is a single apply.
    Set this only if the url_is_predictable output comes back false, which means
    the project still issues legacy hash-based URLs.
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
