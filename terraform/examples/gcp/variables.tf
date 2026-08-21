variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "name_prefix" {
  type    = string
  default = "authlab"
}

variable "image" {
  description = "Container image, e.g. us-central1-docker.pkg.dev/my-project/authlab/authlab:1.0.0"
  type        = string
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

variable "custom_domain" {
  description = <<-EOT
    A domain you own and will point at the app, e.g. "authlab.contoso.com".
    Optional but recommended for anything more than a one-off test: it survives
    the service being recreated, it is something you can circulate to colleagues
    without explanation, and it stays valid at your identity provider.

    Terraform does not create the DNS records — see the custom_domain_dns
    output for exactly what to create.
  EOT
  type        = string
  default     = ""
}
