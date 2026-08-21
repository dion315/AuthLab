output "app_url" {
  description = "The URL to use, and the one the app believes is its own."
  value       = local.base_url
}

output "login_url" {
  description = "Hand this to anyone who is testing sign-in."
  value       = "${local.base_url}/login"
}

output "generated_url" {
  description = <<-EOT
    The URL Cloud Run actually assigned, regardless of any custom domain. Also
    what a custom domain should resolve to.
  EOT
  value       = google_cloud_run_v2_service.app.uri
}

output "url_is_predictable" {
  description = <<-EOT
    True when the URL computed before deployment matches the one Cloud Run
    assigned — which is what makes a single apply sufficient. False means this
    project still issues legacy hash-based URLs: set base_url_override to the
    generated_url output and apply again.
  EOT
  value       = local.generated_url == google_cloud_run_v2_service.app.uri
}

output "next_step" {
  description = "What to do now."
  value = (
    local.generated_url != google_cloud_run_v2_service.app.uri
    ? "This project issues legacy Cloud Run URLs. Set base_url_override = \"${google_cloud_run_v2_service.app.uri}\" and apply again."
    : var.custom_domain != ""
    ? "Point ${var.custom_domain} at Cloud Run — see the custom_domain_dns output — then sign in at ${local.base_url}/login."
    : "Ready. Sign in at ${local.base_url}/login, then register the values in the idp_configuration output at your identity provider."
  )
}

output "custom_domain_dns" {
  description = <<-EOT
    What to create in DNS when using custom_domain. Terraform does not create
    these: the zone is usually managed elsewhere, and a record pointed at the
    wrong place is worse than no record.

    Cloud Run domain mappings additionally require the domain to be verified
    against the project, and are not available in every region — Google's
    guidance is to front the service with a load balancer where they are not.
  EOT
  value = var.custom_domain == "" ? null : {
    domain            = var.custom_domain
    maps_to           = google_cloud_run_v2_service.app.uri
    verification_note = "Verify domain ownership for project ${var.project_id} before creating the mapping."
  }
}

output "idp_configuration" {
  description = <<-EOT
    Every value an identity provider needs. Replace {slug} with the connection
    slug you choose in the admin console.
  EOT
  value = {
    oidc_redirect_uri = "${local.base_url}/auth/oidc/{slug}/callback"
    saml_acs_url      = "${local.base_url}/auth/saml/{slug}/acs"
    saml_sls_url      = "${local.base_url}/auth/saml/{slug}/sls"
    saml_metadata_url = "${local.base_url}/auth/saml/{slug}/metadata"
    scim_tenant_url   = "${local.base_url}/scim/v2"
  }
}

output "database_connection_name" {
  value = google_sql_database_instance.db.connection_name
}

output "service_account_email" {
  value = google_service_account.app.email
}
