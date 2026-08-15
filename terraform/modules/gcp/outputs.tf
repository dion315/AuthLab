output "app_url" {
  description = "Public URL of the deployed app."
  value       = google_cloud_run_v2_service.app.uri
}

output "base_url_configured" {
  description = "What the app currently believes its own URL is."
  value       = local.base_url
}

output "needs_second_apply" {
  description = "True while BASE_URL does not match the real URL. Set base_url_override to app_url and apply again."
  value       = local.base_url != google_cloud_run_v2_service.app.uri
}

output "redirect_uri_pattern" {
  description = "Register this at your IdP, replacing {slug} with the connection slug."
  value       = "${google_cloud_run_v2_service.app.uri}/auth/oidc/{slug}/callback"
}

output "scim_base_url" {
  description = "Tenant URL for SCIM provisioning."
  value       = "${google_cloud_run_v2_service.app.uri}/scim/v2"
}

output "database_connection_name" {
  value = google_sql_database_instance.db.connection_name
}

output "service_account_email" {
  value = google_service_account.app.email
}
