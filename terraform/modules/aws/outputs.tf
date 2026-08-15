output "app_url" {
  description = "Public URL of the deployed app."
  value       = "https://${aws_apprunner_service.app.service_url}"
}

output "base_url_configured" {
  description = "What the app currently believes its own URL is."
  value       = local.base_url
}

output "needs_second_apply" {
  description = "True while BASE_URL does not match the real URL. Set base_url_override to app_url and apply again."
  value       = local.base_url != "https://${aws_apprunner_service.app.service_url}"
}

output "redirect_uri_pattern" {
  description = "Register this at your IdP, replacing {slug} with the connection slug."
  value       = "https://${aws_apprunner_service.app.service_url}/auth/oidc/{slug}/callback"
}

output "scim_base_url" {
  description = "Tenant URL for SCIM provisioning."
  value       = "https://${aws_apprunner_service.app.service_url}/scim/v2"
}

output "database_host" {
  value = aws_db_instance.db.endpoint
}

output "secret_arn" {
  value = aws_secretsmanager_secret.app.arn
}
