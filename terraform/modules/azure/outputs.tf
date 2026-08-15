output "app_url" {
  description = "Public URL of the deployed app."
  value       = "https://${azurerm_container_app.app.ingress[0].fqdn}"
}

output "base_url_configured" {
  description = "What the app currently believes its own URL is."
  value       = local.base_url
}

output "needs_second_apply" {
  description = <<-EOT
    True when the app's configured BASE_URL does not match its real URL.
    While true, OIDC redirect URIs and SAML ACS URLs will be wrong. Fix by
    setting base_url_override to the app_url output and applying again.
  EOT
  value       = local.base_url != "https://${azurerm_container_app.app.ingress[0].fqdn}"
}

output "redirect_uri_pattern" {
  description = "Register this at your IdP, replacing {slug} with the connection slug."
  value       = "https://${azurerm_container_app.app.ingress[0].fqdn}/auth/oidc/{slug}/callback"
}

output "scim_base_url" {
  description = "Tenant URL for SCIM provisioning."
  value       = "https://${azurerm_container_app.app.ingress[0].fqdn}/scim/v2"
}

output "database_host" {
  value = azurerm_postgresql_flexible_server.db.fqdn
}

output "key_vault_name" {
  value = azurerm_key_vault.kv.name
}
