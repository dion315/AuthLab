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
    The hostname Azure assigned, regardless of any custom domain. Also the
    CNAME target to point a custom domain at.
  EOT
  value       = "https://${azurerm_container_app.app.ingress[0].fqdn}"
}

output "url_is_predictable" {
  description = <<-EOT
    True when the URL computed before deployment matches the one Azure actually
    assigned — which is what makes a single apply sufficient. If this is ever
    false, Azure has changed how it composes FQDNs: set base_url_override to
    the generated_url output and apply again.
  EOT
  value       = local.generated_fqdn == azurerm_container_app.app.ingress[0].fqdn
}

output "next_step" {
  description = "What to do now."
  value = (
    local.generated_fqdn != azurerm_container_app.app.ingress[0].fqdn
    ? "The predicted URL did not match. Set base_url_override = \"https://${azurerm_container_app.app.ingress[0].fqdn}\" and apply again."
    : var.custom_domain != ""
    ? "Point ${var.custom_domain} at ${azurerm_container_app.app.ingress[0].fqdn} — see the custom_domain_dns output — then sign in at ${local.base_url}/login."
    : "Ready. Sign in at ${local.base_url}/login, then register the values in the idp_configuration output at your identity provider."
  )
}

output "custom_domain_dns" {
  description = <<-EOT
    The DNS records to create when using custom_domain. Terraform does not
    create these: the zone is usually managed elsewhere, and a record pointed
    at the wrong place is worse than no record.

    After they resolve, add the domain to the Container App and let Azure issue
    a managed certificate.
  EOT
  value = var.custom_domain == "" ? null : {
    cname_name   = var.custom_domain
    cname_target = azurerm_container_app.app.ingress[0].fqdn
    txt_name     = "asuid.${split(".", var.custom_domain)[0]}"
    txt_value    = azurerm_container_app.app.custom_domain_verification_id
  }
}

output "idp_configuration" {
  description = <<-EOT
    Every value an identity provider needs. Replace {slug} with the connection
    slug you choose in the admin console.

    oidc_post_logout_uri must be registered too, or federated sign-out is
    refused by the provider. oidc_initiate_login is only needed for IdP-initiated
    sign-in (Okta's "Initiate login URI"), and oidc_jwks_url only when accepting
    encrypted ID tokens — register it as the client's jwks_uri.
  EOT
  value = {
    oidc_redirect_uri    = "${local.base_url}/auth/oidc/{slug}/callback"
    oidc_post_logout_uri = "${local.base_url}/"
    oidc_initiate_login  = "${local.base_url}/auth/oidc/{slug}/login"
    oidc_jwks_url        = "${local.base_url}/auth/oidc/{slug}/jwks.json"
    saml_acs_url         = "${local.base_url}/auth/saml/{slug}/acs"
    saml_sls_url         = "${local.base_url}/auth/saml/{slug}/sls"
    saml_metadata_url    = "${local.base_url}/auth/saml/{slug}/metadata"
    scim_tenant_url      = "${local.base_url}/scim/v2"
  }
}

output "database_host" {
  value = azurerm_postgresql_flexible_server.db.fqdn
}

output "key_vault_name" {
  value = azurerm_key_vault.kv.name
}
