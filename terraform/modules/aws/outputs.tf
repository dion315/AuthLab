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
    The hostname App Runner assigned, regardless of any custom domain. Also the
    CNAME target to point a custom domain at.
  EOT
  value       = "https://${aws_apprunner_service.app.service_url}"
}

output "url_is_predictable" {
  description = <<-EOT
    Always false on a first apply, and unavoidably so: App Runner mints a random
    subdomain at creation time and there is nothing to compute it from. This is
    the one cloud of the three that genuinely needs two passes — or a custom
    domain, which sidesteps it entirely.
  EOT
  value       = local.base_url == "https://${aws_apprunner_service.app.service_url}" || var.custom_domain != ""
}

output "next_step" {
  description = "What to do now."
  value = (
    var.custom_domain != ""
    ? "Point ${var.custom_domain} at ${aws_apprunner_service.app.service_url} — see the custom_domain_dns output — then sign in at ${local.base_url}/login."
    : local.base_url != "https://${aws_apprunner_service.app.service_url}"
    ? "Set base_url_override = \"https://${aws_apprunner_service.app.service_url}\" in terraform.tfvars and apply again. Until you do, sign-in and provisioning URLs are wrong."
    : "Ready. Sign in at ${local.base_url}/login, then register the values in the idp_configuration output at your identity provider."
  )
}

output "custom_domain_dns" {
  description = <<-EOT
    What to create in DNS when using custom_domain. Terraform does not create
    these: the zone is usually managed elsewhere, and a record pointed at the
    wrong place is worse than no record.

    Associate the domain with the App Runner service to have it issue and
    validate a certificate; App Runner then returns the validation records to
    add alongside the CNAME.
  EOT
  value = var.custom_domain == "" ? null : {
    cname_name   = var.custom_domain
    cname_target = aws_apprunner_service.app.service_url
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

output "database_host" {
  value = aws_db_instance.db.endpoint
}

output "secret_arn" {
  value = aws_secretsmanager_secret.app.arn
}
