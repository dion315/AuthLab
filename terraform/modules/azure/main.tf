terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

locals {
  name = var.name_prefix

  # Container Apps generates its FQDN from the app name, environment, region,
  # and a random suffix, so it cannot be predicted before creation. The app is
  # deployed with a placeholder BASE_URL and corrected on a second apply — see
  # base_url_override and the note in terraform/README.md.
  base_url = var.base_url_override != "" ? var.base_url_override : (
    var.custom_domain != "" ? "https://${var.custom_domain}" : "http://localhost:8000"
  )
}

resource "random_password" "db" {
  length  = 32
  special = false
}

# --- networking-free Postgres ------------------------------------------------
# Public endpoint with password auth keeps a first deployment to one apply.
# Private networking is the right answer for anything long-lived.

resource "azurerm_postgresql_flexible_server" "db" {
  name                          = "${local.name}-pg"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  version                       = "16"
  administrator_login           = "authlab"
  administrator_password        = random_password.db.result
  storage_mb                    = 32768
  sku_name                      = var.database_sku
  zone                          = "1"
  backup_retention_days         = 7
  public_network_access_enabled = true

  lifecycle {
    # Azure returns the zone it actually placed the server in, which may differ
    # from the request and would otherwise show as perpetual drift.
    ignore_changes = [zone, high_availability]
  }
}

resource "azurerm_postgresql_flexible_server_database" "db" {
  name      = "authlab"
  server_id = azurerm_postgresql_flexible_server.db.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "azure_services" {
  name             = "allow-azure-services"
  server_id        = azurerm_postgresql_flexible_server.db.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# --- identity and secrets ----------------------------------------------------

resource "azurerm_user_assigned_identity" "app" {
  name                = "${local.name}-identity"
  resource_group_name = var.resource_group_name
  location            = var.location
}

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "kv" {
  name                       = substr(replace("${local.name}kv", "-", ""), 0, 24)
  resource_group_name        = var.resource_group_name
  location                   = var.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
  rbac_authorization_enabled = true
}

# The identity running Terraform needs to write the secrets; the app identity
# needs to read them.
resource "azurerm_role_assignment" "kv_admin" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "kv_reader" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_key_vault_secret" "app_secret_key" {
  name         = "app-secret-key"
  value        = var.app_secret_key
  key_vault_id = azurerm_key_vault.kv.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

resource "azurerm_key_vault_secret" "database_url" {
  name = "database-url"
  value = format(
    "postgresql+psycopg://authlab:%s@%s:5432/authlab?sslmode=require",
    urlencode(random_password.db.result),
    azurerm_postgresql_flexible_server.db.fqdn,
  )
  key_vault_id = azurerm_key_vault.kv.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

resource "azurerm_key_vault_secret" "bootstrap_password" {
  name         = "bootstrap-admin-password"
  value        = var.bootstrap_admin_password
  key_vault_id = azurerm_key_vault.kv.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

# --- compute -----------------------------------------------------------------

resource "azurerm_log_analytics_workspace" "law" {
  name                = "${local.name}-law"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_container_app_environment" "env" {
  name                       = "${local.name}-env"
  resource_group_name        = var.resource_group_name
  location                   = var.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id
}

resource "azurerm_container_app" "app" {
  name                         = "${local.name}-app"
  resource_group_name          = var.resource_group_name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  dynamic "registry" {
    for_each = var.registry_server != "" ? [1] : []
    content {
      server   = var.registry_server
      identity = azurerm_user_assigned_identity.app.id
    }
  }

  secret {
    name                = "app-secret-key"
    key_vault_secret_id = azurerm_key_vault_secret.app_secret_key.versionless_id
    identity            = azurerm_user_assigned_identity.app.id
  }
  secret {
    name                = "database-url"
    key_vault_secret_id = azurerm_key_vault_secret.database_url.versionless_id
    identity            = azurerm_user_assigned_identity.app.id
  }
  secret {
    name                = "bootstrap-admin-password"
    key_vault_secret_id = azurerm_key_vault_secret.bootstrap_password.versionless_id
    identity            = azurerm_user_assigned_identity.app.id
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "auto"
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  template {
    # Scale to zero: no compute charge while idle. The trade-off is a cold
    # start on the first request, which is occasionally long enough to be
    # noticeable in the middle of an OAuth redirect. Set min_replicas = 1 if
    # that gets annoying during a testing session.
    min_replicas = var.min_replicas
    max_replicas = 3

    container {
      name   = "authlab"
      image  = var.image
      cpu    = 0.5
      memory = "1Gi"

      # Every variable the app needs is set here. Missing APP_SECRET_KEY or
      # DATABASE_URL means the container will not start.
      env {
        name  = "BASE_URL"
        value = local.base_url
      }
      env {
        name  = "PORT"
        value = "8000"
      }
      env {
        name  = "TRUST_PROXY_HEADERS"
        value = "true"
      }
      env {
        name  = "BOOTSTRAP_ADMIN_EMAIL"
        value = var.bootstrap_admin_email
      }
      env {
        name        = "APP_SECRET_KEY"
        secret_name = "app-secret-key"
      }
      env {
        name        = "DATABASE_URL"
        secret_name = "database-url"
      }
      env {
        name        = "BOOTSTRAP_ADMIN_PASSWORD"
        secret_name = "bootstrap-admin-password"
      }

      liveness_probe {
        transport = "HTTP"
        port      = 8000
        path      = "/healthz"
      }

      readiness_probe {
        transport = "HTTP"
        port      = 8000
        path      = "/readyz"
      }
    }
  }

  depends_on = [
    azurerm_role_assignment.kv_reader,
    azurerm_postgresql_flexible_server_database.db,
  ]
}
