terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

data "google_project" "this" {
  project_id = var.project_id
}

locals {
  name         = var.name_prefix
  service_name = "${var.name_prefix}-app"

  # Cloud Run now issues deterministic URLs of the form
  #   https://<service>-<project number>-<region>.run.app
  # every component of which is known before the service exists. So the URL can
  # be computed up front rather than read back from the created service, and a
  # first deployment is a single apply.
  #
  # It is also stable: it survives redeploying, pushing a new image, and
  # deleting and recreating the service, because nothing in it is random. That
  # is what makes it safe to register at an identity provider and circulate to
  # other people.
  #
  # Services created before deterministic URLs rolled out keep a legacy
  # hash-based hostname instead. The url_matches_service output below compares
  # this against what the service actually reports, so a mismatch is visible
  # rather than mysterious — set base_url_override to the app_url output if you
  # land on a project still issuing the old form.
  generated_url = "https://${local.service_name}-${data.google_project.this.number}.${var.region}.run.app"

  # Precedence: an explicit override wins, then a custom domain, then the URL
  # Cloud Run generates. See the custom_domain variable for what you must do in
  # DNS — this setting only tells the app what to call itself.
  base_url = (
    var.base_url_override != "" ? var.base_url_override :
    var.custom_domain != "" ? "https://${var.custom_domain}" :
    local.generated_url
  )
}

resource "random_password" "db" {
  length  = 32
  special = false
}

resource "random_id" "suffix" {
  byte_length = 3
}

# --- database ----------------------------------------------------------------

resource "google_sql_database_instance" "db" {
  # Instance names cannot be reused for a week after deletion, so a random
  # suffix keeps destroy/apply cycles from failing.
  name             = "${local.name}-pg-${random_id.suffix.hex}"
  region           = var.region
  database_version = "POSTGRES_16"

  settings {
    tier              = var.database_tier
    availability_type = "ZONAL"
    disk_size         = 10
    disk_autoresize   = true

    ip_configuration {
      # Cloud Run reaches Cloud SQL through the built-in connector rather than
      # an IP route, so no authorized networks are needed.
      ipv4_enabled = true
    }

    backup_configuration {
      enabled = true
    }
  }

  deletion_protection = false
}

resource "google_sql_database" "db" {
  name     = "authlab"
  instance = google_sql_database_instance.db.name
}

resource "google_sql_user" "user" {
  name     = "authlab"
  instance = google_sql_database_instance.db.name
  password = random_password.db.result
}

# --- secrets -----------------------------------------------------------------

resource "google_secret_manager_secret" "app_secret_key" {
  secret_id = "${local.name}-app-secret-key"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "app_secret_key" {
  secret      = google_secret_manager_secret.app_secret_key.id
  secret_data = var.app_secret_key
}

resource "google_secret_manager_secret" "database_url" {
  secret_id = "${local.name}-database-url"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "database_url" {
  secret = google_secret_manager_secret.database_url.id
  # The Cloud Run connector exposes a Unix socket rather than a TCP endpoint.
  secret_data = format(
    "postgresql+psycopg://authlab:%s@/authlab?host=/cloudsql/%s",
    urlencode(random_password.db.result),
    google_sql_database_instance.db.connection_name,
  )
}

resource "google_secret_manager_secret" "bootstrap_password" {
  secret_id = "${local.name}-bootstrap-password"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "bootstrap_password" {
  secret      = google_secret_manager_secret.bootstrap_password.id
  secret_data = var.bootstrap_admin_password != "" ? var.bootstrap_admin_password : "unset"
}

# --- identity ----------------------------------------------------------------

resource "google_service_account" "app" {
  account_id   = "${local.name}-sa"
  display_name = "AuthLab Cloud Run service account"
}

resource "google_project_iam_member" "cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.app.email}"
}

resource "google_secret_manager_secret_iam_member" "app_secret_key" {
  secret_id = google_secret_manager_secret.app_secret_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.app.email}"
}

resource "google_secret_manager_secret_iam_member" "database_url" {
  secret_id = google_secret_manager_secret.database_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.app.email}"
}

resource "google_secret_manager_secret_iam_member" "bootstrap_password" {
  secret_id = google_secret_manager_secret.bootstrap_password.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.app.email}"
}

# --- compute -----------------------------------------------------------------

resource "google_cloud_run_v2_service" "app" {
  # Must match local.service_name, which local.generated_url is built from.
  name                = local.service_name
  location            = var.region
  deletion_protection = false
  ingress             = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.app.email

    scaling {
      # Scale to zero: no charge while idle, at the cost of a cold start.
      min_instance_count = var.min_instances
      max_instance_count = 3
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [google_sql_database_instance.db.connection_name]
      }
    }

    containers {
      image = var.image

      ports {
        container_port = 8000
      }

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

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
        name = "APP_SECRET_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.app_secret_key.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.database_url.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "BOOTSTRAP_ADMIN_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.bootstrap_password.secret_id
            version = "latest"
          }
        }
      }

      startup_probe {
        http_get {
          path = "/healthz"
          port = 8000
        }
        initial_delay_seconds = 5
        period_seconds        = 5
        failure_threshold     = 10
      }

      liveness_probe {
        http_get {
          path = "/healthz"
          port = 8000
        }
        period_seconds = 30
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_version.app_secret_key,
    google_secret_manager_secret_version.database_url,
    google_secret_manager_secret_iam_member.app_secret_key,
    google_secret_manager_secret_iam_member.database_url,
    google_sql_user.user,
  ]
}

# The app does its own authentication, so Cloud Run's IAM gate stays open —
# otherwise the IdP could not reach the callback endpoints.
resource "google_cloud_run_v2_service_iam_member" "public" {
  name     = google_cloud_run_v2_service.app.name
  location = google_cloud_run_v2_service.app.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}
