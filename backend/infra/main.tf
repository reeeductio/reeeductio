# ------------------------------------------------------------------
# Artifact Registry
# ------------------------------------------------------------------

resource "google_artifact_registry_repository" "reeeductio" {
  project       = var.project_id
  location      = var.region
  repository_id = "reeeductio"
  format        = "DOCKER"
  mode          = "STANDARD_REPOSITORY"
}

# ------------------------------------------------------------------
# Service Account & IAM
# ------------------------------------------------------------------

resource "google_service_account" "backend" {
  project      = var.project_id
  account_id   = "reeeductio-backend"
  display_name = "reeeductio backend"
}

# Firestore read/write
resource "google_project_iam_member" "backend_firestore" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.backend.email}"
}

# Secret Manager read (needed to mount secrets at runtime)
resource "google_project_iam_member" "backend_secrets" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.backend.email}"
}

# ------------------------------------------------------------------
# Secret Manager (structure only — populate values out-of-band)
# ------------------------------------------------------------------

resource "google_secret_manager_secret" "config" {
  project   = var.project_id
  secret_id = "reeeductio-config"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "jwt_secret" {
  project   = var.project_id
  secret_id = "reeeductio-jwt-secret"

  replication {
    auto {}
  }
}

# ------------------------------------------------------------------
# Cloud Run
# ------------------------------------------------------------------

resource "google_cloud_run_v2_service" "backend" {
  project  = var.project_id
  location = var.region
  name     = "reeeductio-backend"
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.backend.email
    timeout         = "300s"

    scaling {
      max_instance_count = 3
    }

    max_instance_request_concurrency = 80

    volumes {
      name = "config"

      secret {
        secret = google_secret_manager_secret.config.secret_id

        items {
          version = "latest"
          path    = "config.yaml"
        }
      }
    }

    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/reeeductio/backend:latest"

      ports {
        name           = "http1"
        container_port = 8000
      }

      env {
        name  = "CONFIG_FILE"
        value = "/config/config.yaml"
      }

      volume_mounts {
        name       = "config"
        mount_path = "/config"
      }

      resources {
        limits = {
          cpu    = "1000m"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      startup_probe {
        initial_delay_seconds = 0
        period_seconds        = 240
        failure_threshold     = 1
        timeout_seconds       = 240

        tcp_socket {
          port = 8000
        }
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }
}

# Allow unauthenticated access (public API)
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.backend.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
