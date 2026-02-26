output "service_url" {
  description = "Cloud Run service URL"
  value       = google_cloud_run_v2_service.backend.uri
}

output "image_repo" {
  description = "Artifact Registry Docker repository base URL"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.reeeductio.repository_id}"
}

output "service_account_email" {
  description = "Backend service account email"
  value       = google_service_account.backend.email
}
