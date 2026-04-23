output "vm_name" {
  description = "Name of the detonation VM."
  value       = google_compute_instance.detonation.name
}

output "vm_internal_ip" {
  description = "Internal VPC IP of the detonation VM. Useful for Splunk indexer ACLs or manual debugging."
  value       = google_compute_instance.detonation.network_interface[0].network_ip
}

output "vm_zone" {
  description = "Zone the VM is deployed in."
  value       = google_compute_instance.detonation.zone
}

output "reset_password_command" {
  description = "gcloud command to reset the Windows administrator password (one-time)."
  value       = "gcloud compute reset-windows-password ${google_compute_instance.detonation.name} --zone=${google_compute_instance.detonation.zone} --project=${var.project_id}"
}

output "iap_rdp_tunnel_command" {
  description = "gcloud command to open an IAP-tunnelled RDP session to localhost:3389."
  value       = "gcloud compute start-iap-tunnel ${google_compute_instance.detonation.name} 3389 --local-host-port=localhost:3389 --zone=${google_compute_instance.detonation.zone} --project=${var.project_id}"
}
