# VM2 — Windows detonation range. Runs Sysmon, Splunk Universal Forwarder, and
# Red Canary's Invoke-AtomicRedTeam. Forwards telemetry over the internal VPC
# to the Splunk indexer on VM1. No public IP. Access via IAP only.
#
# See docs/vm2_detonation_lab.md for architecture + demo runbook.

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

locals {
  detonation_tag = "cti-detonation"
  iap_rdp_tag    = "iap-rdp"
}

# ---- Firewall rules -----------------------------------------------------------

# IAP-only RDP into the detonation VM. No public ingress.
resource "google_compute_firewall" "allow_iap_rdp" {
  name        = "allow-iap-rdp"
  project     = var.project_id
  network     = var.network
  direction   = "INGRESS"
  description = "RDP via Identity-Aware Proxy only"

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  source_ranges = [var.iap_source_range]
  target_tags   = [local.iap_rdp_tag]
}

# Detonation VM -> Splunk receiver on VM1. Source/target tag matching keeps
# the scope tight even if the VPC has other workloads.
resource "google_compute_firewall" "allow_internal_splunk_forward" {
  name        = "allow-internal-splunk-forward"
  project     = var.project_id
  network     = var.network
  direction   = "INGRESS"
  description = "Splunk UF (VM2) -> Splunk indexer (VM1) on internal VPC only"

  allow {
    protocol = "tcp"
    ports    = ["9997"]
  }

  source_tags = [local.detonation_tag]
  target_tags = [var.vm1_platform_tag]
}

# ---- Detonation VM -----------------------------------------------------------

resource "google_compute_instance" "detonation" {
  name         = var.vm_name
  project      = var.project_id
  zone         = var.zone
  machine_type = var.machine_type
  tags         = [local.iap_rdp_tag, local.detonation_tag]
  labels       = var.labels

  boot_disk {
    initialize_params {
      image = "${var.image_project}/${var.image_family}"
      size  = var.boot_disk_size_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    network    = var.network
    subnetwork = var.subnetwork
    # No access_config block = no external IP. IAP is the only ingress.
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin           = "FALSE"
    splunk-indexer-ip        = var.vm1_internal_ip
    windows-startup-script-ps1 = file("${path.module}/${var.bootstrap_script_path}")
  }

  # Atomic Red Team and Sysmon installs mutate the image on first boot.
  # Metadata changes should not trigger a re-create — ignore them after apply.
  lifecycle {
    ignore_changes = [
      metadata["windows-startup-script-ps1"],
    ]
  }
}
