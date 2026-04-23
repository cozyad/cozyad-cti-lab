variable "project_id" {
  description = "GCP project ID. Same project as VM1 (OpenCTI/Splunk host)."
  type        = string
}

variable "region" {
  description = "GCP region. London for S&P Global demo context."
  type        = string
  default     = "europe-west2"
}

variable "zone" {
  description = "GCP zone within the region."
  type        = string
  default     = "europe-west2-a"
}

variable "network" {
  description = "VPC network name. Must be the same VPC as VM1 so the UF can reach the Splunk indexer over internal IP."
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "Subnetwork name within the VPC."
  type        = string
  default     = "default"
}

variable "vm1_internal_ip" {
  description = "Internal IP of VM1 (OpenCTI/Splunk host). Passed to the Windows bootstrap as instance metadata; the UF uses it as the receiving indexer."
  type        = string
}

variable "vm1_platform_tag" {
  description = "Network tag applied to VM1 so the internal firewall rule can target it. Add the tag to VM1 with: gcloud compute instances add-tags <vm1> --tags=cti-platform"
  type        = string
  default     = "cti-platform"
}

variable "vm_name" {
  description = "Name of the detonation VM."
  type        = string
  default     = "cti-win-detonation"
}

variable "machine_type" {
  description = "GCE machine type. e2-standard-2 (2 vCPU / 8 GB) is sufficient for Atomic Red Team runs."
  type        = string
  default     = "e2-standard-2"
}

variable "boot_disk_size_gb" {
  description = "Boot disk size in GB. 80 GB leaves room for atomics library, Sysmon archives, and UF spool."
  type        = number
  default     = 80
}

variable "image_family" {
  description = "Windows Server image family."
  type        = string
  default     = "windows-2022"
}

variable "image_project" {
  description = "Project hosting the Windows Server image family."
  type        = string
  default     = "windows-cloud"
}

variable "iap_source_range" {
  description = "Google Identity-Aware Proxy source range. Do not change unless GCP's IAP range is updated."
  type        = string
  default     = "35.235.240.0/20"
}

variable "bootstrap_script_path" {
  description = "Path to the Windows PowerShell bootstrap script, relative to this module."
  type        = string
  default     = "../../bootstrap/windows_startup.ps1"
}

variable "labels" {
  description = "Optional labels applied to the VM. Useful for cost tracking."
  type        = map(string)
  default = {
    purpose = "cti-lab-detonation"
    managed = "terraform"
  }
}
