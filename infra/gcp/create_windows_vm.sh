#!/usr/bin/env bash
# Provision the Windows detonation VM (VM2) in the same VPC as the OpenCTI/Splunk host (VM1).
#
# Prereqs:
#   - gcloud CLI authenticated (`gcloud auth login` + `gcloud config set project <id>`)
#   - VM1 already exists and its internal IP is known (set SPLUNK_INDEXER_IP below)
#   - The VPC network and subnet names below match your environment
#
# Usage:
#   export PROJECT_ID=your-gcp-project
#   export VM1_INTERNAL_IP=10.0.0.2        # Splunk indexer reachable on :9997
#   export NETWORK=default                  # or custom VPC name
#   export SUBNET=default                   # or custom subnet name
#   export REGION=europe-west2              # London
#   export ZONE=europe-west2-a
#   ./infra/gcp/create_windows_vm.sh
#
# Cost note: Windows Server 2022 on e2-standard-2 (~2 vCPU / 8 GB) is ~$0.10/hr
# including licence. Stop the VM when not demoing:
#   gcloud compute instances stop cti-win-detonation --zone="$ZONE"

set -euo pipefail

: "${PROJECT_ID:?Set PROJECT_ID}"
: "${VM1_INTERNAL_IP:?Set VM1_INTERNAL_IP (internal IP of the OpenCTI/Splunk host)}"
NETWORK="${NETWORK:-default}"
SUBNET="${SUBNET:-default}"
REGION="${REGION:-europe-west2}"
ZONE="${ZONE:-europe-west2-a}"
VM_NAME="${VM_NAME:-cti-win-detonation}"
MACHINE_TYPE="${MACHINE_TYPE:-e2-standard-2}"
BOOTSTRAP="$(dirname "$0")/../../infra/bootstrap/windows_startup.ps1"

if [[ ! -f "$BOOTSTRAP" ]]; then
  echo "Bootstrap script not found: $BOOTSTRAP" >&2
  exit 1
fi

echo "=== Creating firewall rules (idempotent) ==="

# IAP range for RDP-over-IAP (authenticated, audited, no public IP required)
gcloud compute firewall-rules describe allow-iap-rdp --project="$PROJECT_ID" >/dev/null 2>&1 || \
  gcloud compute firewall-rules create allow-iap-rdp \
    --project="$PROJECT_ID" \
    --network="$NETWORK" \
    --direction=INGRESS \
    --action=ALLOW \
    --rules=tcp:3389 \
    --source-ranges=35.235.240.0/20 \
    --target-tags=iap-rdp \
    --description="RDP via Identity-Aware Proxy only"

# Internal-only rule: detonation VM -> Splunk receiver :9997 on VM1
gcloud compute firewall-rules describe allow-internal-splunk-forward --project="$PROJECT_ID" >/dev/null 2>&1 || \
  gcloud compute firewall-rules create allow-internal-splunk-forward \
    --project="$PROJECT_ID" \
    --network="$NETWORK" \
    --direction=INGRESS \
    --action=ALLOW \
    --rules=tcp:9997 \
    --source-tags=cti-detonation \
    --target-tags=cti-platform \
    --description="Splunk UF -> indexer (internal VPC only)"

echo "=== Creating Windows VM: $VM_NAME ==="

# Render the startup script with the Splunk indexer IP baked in.
# GCP metadata limits make it easier to pass the IP via a separate metadata key
# that the bootstrap script reads, rather than templating into the script body.
gcloud compute instances create "$VM_NAME" \
  --project="$PROJECT_ID" \
  --zone="$ZONE" \
  --machine-type="$MACHINE_TYPE" \
  --network="$NETWORK" \
  --subnet="$SUBNET" \
  --no-address \
  --image-family=windows-2022 \
  --image-project=windows-cloud \
  --boot-disk-size=80GB \
  --boot-disk-type=pd-balanced \
  --tags=iap-rdp,cti-detonation \
  --metadata="enable-oslogin=FALSE,splunk-indexer-ip=${VM1_INTERNAL_IP}" \
  --metadata-from-file="windows-startup-script-ps1=${BOOTSTRAP}" \
  --shielded-secure-boot \
  --shielded-vtpm \
  --shielded-integrity-monitoring

echo
echo "=== VM created. Next steps ==="
echo "1. Wait ~5 min for first-boot bootstrap to complete (Sysmon + UF + Atomic RT install)."
echo "2. Reset Windows password for RDP:"
echo "     gcloud compute reset-windows-password $VM_NAME --zone=$ZONE"
echo "3. Start IAP RDP tunnel:"
echo "     gcloud compute start-iap-tunnel $VM_NAME 3389 --local-host-port=localhost:3389 --zone=$ZONE"
echo "4. Connect with any RDP client to localhost:3389"
echo "5. On VM1, ensure Splunk receiver is enabled on :9997 (see docs/vm2_detonation_lab.md)"
