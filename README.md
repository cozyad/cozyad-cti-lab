# 🧠 cozyad-cti-lab

### Production-Grade Cyber Threat Intelligence Platform | Google Cloud | OpenCTI | Beast Intel | MITRE ATT&CK | AI-Native Analysis | Live Detection Pipeline

A personal threat intelligence lab built to bridge 20 years of operational intelligence experience with modern commercial CTI engineering — from concept to production on Google Cloud Platform, with a live detection pipeline firing on real adversary-emulation telemetry.

---

## Overview

This project documents the design, deployment, and ongoing development of a production-grade Cyber Threat Intelligence platform running on Google Cloud Platform. The platform centralises threat intelligence into a structured STIX 2.1 knowledge graph, correlating threat actors, malware, TTPs, CVEs and indicators across multiple live feeds — enriched with MITRE ATT&CK mappings and surfaced through **Beast Intel**, a custom MCP server that enables AI-native analyst workflows via Claude Code.

A second GCP VM runs an isolated Windows detonation range where adversary emulation telemetry flows through Sysmon → Splunk Universal Forwarder → Splunk indexer → **16 BeastIntel named detection rules** based on FBI/CISA Advisory AA25-141B (LummaC2). All 5 core TTPs fire live. Alerts surface to a purpose-built Splunk dashboard and write to `index=_audit` for investigation.

---

## Architecture

```
Claude Code (Windows workstation)
       │
       │ SSH via IAP Tunnel (127.0.0.1:2222)
       │
GCP Compute Engine — VM1 cti-platform (Ubuntu 22.04)
       │
       ├── Beast Intel MCP Server ←── 14 CTI tools over OpenCTI GraphQL
       │
       ├── Docker Compose Stack
       │     ├── OpenCTI 6.x (knowledge graph, STIX 2.1)
       │     ├── Elasticsearch (storage + search)
       │     ├── RabbitMQ (connector queue)
       │     ├── Redis (cache)
       │     ├── MinIO (object store)
       │     └── Splunk (indexer :9997 | UI :8000)
       │           └── 16 BeastIntel detection rules (AA25-141B)
       │                 └── Dashboard: beastintel_lummac2_detections
       │
       │   TCP :9997 (UF → indexer)
       ▼
GCP Compute Engine — VM2 cti-win-detonation (Windows Server 2022)
       │
       ├── Sysmon v15 (SwiftOnSecurity config)
       │     EventCode=1 (ProcessCreate), 3 (NetworkConn),
       │     11 (FileCreate), 12/13 (Registry), 22 (DNS)
       │
       ├── Splunk Universal Forwarder
       │     index=sysmon | index=wineventlog | index=atomic_red_team
       │
       └── ART Atomics (art_atomics_final.ps1)
             Automated via GCE startup-script metadata
             Fires all 5 TTPs on every VM reset
```

No public IP on either VM. All access via GCP Identity-Aware Proxy —
authenticated, audited, zero exposed attack surface.

---

## Detection Pipeline — AA25-141B LummaC2

Live end-to-end pipeline: adversary emulation → telemetry → detection → alerting.

### 5 MITRE ATT&CK Techniques, All Firing

| TTP | MITRE ID | Detection Rule | Signal |
|-----|----------|---------------|--------|
| System Info Discovery | T1082 | T1082-SYSINFO | systeminfo / wmic / whoami (EventCode=1) |
| Base64 ClickFix Dropper | T1140 | T1140-POWERSHELL-BASE64-CLICKFIX | `powershell IEX + FromBase64String` (EventCode=1) |
| Double Extension Masquerade | T1036 | T1036-DOUBLE-EXTENSION | `invoice_2026.pdf.exe` execution (EventCode=1) |
| Browser Cookie Theft | T1539 | T1539-BROWSER-DATA-FILE-ACCESS | Non-browser write to `*Cookies*` (EventCode=11) |
| rundll32 Execution | T1106 | T1106-RUNDLL32-OPCODE3 | `rundll32.exe C:\Users\Public\*.dll` (EventCode=1) |

Plus: Kill Chain correlation rule, Sysmon health rule, and 9 supporting rules for network, DNS, registry, and image-load events. **16 rules total.**

### Pipeline Architecture Detail

```
VM2 — Sysmon EventCode=1,3,11,12,13,22
  ↓  renderXml=true, sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational
VM1 — Splunk UF TCP :9997
  ↓  Splunk_TA_microsoft_sysmon (with source stanza override fix)
     index=sysmon host=cti-win-detonation
  ↓  16 BeastIntel saved search rules
     alert_type=number of events >0, actions=log_event, alert.track=1
  ↓  index=_audit (alert_fired) + Dashboard panels
```

### Key Engineering Detail: Field Extraction Fix

The Splunk TA for Microsoft Sysmon ships with a source stanza mismatch that silently
drops all field extraction — EventCode, Image, CommandLine, TargetFilename all return
empty. Root cause: TA default uses `[source::XmlWinEventLog:...]` but UF sets
`source = WinEventLog:...`. Fixed with a local props.conf override in
`splunk/ta/local/props.conf`. See `docs/detection_engineering.md` for full detail.

### Dashboard

```
http://<splunk-host>:8000/en-US/app/search/beastintel_lummac2_detections
```

10 panels: pipeline health chart, TTP hit summary, 5 TTP detail tables,
kill chain timeline, triggered alerts table, alert counts by rule.

---

## Beast Intel — MCP Server

The core innovation of this build is **Beast Intel** — a custom Model Context
Protocol (MCP) server that wraps OpenCTI's GraphQL API and exposes structured
threat intelligence tools directly to Claude Code. AI-native analyst workflows:
natural language queries → live platform calls → finished intelligence.

Beast Intel exposes 14 tools across four capability categories:

**Discovery**
- `list_all_intrusion_sets` — enumerate all tracked threat actors
- `get_sector_actors` — actors known to target a specific industry

**Actor Profiling**
- `get_intrusion_set_profile` — motivation, sophistication, aliases
- `get_intrusion_set_ttps` — MITRE ATT&CK technique mapping
- `get_intrusion_set_infrastructure` — malware and infrastructure associations
- `get_related_actors` — cluster overlap and relationship analysis
- `get_campaigns` — historical operations and objectives
- `get_indicators` — IOCs for detection and hunting
- `get_malware_profile` — capabilities, C2 method, evasion techniques

**Detection Engineering**
- `generate_yara_rule` — YARA rule generation from actor tooling
- `generate_yara_rules_for_actor` — bulk YARA for actor's full toolkit
- `generate_sigma_rule` — Sigma detection rule generation
- `generate_sigma_rules_for_actor` — bulk Sigma for actor TTPs

**Adversary Emulation**
- `export_to_caldera` — convert threat intel to CALDERA adversary profile

---

## Threat Intelligence Feeds

### Live Connectors

**MITRE ATT&CK** — Full Enterprise matrix, analytical backbone for all TTP mapping

**Ransomware.live** — Real-time ransomware victim claims with actor attribution and HudsonRock infostealer corroboration

**CISA KEV** — CISA's authoritative catalogue of CVEs actively exploited in the wild

**ThreatFox (Abuse.ch)** — Community IOC feed: IPs, domains, URLs, hashes, C2 tracking

**URLhaus (Abuse.ch)** — Malware distribution URLs and hosting infrastructure

**MalwareBazaar (Abuse.ch)** — Malware sample metadata, file hashes, family classifications

**VirusTotal (Enrichment)** — Indicator enrichment with multi-vendor detection context

### Data Flow

```
External Feeds → Connectors → RabbitMQ → OpenCTI Workers → Elasticsearch
                                                                 │
                                                        Knowledge Graph
                                                        (STIX 2.1 objects)
                                                                 │
                                             ATT&CK Enrichment & Correlation
                                                                 │
                                                    Beast Intel MCP Layer
                                                                 │
                                                   Claude Code AI Analysis
```

---

## AI-Native Analyst Workflows

**TTP Chain Analysis** — Query an actor's full technique set, map to MITRE ATT&CK IDs, generate a structured kill chain narrative in a single natural language request against the live platform.

**Victim Intelligence** — Query the OpenCTI GraphQL API directly via IAP tunnel for free-text searches across the full object graph, surfacing victim organisation intelligence not exposed through structured tools.

**Cross-Source Corroboration** — Combine Beast Intel actor data with open-source reporting, Ransomware.live entries, and HudsonRock infostealer attribution to produce confidence-assessed intelligence products.

**Detection Generation** — Generate YARA and Sigma rules directly from actor TTP profiles and malware characteristics, ready for deployment into detection engineering pipelines.

**Adversary Emulation** — Export a full actor TTP chain as a CALDERA adversary profile (e.g. 44 techniques for LAPSUS$ mapped to ATT&CK IDs, structured for red team emulation).

---

## Repository Structure

```
cozyad-cti-lab/
├── README.md
├── beast_intel_mcp.py          # MCP server (14 CTI tools)
├── docker-compose.yml          # VM1 full stack
├── requirements.txt
├── atomic/
│   ├── lumma_ttp_chain.ps1     # 13-technique Invoke-AtomicRedTeam chain
│   └── art_atomics_final.ps1   # 5-TTP ART simulation (AA25-141B, all firing)
├── docs/
│   ├── vm2_detonation_lab.md   # Provisioning + Sysmon/UF setup + runbook
│   └── detection_engineering.md # 16 BeastIntel rules, SPL, MITRE mapping
├── examples/
│   ├── caldera_lapsus_adversary.json
│   ├── lapsus_ttp_chain.json
│   ├── sigma_T1621_mfa_fatigue.yaml
│   └── yara_wannacry.yar
├── infra/
│   ├── bootstrap/windows_startup.ps1   # GCE first-boot: Sysmon + UF + ART
│   ├── gcp/create_windows_vm.sh        # gcloud provisioning script
│   └── terraform/vm2/                  # Terraform (preferred path)
├── splunk/
│   ├── forwarder/
│   │   ├── inputs.conf         # UF source config (source of truth)
│   │   └── outputs.conf        # UF → indexer target
│   ├── indexer/indexes.conf    # Index definitions for VM1
│   └── ta/local/props.conf     # TA source stanza fix (critical — see docs)
└── tools/
    ├── cti_report_ingestor.py  # Ingest external CTI reports into OpenCTI
    └── lumma_reports.txt       # Source URLs for AA25-141B research
```

---

## Security & Infrastructure

- **Identity-Aware Proxy (IAP):** All VM access via authenticated IAP tunnel — no public IP, no SSH exposure to the internet
- **Service Account:** Least-privilege GCP service account for platform authentication
- **No stored credentials in code:** All secrets via `.env` files excluded from version control; scripts use `os.environ`
- **Firewall rules:** Deny-by-default, explicit permit only for required inter-service communication
- **Shielded VM:** vTPM and integrity monitoring enabled on both VMs
- **Google Cloud Monitoring:** VM and container health monitoring (Security Command Center integration planned)

---

## Detonation Range Quick Start

```bash
# Provision VM2
cd infra/terraform/vm2 && terraform apply

# Deploy ART atomics as startup script (auto-fires on every reset)
gcloud compute instances add-metadata cti-win-detonation \
  --metadata-from-file windows-startup-script-ps1=atomic/art_atomics_final.ps1 \
  --zone=europe-west2-a

# Reset VM to trigger atomics
gcloud compute instances reset cti-win-detonation --zone=europe-west2-a

# ~2 minutes later: check Splunk dashboard
# http://<splunk-host>:8000/en-US/app/search/beastintel_lummac2_detections
```

Stop the VM when not demoing: `gcloud compute instances stop cti-win-detonation --zone=europe-west2-a`

---

## Planned

- [ ] YARA rule deployment — wire Beast Intel YARA generation to a scanning engine on VM2, results indexed to Splunk
- [ ] Google Security Command Center — security posture monitoring for the GCP environment
- [ ] Neo4j graph layer — native graph queries for victim → actor → infrastructure traversal
- [ ] Victim search MCP tool — expose free-text victim organisation search through Beast Intel
- [ ] Malware sandbox connector integration
- [ ] AI-assisted triage — automated analyst and executive-level intelligence summaries
- [ ] Honeypot VM — adversary observation feeding IOCs back into OpenCTI

---

## Skills Demonstrated

`Threat Intelligence` `MITRE ATT&CK` `Detection Engineering` `OpenCTI` `Splunk` `Sysmon` `Atomic Red Team` `Google Cloud Platform` `Terraform` `Docker Compose` `Elasticsearch` `STIX 2.1` `MCP Server Development` `GraphQL` `Python` `PowerShell` `AI-Native Workflows` `Claude Code` `Linux Administration` `IAP Tunnelling` `Intelligence Cycle` `TTP Analysis` `IOC Management` `YARA` `Sigma` `Adversary Emulation` `CALDERA` `Source Assessment` `Analytic Tradecraft`

---

⚠️ *This repository documents architecture, methodology and tooling only. No sensitive data, credentials, operational intelligence, or victim-identifying information is included or referenced.*

---

*Actively developed. Last updated April 2026.*
