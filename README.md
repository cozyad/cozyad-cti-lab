# 🧠 cozyad-cti-lab

### Production-Grade Cyber Threat Intelligence Platform | Google Cloud | OpenCTI | Beast Intel | MITRE ATT&CK | AI-Native Analysis

A personal threat intelligence lab built to bridge 20 years of operational intelligence experience with modern commercial CTI engineering — from concept to production on Google Cloud Platform.

---

## Overview

This project documents the design, deployment, and ongoing development of a production-grade Cyber Threat Intelligence platform running on Google Cloud Platform. The platform centralises threat intelligence into a structured STIX 2.1 knowledge graph, correlating threat actors, malware, TTPs, CVEs and indicators across multiple live feeds — enriched with MITRE ATT&CK mappings and surfaced through **Beast Intel**, a custom MCP server that enables AI-native analyst workflows via Claude Code.

---

## Architecture

### Stack

| Component | Technology |
|-----------|------------|
| Cloud Platform | Google Cloud Platform (Compute Engine) |
| VM OS | Ubuntu 22.04 LTS — e2-highmem-4, 4 vCPUs, 32 GB RAM, 100 GB Standard Persistent Disk |
| CTI Platform | OpenCTI 6.x |
| Containerisation | Docker Compose |
| Search & Storage | Elasticsearch |
| Message Queue | RabbitMQ |
| Cache | Redis |
| Object Storage | MinIO |
| Remote Access | IAP Tunnel (Identity-Aware Proxy) — no public IP exposure |
| AI Analyst Interface | Claude Code + Beast Intel MCP Server |
| IaC | Terraform (GCP provisioning) + Docker Compose |

### Beast Intel — MCP Server

The core innovation of this build is **Beast Intel** — a custom Model Context Protocol (MCP) server that wraps OpenCTI's GraphQL API and exposes structured threat intelligence tools directly to Claude Code. This enables AI-native analyst workflows where natural language queries are translated into live platform calls.

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

### Connection Architecture

```
Claude Code (Windows)
       │
       │ SSH via IAP Tunnel (127.0.0.1:2222)
       │
GCP Compute Engine — VM1 (cti-platform)
       │
       ├── mcp_stdin_filter.py
       │         │
       │   beast_intel_mcp.py  ←── Beast Intel MCP Server
       │         │
       │    OpenCTI GraphQL API (localhost:8080/graphql)
       │         │
       ├── Docker Compose Stack
       │     ├── OpenCTI
       │     ├── Elasticsearch
       │     ├── RabbitMQ
       │     ├── Redis
       │     ├── MinIO
       │     └── Splunk (receiver :9997, UI :8000)
       │
       │   internal VPC :9997
       ▼
GCP Compute Engine — VM2 (cti-win-detonation)
       │
       ├── Sysmon (SwiftOnSecurity config)
       ├── Splunk Universal Forwarder
       └── Invoke-AtomicRedTeam + atomics library
             └── Lumma TTP chain (atomic/lumma_ttp_chain.ps1)
```

No public IP on either VM. All access via GCP Identity-Aware Proxy —
authenticated, audited, zero exposed attack surface. See
[`docs/vm2_detonation_lab.md`](docs/vm2_detonation_lab.md) for the Windows
detonation range.

---

## Threat Intelligence Feeds

### Live Connectors

**MITRE ATT&CK**
- Full ATT&CK Enterprise matrix — tactics, techniques, sub-techniques, software, group profiles
- Analytical backbone for TTP mapping across all other feeds

**Ransomware.live**
- Real-time ransomware victim claims with actor attribution
- HudsonRock infostealer corroboration data where available
- Ingested as STIX Report objects linked to Intrusion Set actors

**CISA Known Exploited Vulnerabilities (KEV)**
- CISA's authoritative catalogue of CVEs actively exploited in the wild
- Prioritised vulnerability intelligence — if CISA flags it, threat actors are using it

**ThreatFox (Abuse.ch)**
- Community-contributed IOC feed — IPs, domains, URLs, hashes
- Malware family tagging and C2 infrastructure tracking

**URLhaus (Abuse.ch)**
- Malware distribution URLs and hosting infrastructure
- Rapidly updated feed of active malware delivery campaigns

**MalwareBazaar (Abuse.ch)**
- High-volume malware sample metadata
- File hashes, tags, malware family classifications

**VirusTotal (Enrichment)**
- Enrichment connector for indicators — IPs, domains, URLs, file hashes
- Confidence scoring and multi-vendor detection context

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

The integration of Beast Intel with Claude Code enables analyst workflows that would previously require manual platform navigation. Examples from live use:

**TTP Chain Analysis**
Query an actor's full technique set, map to MITRE ATT&CK IDs, and generate a structured kill chain narrative — in a single natural language request against the live platform.

**Victim Intelligence**
Bypass the MCP tool layer when needed — query the OpenCTI GraphQL API directly via the IAP tunnel to run free-text searches across the full object graph, surfacing victim organisation intelligence not exposed through structured tools.

**Cross-Source Corroboration**
Combine Beast Intel actor data with open-source reporting, Ransomware.live entries, and HudsonRock infostealer attribution to produce confidence-assessed intelligence products — distinguishing single-source actor claims from independently corroborated incidents.

**Detection Generation**
Generate YARA and Sigma rules directly from actor TTP profiles and malware characteristics, ready for deployment into detection engineering pipelines.

**Adversary Emulation**
Export a full actor TTP chain as a CALDERA adversary profile — 44 techniques for LAPSUS$ mapped to ATT&CK IDs and structured for red team emulation.

---

## Security & Infrastructure

Designed with GCP security best practices:

- **Identity-Aware Proxy (IAP):** All VM access via authenticated IAP tunnel — no public IP, no SSH exposure to the internet
- **Service Account:** Least-privilege GCP service account for platform authentication
- **No stored credentials in code:** All secrets managed via `.env` files excluded from version control
- **Firewall rules:** Deny-by-default, explicit permit only for required inter-service communication
- **Google Cloud Monitoring:** VM and container health monitoring (Security Command Center integration planned)

---

## Why I Built This

I have spent 20 years delivering threat intelligence operationally in UK law enforcement. I understood threat actors, the intelligence cycle, and how to produce assessments that drove decisions at national and international level. What I wanted to develop was the engineering side — how commercial CTI teams actually build and operate the platforms that underpin modern threat intelligence functions.

This lab is the answer to that question. Built from scratch, on a real cloud platform, with real data, at production standards — not a lab exercise but a working system I actively use for intelligence production.

The Beast Intel MCP integration represents the next evolution: not just a platform that stores intelligence, but one that can be queried conversationally by an AI analyst — collapsing the distance between raw data and finished intelligence product.

---

## Detonation Range (VM2)

A second GCP VM runs Windows Server 2022 as an isolated detonation range for
adversary-emulation telemetry generation. Red Canary's **Atomic Red Team**
drives a TTP chain that mimics Lumma Stealer behaviours; Sysmon and PowerShell
logs are forwarded to the Splunk indexer on VM1 over the internal VPC.

**Provisioning: Terraform (preferred) or gcloud**

Terraform is the default path — it matches the existing IaC discipline on VM1,
keeps state reproducible, and makes tearing down the detonation range a
one-command operation. The bash script is retained as a zero-dependency
fallback for quick rebuilds or environments without Terraform installed.

```bash
cd infra/terraform/vm2
cp terraform.tfvars.example terraform.tfvars   # edit with your project + VM1 IP
terraform init
terraform plan
terraform apply
terraform destroy                              # tear down when not needed
```

Fallback (bash / gcloud CLI):
```bash
export PROJECT_ID=... VM1_INTERNAL_IP=...
./infra/gcp/create_windows_vm.sh
```

**Files**
- `infra/terraform/vm2/` — Terraform module (preferred)
- `infra/gcp/create_windows_vm.sh` — gcloud script (fallback)
- `infra/bootstrap/windows_startup.ps1` — first-boot Sysmon + UF + Atomic RT
- `atomic/lumma_ttp_chain.ps1` — 13-technique Lumma behaviour chain
- `splunk/forwarder/` — UF inputs/outputs (source of truth)
- `splunk/indexer/indexes.conf` — indexes definitions for VM1
- `docs/vm2_detonation_lab.md` — provisioning + demo runbook

---

## Planned

- [ ] Google Security Command Center — security posture monitoring and threat detection for the GCP environment
- [ ] Neo4j graph layer — native graph queries for relationship traversal (victim → actor, actor → infrastructure)
- [ ] Victim search MCP tool — expose free-text victim organisation search through the Beast Intel interface
- [ ] Malware sandbox connector integration
- [ ] AI-assisted triage workflows — automated analyst and executive-level intelligence summaries
- [ ] Honeypot VM — adversary observation feeding IOCs back into OpenCTI

---

## Skills Demonstrated

`Threat Intelligence` `MITRE ATT&CK` `OpenCTI` `Google Cloud Platform` `Terraform` `Docker Compose` `Elasticsearch` `STIX 2.1` `MCP Server Development` `GraphQL` `Python` `AI-Native Workflows` `Claude Code` `Linux Administration` `IAP Tunnelling` `Intelligence Cycle` `TTP Analysis` `IOC Management` `Detection Engineering` `YARA` `Sigma` `Adversary Emulation` `CALDERA` `Source Assessment` `Analytic Tradecraft`

---


⚠️ *This repository documents architecture, methodology and tooling only. No sensitive data, credentials, operational intelligence, or victim-identifying information is included or referenced.*

---

*Actively developed. Last updated April 2026.*
