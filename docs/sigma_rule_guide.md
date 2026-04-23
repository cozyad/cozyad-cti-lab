# Sigma Rules — What They Are and How to Write Them

## What is a Sigma Rule?

Sigma is an open standard for writing detection logic that is not tied to any
specific SIEM. A single Sigma rule can be compiled to:

- **SPL** — Splunk
- **KQL** — Microsoft Sentinel / Defender
- **Elastic DSL** — Elastic SIEM
- **Chronicle YARA-L** — Google Chronicle
- **AQL** — IBM QRadar

This is the value: write the detection once in Sigma, deploy it everywhere.
The `examples/sigma/` directory in this repo contains 14 Sigma rules covering
the full LummaC2 TTP chain — the same detections as the BeastIntel SPL rules
but in portable format.

---

## Anatomy of a Sigma Rule

```yaml
title: Short human-readable name                    # required
id: 8f3a1b2c-...                                    # UUID — unique identifier
status: experimental | test | stable                # maturity
description: What this rule detects and why         # required
references:                                         # source intel/advisories
    - https://attack.mitre.org/techniques/T1082
author: Your name
date: 2026-04-23
tags:                                               # ATT&CK mapping
    - attack.t1082
    - attack.discovery
logsource:                                          # what log source to search
    category: process_creation
    product: windows
detection:                                          # the actual logic
    selection:
        Image|endswith:
            - '\systeminfo.exe'
            - '\wmic.exe'
    condition: selection                            # how selections combine
falsepositives:                                     # known benign triggers
    - IT administration scripts
    - Monitoring agents
level: low | medium | high | critical               # severity
```

---

## How to Write One — Step by Step

### Step 1: Start with the SPL you already have

Every Sigma rule in this repo was written by converting a working SPL detection.
Take the SPL, identify what fields it uses, and map them to Sigma.

**SPL:**
```spl
index=sysmon EventCode=1
(Image="*\systeminfo.exe" OR Image="*\wmic.exe")
```

**That becomes Sigma:**
```yaml
logsource:
    category: process_creation   # EventCode=1 maps to this category
    product: windows
detection:
    selection:
        Image|endswith:
            - '\systeminfo.exe'
            - '\wmic.exe'
    condition: selection
```

### Step 2: Know the logsource categories

| Sysmon EventCode | Sigma category | Key fields |
|---|---|---|
| 1 — ProcessCreate | `process_creation` | Image, CommandLine, ParentImage, User |
| 3 — NetworkConnect | `network_connection` | DestinationIp, DestinationPort, Image |
| 7 — ImageLoad | `image_load` | ImageLoaded, Image |
| 11 — FileCreate | `file_event` | TargetFilename, Image |
| 12/13 — Registry | `registry_event` | TargetObject, Details |
| 22 — DNSQuery | `dns_query` | QueryName, Image |

### Step 3: Sigma field modifiers

Sigma field modifiers replace SPL wildcard logic:

| SPL | Sigma equivalent |
|---|---|
| `Image="*\powershell.exe"` | `Image\|endswith: '\powershell.exe'` |
| `Image="C:\Windows\*"` | `Image\|startswith: 'C:\Windows\'` |
| `CommandLine="*IEX*"` | `CommandLine\|contains: 'IEX'` |
| `CommandLine="*IEX*" OR CommandLine="*Invoke*"` | `CommandLine\|contains\|any: ['IEX','Invoke-Expression']` |
| `match(Image,"powershell\.exe")` | `Image\|endswith: '\powershell.exe'` |

### Step 4: Combine selections with condition logic

```yaml
detection:
    selection_image:
        Image|endswith: '\powershell.exe'
    selection_cmdline:
        CommandLine|contains|any:
            - 'IEX'
            - 'Invoke-Expression'
    selection_b64:
        CommandLine|contains|any:
            - 'FromBase64String'
            - 'EncodedCommand'
            - ' -enc '
    condition: selection_image and (selection_cmdline and selection_b64)
```

This is the SPL logic `Image="*\powershell.exe" AND (IEX OR Invoke-Expression) AND (FromBase64String OR EncodedCommand)` expressed in Sigma.

### Step 5: NOT conditions

```yaml
detection:
    selection:
        TargetFilename|contains: 'Cookies'
    filter:
        Image|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
            - '\firefox.exe'
    condition: selection and not filter
```

### Step 6: Set the level correctly

| Level | When to use |
|---|---|
| `low` | Noisy, needs additional context — useful for hunting only |
| `medium` | Suspicious, investigate — high false positive rate in isolation |
| `high` | Strong indicator of malicious activity — low false positive rate |
| `critical` | Near-certain malicious — escalate immediately |

---

## How to Compile Sigma to SPL

Using the `sigma-cli` tool:

```bash
pip install sigma-cli
sigma-cli list                          # list available backends
sigma convert -t splunk sigma/lummac2_T1082_system_discovery.yml
```

Output — compiled SPL ready to paste into Splunk:
```spl
(Image IN ("*\\systeminfo.exe", "*\\wmic.exe", "*\\ipconfig.exe", "*\\hostname.exe", "*\\whoami.exe"))
```

Convert all rules at once:
```bash
sigma convert -t splunk examples/sigma/*.yml
```

Convert to KQL for Sentinel:
```bash
sigma convert -t microsoft365defender examples/sigma/*.yml
```

---

## How Beast Intel Generates Sigma Rules

Beast Intel's `generate_sigma_rule` tool:
1. Pulls the actor's TTP list from OpenCTI (ATT&CK technique IDs + names)
2. For each technique, generates the Sigma YAML structure with correct metadata,
   ATT&CK tags, and logsource category
3. Fills the detection block with a template based on the technique type

The output is a valid Sigma skeleton — correct structure, right fields, ATT&CK
mapping done. The detection logic (specific strings, paths, thresholds) is then
completed based on what was observed in the lab telemetry and validated against
real Sysmon data.

This is the workflow: **Beast Intel generates the framework → lab telemetry
validates and completes the detection logic → sigma-cli compiles to target SIEM.**

---

## Interview Talking Points

- "Sigma is my portable detection format. I write the logic once and I can
  compile it to SPL for Splunk or KQL for Sentinel — the same rule works in
  both environments without rewriting."
- "Every Sigma rule in this repo started as a working SPL detection that I
  validated against real adversary emulation telemetry. The Sigma is the
  portable expression of something I know fires."
- "Beast Intel generates the Sigma structure from the actor's ATT&CK TTP
  profile — I get the metadata, tags, and logsource correct automatically.
  I complete the detection logic from what I observed in the lab."
- "The `level` field matters operationally — a `critical` alert pages someone
  at 3am, a `medium` goes into a daily triage queue. Calibrating that correctly
  is as important as writing the detection."
