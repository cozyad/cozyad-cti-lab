# Detection Engineering — BeastIntel LummaC2 Rules

Live detection pipeline for FBI/CISA Advisory AA25-141B (LummaC2).  
Sysmon telemetry on `host=cti-win-detonation` → Splunk UF → Splunk indexer → 16 BeastIntel saved search rules.

All rules are deployed as Splunk saved searches under `index=sysmon host=cti-win-detonation` and fire alerts to `index=_audit` when results exceed zero.

---

## Architecture

```
VM2 cti-win-detonation (Windows Server 2022)
  Sysmon v15 (SwiftOnSecurity config)
        │ EventCode=1,3,6,7,11,12,13,22
        ▼
  Splunk Universal Forwarder
  inputs.conf: sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational
        │ TCP :9997
        ▼
VM1 cti-platform — Splunk indexer (Docker)
  Splunk_TA_microsoft_sysmon
  splunk/ta/local/props.conf  ← source stanza fix (WinEventLog not XmlWinEventLog)
  index=sysmon
        │
        ▼
  16 BeastIntel Saved Search Rules
        │ alert_type=number of events, alert_comparator=greater than 0
        │ actions=log_event, alert.track=1
        ▼
  index=_audit (alert_fired events)
        │
        ▼
  Dashboard: beastintel_lummac2_detections
```

### Critical Field Extraction Fix

The Splunk TA for Microsoft Sysmon ships with a default props.conf stanza:
```
[source::XmlWinEventLog:Microsoft-Windows-Sysmon/Operational]
```
But the UF sets `source = WinEventLog:...` — the `XmlWinEventLog` prefix only applies when `renderXml=false`. This mismatch silently prevents all field extraction: `EventCode`, `Image`, `CommandLine`, `TargetFilename` all return empty.

Fix: `splunk/ta/local/props.conf` overrides with the correct source stanza. Deploy to `/opt/splunk/etc/apps/Splunk_TA_microsoft_sysmon/local/props.conf` and restart Splunk.

---

## MITRE ATT&CK Coverage

| BeastIntel Rule | MITRE ID | Tactic | Sysmon Event | Description |
|---|---|---|---|---|
| T1082-SYSINFO | T1082 | Discovery | EventCode=1 | systeminfo / wmic / ipconfig / whoami |
| T1140-POWERSHELL-BASE64-CLICKFIX | T1140 | Defence Evasion | EventCode=1 | PowerShell IEX + Base64 decode (ClickFix dropper) |
| T1036-DOUBLE-EXTENSION | T1036 | Defence Evasion | EventCode=1 | Process image matches *.pdf.exe / *.doc.exe |
| T1539-BROWSER-DATA-FILE-ACCESS | T1539 | Credential Access | EventCode=11 | Non-browser write to Cookies / Login Data path |
| T1106-RUNDLL32-OPCODE3 | T1106 | Execution | EventCode=1 | rundll32 launched from writable user path |
| KILLCHAIN-RECON | T1082+T1140+T1036+T1106+T1539 | Kill Chain | EventCode=1,11 | Multi-stage recon → dropper → exec → data access |
| SYSMON-DATA-HEALTH | — | Pipeline Health | Any | Sysmon event volume monitoring |

Plus 9 additional supporting rules for network connections (EventCode=3), DNS queries (EventCode=22), registry operations (EventCode=12/13), image loads (EventCode=7), driver loads (EventCode=6), and file creation variants.

---

## Rule SPL Reference

### T1082 — System Information Discovery
```spl
index=sysmon host=cti-win-detonation EventCode=1 earliest=-1h
(Image="*\systeminfo.exe" OR Image="*\wmic.exe" OR Image="*\ipconfig.exe"
 OR Image="*\hostname.exe" OR Image="*\whoami.exe")
| table _time Computer User Image CommandLine
| sort - _time
```

### T1140 — PowerShell Base64 ClickFix Dropper
```spl
index=sysmon host=cti-win-detonation EventCode=1 earliest=-1h
Image="*\powershell.exe"
(CommandLine="*IEX*" OR CommandLine="*Invoke-Expression*")
(CommandLine="*FromBase64String*" OR CommandLine="*EncodedCommand*" OR CommandLine="* -enc *")
| table _time Computer User CommandLine
| sort - _time
```
> Note: Rule requires BOTH a Base64 indicator AND IEX/Invoke-Expression in the same CommandLine. The ART simulation uses `-Command "IEX(...FromBase64String(...))"` to satisfy both conditions. `-EncodedCommand` alone does not trigger this rule.

### T1036 — Double Extension Masquerade
```spl
index=sysmon host=cti-win-detonation EventCode=1 earliest=-1h
(Image="*.pdf.exe" OR Image="*.doc.exe" OR Image="*.zip.exe" OR Image="*.xlsx.exe")
| table _time Computer User Image CommandLine ParentImage
| sort - _time
```

### T1539 — Browser Cookie File Access
```spl
index=sysmon host=cti-win-detonation EventCode=11 earliest=-1h
(TargetFilename="*Cookies*" OR TargetFilename="*Login Data*"
 OR TargetFilename="*\CTILab\*Cookies*")
NOT (Image="*\chrome.exe" OR Image="*\msedge.exe" OR Image="*\firefox.exe")
| table _time Computer Image TargetFilename
| sort - _time
```
> Note: Sysmon EventCode=11 (FileCreate) only fires for executable extensions (.exe, .dll, .ps1, etc.) under SwiftOnSecurity config. The ART simulation creates `C:\CTILab\Cookies.exe` (cmd.exe copy) to ensure EventCode=11 fires and satisfy the `*Cookies*` match.

### T1106 — rundll32 Suspicious DLL Execution
```spl
index=sysmon host=cti-win-detonation EventCode=1 earliest=-1h
Image="*\rundll32.exe"
(CommandLine="*\Users\Public\*" OR CommandLine="*\Windows\Temp\*"
 OR CommandLine="*\AppData\*")
| table _time Computer User Image CommandLine ParentImage
| sort - _time
```
> Note: Use `\Users\Public\` path for simulation. SYSTEM's `%TEMP%` resolves to `C:\Windows\TEMP` (uppercase) which does not match the lowercase `Temp` in the rule. `Users\Public` is writable by all users and matches the rule unambiguously.

### Kill Chain — Recon to Data Access
```spl
index=sysmon host=cti-win-detonation earliest=-1h
(EventCode=1 OR EventCode=11)
(Image="*\systeminfo.exe" OR Image="*\whoami.exe" OR Image="*\hostname.exe"
 OR Image="*.pdf.exe" OR Image="*\rundll32.exe"
 OR (Image="*\powershell.exe" AND (CommandLine="*IEX*" OR CommandLine="*EncodedCommand*"))
 OR TargetFilename="*Cookies*")
| eval Stage=case(
    Image="*\systeminfo.exe" OR Image="*\whoami.exe" OR Image="*\hostname.exe","1 - Recon",
    Image="*\powershell.exe","2 - Dropper",
    Image="*.pdf.exe" OR Image="*\rundll32.exe","3 - Execution",
    TargetFilename="*Cookies*","4 - Data Access")
| table _time Stage Image CommandLine TargetFilename
| sort _time
```

---

## Alert Trigger Configuration

All 16 BeastIntel saved searches are configured via Splunk API:
```
alert_type        = number of events
alert_comparator  = greater than
alert_threshold   = 0
alert.track       = 1        ← appears in Alert Manager
actions           = log_event ← writes to index=_audit
alert.suppress    = 0
```

Query fired alerts:
```spl
index=_audit action=alert_fired savedsearch_name="BeastIntel*" earliest=-24h
| eval Rule=replace(savedsearch_name,"BeastIntel - LUMMAC2-","")
| table _time Rule result_count savedsearch_name
| sort - _time
```

---

## Dashboard

URL: `http://<splunk-host>:8000/en-US/app/search/beastintel_lummac2_detections`

Panels:
1. Pipeline Health — Sysmon event volume by EventCode (last 24h)
2. TTP Hit Summary — all rules with hit count and last-seen time (last 1h)
3. T1082 System Info Discovery detail table
4. T1140 PowerShell Base64 ClickFix detail table
5. T1036 Double Extension detail table
6. T1539 Browser Cookie Access detail table
7. T1106 rundll32 detail table
8. Kill Chain — multi-stage timeline view
9. Triggered Alerts (last 24h) — from `index=_audit`
10. Alert counts by rule — pie chart

---

## Adversary Emulation

Run `atomic/art_atomics_final.ps1` to generate all 5 TTP signals:

```powershell
# Manual run (RDP session on VM2)
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\OpenCTI\art_atomics_final.ps1

# Automated (GCE startup-script — fires on every VM reset)
gcloud compute instances add-metadata cti-win-detonation \
  --metadata-from-file windows-startup-script-ps1=atomic/art_atomics_final.ps1
```

Expected outcome: within 2–3 minutes of execution, all 5 detection rules should show hits in the dashboard and alert triggers should appear in `index=_audit`.

---

## Verification

Use `verify_named_rules.py` to dispatch all BeastIntel rules against live data and report fired/silent:

```bash
# From inside the Splunk container
python3 /opt/splunk/verify_named_rules.py
```

Expected output (all rules firing):
```
[FIRED ✓] BeastIntel - LUMMAC2-T1082-SYSINFO
[FIRED ✓] BeastIntel - LUMMAC2-T1140-POWERSHELL-BASE64-CLICKFIX
[FIRED ✓] BeastIntel - LUMMAC2-T1036-DOUBLE-EXTENSION
[FIRED ✓] BeastIntel - LUMMAC2-T1539-BROWSER-DATA-FILE-ACCESS
[FIRED ✓] BeastIntel - LUMMAC2-T1106-RUNDLL32-OPCODE3
[FIRED ✓] BeastIntel - LUMMAC2-KILLCHAIN-RECON
[FIRED ✓] BeastIntel - LUMMAC2-SYSMON-DATA-HEALTH

RESULT: 7/7 BeastIntel rules fired on live sysmon data
```

---

## Pipeline Utilities

| Script | Location | Purpose |
|---|---|---|
| `art_atomics_final.ps1` | `atomic/` | Fire all 5 TTP simulations |
| `create_dashboard.py` | `C:\OpenCTI\` | Create/update Splunk detection dashboard |
| `fix_alert_triggers.py` | `C:\OpenCTI\` | Configure alert trigger conditions on all rules |
| `verify_named_rules.py` | `C:\OpenCTI\` | Dispatch and poll all named rules, report fired/silent |
| `run_detections.py` | `C:\OpenCTI\` | Quick SPL verification of all 5 TTP searches |
