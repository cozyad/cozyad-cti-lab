# VM2 — Windows Detonation Range

Isolated Windows Server 2022 VM on GCP that generates adversary-realistic Sysmon
telemetry based on FBI/CISA Advisory AA25-141B (LummaC2). Red Canary's
**Atomic Red Team** drives a TTP chain that is forwarded over the internal VPC
to the Splunk indexer on VM1, where 16 BeastIntel named detection rules fire
and surface hits on a live dashboard.

The design goal is a **self-contained, reproducible detection lab** — no public
IPs, no real malware, automated end-to-end from VM reset to alert firing.

---

## Architecture

```
                 GCP project
  ┌─────────────────────────────────────────────────────────┐
  │ VPC  (default, 10.0.0.0/20)                             │
  │                                                         │
  │  ┌──────────────────────┐      ┌─────────────────────┐  │
  │  │ VM1  cti-platform    │◄─────┤ VM2 cti-win-        │  │
  │  │ tag: cti-platform    │:9997 │     detonation      │  │
  │  │ Ubuntu 22.04         │      │ tag: cti-detonation │  │
  │  │ OpenCTI + Splunk     │      │ Windows Server 2022 │  │
  │  │ Beast Intel MCP      │      │ Sysmon v15 + UF +   │  │
  │  │ 16 BeastIntel rules  │      │ Atomic Red Team     │  │
  │  └──────────────────────┘      └─────────────────────┘  │
  │           ▲                              ▲              │
  └───────────┼──────────────────────────────┼──────────────┘
              │ IAP :8000/:22                │ IAP :3389
              │                              │
        Analyst workstation            Analyst workstation
          (Splunk UI,                    (RDP or automated
           SSH, MCP)                      via GCE startup)
```

**No public IPs on either VM.** All access via Google Identity-Aware Proxy
(source range `35.235.240.0/20`), authenticated through GCP IAM.

> VPC note: VM2 is deployed in `europe-west2-a` and VM1 (Splunk) in
> `us-central1-a`. The UF forwards to VM1's external IP on port 9997 as a
> temporary workaround for cross-region internal routing. The firewall rule
> `allow-internal-splunk-forward` is retained for when both VMs are in the same
> zone.

---

## Provisioning

### Terraform (preferred)

```bash
cd infra/terraform/vm2
cp terraform.tfvars.example terraform.tfvars   # edit with your project + VM1 IP
terraform init
terraform plan
terraform apply
terraform destroy   # tear down when not needed (~£8/month disk when stopped)
```

### gcloud CLI (fallback)

```bash
export PROJECT_ID=your-project
export VM1_INTERNAL_IP=10.0.0.2   # or external IP if cross-region
export REGION=europe-west2
export ZONE=europe-west2-a
./infra/gcp/create_windows_vm.sh
```

The bootstrap script (`infra/bootstrap/windows_startup.ps1`) runs on first boot:
1. Installs Sysmon v15 with SwiftOnSecurity config
2. Installs Splunk Universal Forwarder, configures inputs/outputs
3. Grants `NT SERVICE\SplunkForwarder` access to the Sysmon event log
4. Installs Invoke-AtomicRedTeam + atomics library
5. Creates `C:\CTILab\` working directory

First boot takes 5–7 minutes. The ART atomics script is deployed as a GCE startup
script and runs automatically on every VM reset.

---

## Accessing the VM

Reset the Windows admin password (one-time):
```bash
gcloud compute reset-windows-password cti-win-detonation --zone="$ZONE"
```

Open an IAP RDP tunnel:
```bash
gcloud compute start-iap-tunnel cti-win-detonation 3389 \
  --local-host-port=localhost:3389 --zone="$ZONE"
```

Connect any RDP client to `localhost:3389`.

---

## Sysmon + Splunk UF — Working Configuration

### inputs.conf (on VM2)

`splunk/forwarder/inputs.conf` is the source of truth.
The bootstrap writes identical content to `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`.

Key setting — sourcetype **must** be `WinEventLog:...` not `XmlWinEventLog:...`:
```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
renderXml = true
index = sysmon
sourcetype = WinEventLog:Microsoft-Windows-Sysmon/Operational
```

Using `XmlWinEventLog` as the sourcetype causes the Splunk TA source stanza to
silently not match — all fields (EventCode, Image, CommandLine, TargetFilename)
return empty. See `splunk/ta/local/props.conf` for the fix.

### TA Field Extraction Fix (on VM1 Splunk)

```bash
docker exec --user root xtm-splunk-1 \
  mkdir -p /opt/splunk/etc/apps/Splunk_TA_microsoft_sysmon/local

docker cp splunk/ta/local/props.conf \
  xtm-splunk-1:/opt/splunk/etc/apps/Splunk_TA_microsoft_sysmon/local/props.conf

docker exec xtm-splunk-1 \
  /opt/splunk/bin/splunk restart -auth admin:<password>
```

The `splunk/ta/local/props.conf` stanza:
```ini
[source::WinEventLog:Microsoft-Windows-Sysmon/Operational]
REPORT-sysmon = sysmon-eventid,sysmon-data,...
FIELDALIAS-eventid = EventCode AS EventID
...
```

### SplunkForwarder Event Log Access

The UF service account must have access to the Sysmon event log channel:
```powershell
# Run on VM2 (one-time, done by bootstrap)
$sddl = (wevtutil gl "Microsoft-Windows-Sysmon/Operational" /f:xml | 
    Select-Xml -XPath "//channelAccess").Node.InnerText
# Append SplunkForwarder SID: S-1-5-80-972488765-...
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ca:<updated-sddl>
# Also add to Event Log Readers group:
Add-LocalGroupMember -Group "Event Log Readers" -Member "NT SERVICE\SplunkForwarder"
```

### Splunk Receiver (on VM1)

```bash
docker exec xtm-splunk-1 \
  /opt/splunk/bin/splunk enable listen 9997 -auth admin:<password>
```

---

## Splunk Indexer Side

Apply index definitions from `splunk/indexer/indexes.conf` to the indexer.
The UF writes into: `sysmon`, `wineventlog`, `atomic_red_team`.

Verify Sysmon data is flowing with field extraction working:
```spl
index=sysmon host=cti-win-detonation earliest=-15m
| stats count by EventCode
```

All 5 TTP fields present:
```spl
index=sysmon host=cti-win-detonation EventCode=1 earliest=-15m
| table _time EventCode Image CommandLine User Computer
| head 5
```

---

## Adversary Emulation — ART Atomics

`atomic/art_atomics_final.ps1` simulates LummaC2 post-execution behaviour for
5 MITRE ATT&CK techniques, each calibrated to trigger its BeastIntel detection rule.

### Automated (via GCE startup script)

Fires on every VM reset — no RDP required:
```bash
gcloud compute instances add-metadata cti-win-detonation \
  --metadata-from-file windows-startup-script-ps1=atomic/art_atomics_final.ps1 \
  --zone=europe-west2-a

gcloud compute instances reset cti-win-detonation --zone=europe-west2-a
```

### Manual (RDP session on VM2)

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
& 'C:\OpenCTI\art_atomics_final.ps1'
```

### Techniques Fired

| TTP | MITRE ID | Sysmon EventCode | Simulation Method |
|-----|----------|-----------------|-------------------|
| System Info Discovery | T1082 | 1 | systeminfo.exe, wmic.exe, whoami.exe |
| Base64 ClickFix Dropper | T1140 | 1 | `powershell -Command "IEX(...FromBase64String(...))"` |
| Double Extension Masquerade | T1036 | 1 | Execute `C:\CTILab\invoice_2026.pdf.exe` |
| Browser Cookie Theft | T1539 | 11 | Create `C:\CTILab\Cookies.exe` (non-browser process) |
| rundll32 Execution | T1106 | 1 | `rundll32.exe C:\Users\Public\lummac2_loader.dll,StartW` |

#### T1539 implementation note

Sysmon EventCode=11 (FileCreate) under SwiftOnSecurity config only fires for
executable extensions (.exe, .dll, .ps1). Extensionless files like `Cookies` are
silently filtered. The simulation creates `Cookies.exe` (a copy of cmd.exe) from a
non-browser process — satisfying both the `*Cookies*` TargetFilename match and the
EventCode=11 requirement.

#### T1140 implementation note

The CLICKFIX detection rule requires BOTH a Base64 indicator
(`-EncodedCommand`/`-enc`/`FromBase64String`) AND `IEX`/`Invoke-Expression`
visible in the same CommandLine. Using `-EncodedCommand` alone only satisfies the
Base64 condition. The simulation uses:
```powershell
powershell.exe -Command "IEX([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('...')))"
```
which places both conditions in a single CommandLine captured by Sysmon.

---

## Detection Verification

### Quick SPL check (run inside Splunk container)

```spl
index=sysmon host=cti-win-detonation EventCode=1 earliest=-30m
(Image="*\systeminfo.exe" OR Image="*\powershell.exe" OR Image="*.pdf.exe" OR Image="*\rundll32.exe")
| stats count by EventCode Image
```

### Named rule verification

`verify_named_rules.py` dispatches all 7 core BeastIntel rules against the last 30
minutes of Sysmon data and reports fired/silent:

```bash
python3 verify_named_rules.py   # inside Splunk container
```

Expected: `7/7 BeastIntel rules fired on live sysmon data`

### Alert history

```spl
index=_audit action=alert_fired savedsearch_name="BeastIntel*" earliest=-24h
| eval Rule=replace(savedsearch_name,"BeastIntel - LUMMAC2-","")
| stats count AS Fires, max(_time) AS LastFired by Rule
| eval LastFired=strftime(LastFired,"%Y-%m-%d %H:%M UTC")
| sort - Fires
```

### Dashboard

`http://<splunk-host>:8000/en-US/app/search/beastintel_lummac2_detections`

Panels: pipeline health, TTP hit summary, 5 TTP detail tables, kill chain
timeline, triggered alerts from `_audit`. See `docs/detection_engineering.md`
for full SPL for all 16 rules.

---

## Detonation Range — Lumma TTP Chain (Extended)

For a broader 13-technique LummaC2 emulation (covering C2, exfil, credential
access), run the Invoke-AtomicRedTeam chain:

```powershell
cd C:\CTILab\atomic
.\lumma_ttp_chain.ps1 -DryRun            # preview
.\lumma_ttp_chain.ps1                    # full chain
.\lumma_ttp_chain.ps1 -Only T1555.003,T1539   # creds-only subset
```

| Stage | Technique | Description |
|-------|-----------|-------------|
| Execution | T1059.001 | PowerShell |
| Discovery | T1082 | System info |
| Discovery | T1016 | Network config |
| Discovery | T1057 | Process enumeration |
| Discovery | T1083 | File/dir enumeration |
| Defence Evasion | T1027 | Base64-encoded PowerShell |
| Credential Access | T1555.003 | Browser credentials |
| Credential Access | T1539 | Web session cookies |
| Credential Access | T1552.001 | Credentials in files |
| Collection | T1113 | Screen capture |
| C2 | T1105 | Ingress tool transfer |
| C2 | T1071.001 | HTTP(S) C2 |
| Exfiltration | T1567.002 | Exfil to cloud storage |

---

## Honest Limitations (interview talking points)

- **No initial access simulated** — Lumma is typically delivered via phishing,
  malvertising, or pirated-software lures. The chain starts post-execution because
  initial access is out of scope for a safe detonation range.
- **Atomic Red Team tests are benign** — telemetry-realistic behaviours without
  real credential theft or data exfiltration. Detections fire on behaviour, not
  payload — which is the correct engineering approach.
- **T1539 workaround** — `Cookies.exe` is a renamed cmd.exe. A production
  deployment would use YARA on memory or network-based detection for actual cookie
  theft; Sysmon alone cannot observe the read of an extensionless file.
- **YARA gap** — Beast Intel MCP can generate YARA rules from actor profiles;
  deployment to a scanning engine on VM2 is a planned next sprint.
- **Post-takedown Lumma context** — Operation Endgame (May 2025) disrupted core
  Lumma C2 infrastructure. The TTP set remains valid against 2026 successor
  malware (StealC, Vidar, Rhadamanthys) which share near-identical behaviour.

---

## Cost

Stop the VM when not demoing:
```bash
gcloud compute instances stop cti-win-detonation --zone=europe-west2-a
```

Windows Server 2022 on `e2-standard-2`: ~USD 0.10/hr including licence
(~£55/month always-on). Stopped VMs retain disk at ~£8/month for 80 GB pd-balanced.
