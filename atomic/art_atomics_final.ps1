# art_atomics_final.ps1
# BeastIntel — LummaC2 AA25-141B Detection Pipeline
# Adversary emulation script: fires Sysmon telemetry for 5 BeastIntel TTPs
# Deployed as GCE startup-script metadata key (runs on every VM reset)
#
# MITRE TTPs covered:
#   T1082  - System Information Discovery
#   T1140  - Deobfuscate/Decode Files or Information (PowerShell Base64 + IEX)
#   T1036  - Masquerading (double-extension .pdf.exe)
#   T1539  - Steal Web Session Cookie (file-create simulation)
#   T1106  - Native API (rundll32 from writable path)
#
# Detection rules: BeastIntel saved searches in Splunk (index=sysmon host=cti-win-detonation)
# Dashboard: http://<splunk-host>:8000/en-US/app/search/beastintel_lummac2_detections

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Path 'C:\CTILab\logs' -Force | Out-Null
Start-Transcript -Path 'C:\CTILab\logs\art-final.log' -Force

Write-Host '=== ART ATOMICS FIRE ==='
Write-Host "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# ---------------------------------------------------------------------------
# T1082 - System Information Discovery
# BeastIntel rule: BeastIntel - LUMMAC2-T1082-SYSINFO
# Sysmon EventCode=1 — systeminfo.exe / wmic.exe process creation
# ---------------------------------------------------------------------------
Write-Host '--- T1082 systeminfo ---'
& systeminfo 2>&1 | Select-Object -First 3 | Write-Host
& wmic os get Caption,Version /format:csv 2>&1 | Write-Host
& ipconfig.exe /all 2>&1 | Select-Object -First 5 | Write-Host
& hostname.exe 2>&1 | Write-Host
& whoami.exe 2>&1 | Write-Host

# ---------------------------------------------------------------------------
# T1027 / T1140 - Base64 PowerShell + IEX (LummaC2 ClickFix dropper sim)
# BeastIntel rule: BeastIntel - LUMMAC2-T1140-POWERSHELL-BASE64-CLICKFIX
# Sysmon EventCode=1 — powershell.exe with IEX + Base64 in CommandLine
#
# IMPORTANT: Rule requires BOTH Base64 indicator AND IEX/Invoke-Expression
# visible in CommandLine. Use -Command "IEX(...FromBase64String(...))" not
# -EncodedCommand alone (that only carries the Base64 flag, not IEX).
# ---------------------------------------------------------------------------
Write-Host '--- T1027/T1140 Base64 IEX PS ---'
$payload1 = 'Write-Host "LummaC2-ClickFix-Simulation"; whoami; Get-Date'
$b64_1 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload1))
& powershell.exe -Command "IEX([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$b64_1')))" 2>&1 | Write-Host

$payload2 = 'Write-Host "BeastIntel-Detection-Test"'
$b64_2 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload2))
& powershell.exe -enc $b64_2 -Command "Invoke-Expression([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$b64_2')))" 2>&1 | Write-Host

# Broader T1027 variant — -EncodedCommand only (no IEX requirement)
$b64_3 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Write-Host "LummaC2-B64-dropper"'))
& powershell.exe -EncodedCommand $b64_3 2>&1 | Write-Host

# ---------------------------------------------------------------------------
# T1036 - Masquerading: Double Extension
# BeastIntel rule: BeastIntel - LUMMAC2-T1036-DOUBLE-EXTENSION
# Sysmon EventCode=1 — Image path matches *.pdf.exe / *.doc.exe
# ---------------------------------------------------------------------------
Write-Host '--- T1036 Double Extension ---'
$f = 'C:\CTILab\invoice_2026.pdf.exe'
Copy-Item 'C:\Windows\System32\cmd.exe' $f -Force -ErrorAction SilentlyContinue
if (Test-Path $f) {
    & $f /c "echo LummaC2-T1036-DoubleExtension" 2>&1 | Write-Host
    Write-Host 'T1036 fired'
}

# ---------------------------------------------------------------------------
# T1539 - Steal Web Session Cookie (file-create simulation)
# BeastIntel rule: BeastIntel - LUMMAC2-T1539-BROWSER-DATA-FILE-ACCESS
# Sysmon EventCode=11 (FileCreate) — fires on executable extensions only
# under SwiftOnSecurity config (extensions: .exe .dll .ps1 etc.)
# TargetFilename must NOT be written by browser processes to avoid exclusion.
# Solution: .exe extension ensures EventCode=11 fires; path *CTILab*Cookies*
# ---------------------------------------------------------------------------
Write-Host '--- T1539 Cookie Theft ---'
$cFile = 'C:\CTILab\Cookies.exe'
Remove-Item $cFile -Force -ErrorAction SilentlyContinue
Copy-Item 'C:\Windows\System32\cmd.exe' $cFile -Force
Write-Host "T1539 cookie-stealer staged: $cFile (exists=$(Test-Path $cFile))"

# ---------------------------------------------------------------------------
# T1106 - Native API: rundll32 from writable path
# BeastIntel rule: BeastIntel - LUMMAC2-T1106-RUNDLL32-OPCODE3
# Sysmon EventCode=1 — rundll32.exe CommandLine contains \Users\Public\
# Note: Use Users\Public not Windows\TEMP — SYSTEM's %TEMP% is uppercase
# TEMP which doesn't match the lowercase 'Temp' in the detection rule.
# ---------------------------------------------------------------------------
Write-Host '--- T1106 rundll32 ---'
$dll = 'C:\Users\Public\lummac2_loader.dll'
Remove-Item $dll -Force -ErrorAction SilentlyContinue
$null = New-Item -ItemType File -Path $dll -Force
& rundll32.exe $dll,StartW 2>&1 | Write-Host
Write-Host 'T1106 rundll32 fired'

# ---------------------------------------------------------------------------
# T1003 - OS Credential Dumping (additional recon)
# ---------------------------------------------------------------------------
Write-Host '--- T1003 whoami ---'
& whoami /all 2>&1 | Select-Object -First 5 | Write-Host

Write-Host ''
Write-Host '=== ART COMPLETE ==='
Write-Host "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Stop-Transcript
