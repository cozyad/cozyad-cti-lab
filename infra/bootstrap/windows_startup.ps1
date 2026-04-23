<#
.SYNOPSIS
    First-boot bootstrap for the CTI lab Windows detonation VM (VM2).

.DESCRIPTION
    Installs and configures:
      - Sysmon (SwiftOnSecurity baseline config)
      - Splunk Universal Forwarder forwarding to VM1 indexer over internal VPC
      - Invoke-AtomicRedTeam framework + atomics library
      - Windows Defender exclusions for C:\AtomicRedTeam (so Atomics can execute)

    Runs on every boot via the `windows-startup-script-ps1` metadata key. Each
    stage is idempotent — re-running is safe. The Splunk indexer internal IP
    comes from instance metadata key `splunk-indexer-ip`.

.NOTES
    Source: cozyad-cti-lab. Safe for lab use only. Atomic Red Team tests can
    generate noisy or dangerous artefacts - keep this VM isolated and stopped
    when not in use.
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# ---- Logging -----------------------------------------------------------------
$logDir = 'C:\CTILab\logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
Start-Transcript -Path (Join-Path $logDir "bootstrap-$(Get-Date -Format yyyyMMdd-HHmmss).log") -Append

function Write-Step($msg) { Write-Host "=== $msg ===" -ForegroundColor Cyan }

# ---- Read instance metadata --------------------------------------------------
Write-Step 'Reading instance metadata'
$metaHeaders = @{ 'Metadata-Flavor' = 'Google' }
$splunkIndexer = Invoke-RestMethod `
    -Uri 'http://metadata.google.internal/computeMetadata/v1/instance/attributes/splunk-indexer-ip' `
    -Headers $metaHeaders `
    -TimeoutSec 5

if ([string]::IsNullOrWhiteSpace($splunkIndexer)) {
    throw 'splunk-indexer-ip metadata key not set on this instance'
}
Write-Host "Splunk indexer: $splunkIndexer"

# ---- Sysmon (SwiftOnSecurity config) -----------------------------------------
Write-Step 'Installing Sysmon'
$sysmonDir = 'C:\Program Files\Sysmon'
New-Item -ItemType Directory -Force -Path $sysmonDir | Out-Null

if (-not (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue)) {
    $sysmonZip = Join-Path $env:TEMP 'Sysmon.zip'
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $sysmonZip
    Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force

    $configPath = Join-Path $sysmonDir 'sysmonconfig.xml'
    Invoke-WebRequest `
        -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' `
        -OutFile $configPath

    & (Join-Path $sysmonDir 'Sysmon64.exe') -accepteula -i $configPath | Out-Null
    Write-Host 'Sysmon installed.'
} else {
    Write-Host 'Sysmon already installed - skipping.'
}

# ---- Splunk Universal Forwarder ---------------------------------------------
Write-Step 'Installing Splunk Universal Forwarder'
$ufService = Get-Service -Name 'SplunkForwarder' -ErrorAction SilentlyContinue
if (-not $ufService) {
    # Pinned UF MSI URL - update when Splunk publishes a new version.
    # The wildcard download page keeps the URL stable but change if 404s occur.
    $ufMsi = Join-Path $env:TEMP 'splunkforwarder.msi'
    $ufUrl = 'https://download.splunk.com/products/universalforwarder/releases/9.3.2/windows/splunkforwarder-9.3.2-d8bb32809498-x64-release.msi'
    Invoke-WebRequest -Uri $ufUrl -OutFile $ufMsi

    $ufPass = 'ChangeMe!' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $ufPass | Out-File -FilePath 'C:\CTILab\uf_admin.txt' -Encoding ascii

    Start-Process msiexec.exe -Wait -ArgumentList @(
        '/i', $ufMsi,
        'AGREETOLICENSE=Yes',
        "RECEIVING_INDEXER=${splunkIndexer}:9997",
        'LAUNCHSPLUNK=1',
        "SPLUNKUSERNAME=admin",
        "SPLUNKPASSWORD=$ufPass",
        '/quiet'
    )
    Write-Host 'Splunk UF installed. Admin password saved to C:\CTILab\uf_admin.txt'
} else {
    Write-Host 'Splunk UF already installed - skipping MSI.'
}

# Drop inputs.conf / outputs.conf regardless - this is our source of truth.
Write-Step 'Writing UF inputs/outputs'
$ufApp = 'C:\Program Files\SplunkUniversalForwarder\etc\system\local'
New-Item -ItemType Directory -Force -Path $ufApp | Out-Null

@"
[tcpout]
defaultGroup = cti_indexers

[tcpout:cti_indexers]
server = ${splunkIndexer}:9997
useACK = true
"@ | Set-Content -Path (Join-Path $ufApp 'outputs.conf') -Encoding ascii

@"
# Host metadata
[default]
host = cti-win-detonation

# Sysmon - primary source for TTP detection
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
renderXml = true
index = sysmon
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

# Classic Windows Security
[WinEventLog://Security]
disabled = false
renderXml = true
index = wineventlog
sourcetype = WinEventLog:Security

# PowerShell operational + scriptblock
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = false
renderXml = true
index = wineventlog
sourcetype = WinEventLog:Microsoft-Windows-PowerShell/Operational

[WinEventLog://Windows PowerShell]
disabled = false
renderXml = true
index = wineventlog
sourcetype = WinEventLog:PowerShell

# System + Application for baseline
[WinEventLog://System]
disabled = false
renderXml = true
index = wineventlog

[WinEventLog://Application]
disabled = false
renderXml = true
index = wineventlog

# Atomic Red Team execution log (human-readable chain record)
[monitor://C:\AtomicRedTeam\atomic-red-team-master\atomics\Indexes\Indexes-CSV\*.csv]
disabled = true

[monitor://C:\CTILab\logs\atomic-*.log]
disabled = false
index = atomic_red_team
sourcetype = atomic:execution:log
"@ | Set-Content -Path (Join-Path $ufApp 'inputs.conf') -Encoding ascii

Restart-Service -Name SplunkForwarder -ErrorAction SilentlyContinue
Write-Host 'UF configuration applied.'

# ---- PowerShell script-block + module logging -------------------------------
Write-Step 'Enabling PowerShell logging (scriptblock + module)'
$psLogKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
New-Item -Path "$psLogKey\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "$psLogKey\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord
New-Item -Path "$psLogKey\ModuleLogging" -Force | Out-Null
Set-ItemProperty -Path "$psLogKey\ModuleLogging" -Name 'EnableModuleLogging' -Value 1 -Type DWord
New-Item -Path "$psLogKey\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$psLogKey\ModuleLogging\ModuleNames" -Name '*' -Value '*' -Type String

# ---- Defender exclusions for Atomic RT ---------------------------------------
# Without this, most Atomic tests get quarantined before telemetry is generated.
# This VM is a deliberate detonation range - these exclusions are by design.
Write-Step 'Adding Defender exclusions for Atomic Red Team'
Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam' -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath 'C:\Tools'         -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath 'C:\CTILab'        -ErrorAction SilentlyContinue

# ---- Install Invoke-AtomicRedTeam -------------------------------------------
Write-Step 'Installing Invoke-AtomicRedTeam'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not (Test-Path 'C:\AtomicRedTeam\invoke-atomicredteam')) {
    Install-Module -Name powershell-yaml -Force -Scope AllUsers -ErrorAction SilentlyContinue
    $installer = Invoke-WebRequest `
        -Uri 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' `
        -UseBasicParsing
    Invoke-Expression $installer.Content
    Install-AtomicRedTeam -getAtomics -Force
    Write-Host 'Invoke-AtomicRedTeam installed with atomics library.'
} else {
    Write-Host 'Invoke-AtomicRedTeam already installed - skipping.'
}

# Persist a machine-level profile entry so RDP sessions can use Invoke-AtomicTest.
$profileLine = "Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force"
$allUsersProfile = "$PSHOME\Profile.ps1"
if (-not (Test-Path $allUsersProfile) -or -not (Select-String -Path $allUsersProfile -Pattern 'Invoke-AtomicRedTeam' -Quiet)) {
    Add-Content -Path $allUsersProfile -Value $profileLine
}

Write-Step 'Bootstrap complete'
Stop-Transcript
