<#
YARA scheduled scan for the CTI lab detonation VM.

Scans known high-signal paths on VM2, emits one JSON line per match into
C:\CTILab\logs\yara-*.log. The Splunk Universal Forwarder picks those up via
a monitor:// stanza (index=yara, sourcetype=yara:match).

Run standalone to scan once:
    PS> .\yara_scheduled_scan.ps1

Install as a scheduled task (every 10 minutes):
    PS> .\yara_scheduled_scan.ps1 -Register

Designed to be idempotent. Safe to re-run during bootstrap.
#>

[CmdletBinding()]
param(
    [switch]$Register,
    [string]$RulesDir   = 'C:\CTILab\yara\rules',
    [string]$BinDir     = 'C:\CTILab\yara\bin',
    [string]$LogDir     = 'C:\CTILab\logs',
    [string]$YaraVersion = '4.5.2',
    [string[]]$ScanPaths = @(
        'C:\Users\Public',
        $env:TEMP,
        "$env:USERPROFILE\Downloads",
        "$env:APPDATA",
        "$env:LOCALAPPDATA\Temp"
    ),
    [int]$IntervalMinutes = 10
)

$ErrorActionPreference = 'Stop'

# ---- 1. Ensure directories ---------------------------------------------------
foreach ($d in @($RulesDir, $BinDir, $LogDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# ---- 2. Install yara64.exe if missing ---------------------------------------
$yaraExe = Join-Path $BinDir 'yara64.exe'
if (-not (Test-Path $yaraExe)) {
    Write-Host "Installing YARA $YaraVersion"
    $zipName = "yara-v$YaraVersion-2326-win64.zip"
    $zipUrl  = "https://github.com/VirusTotal/yara/releases/download/v$YaraVersion/$zipName"
    $zipPath = Join-Path $env:TEMP $zipName
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
    Expand-Archive -Path $zipPath -DestinationPath $BinDir -Force
    Remove-Item $zipPath -Force
}

if (-not (Test-Path $yaraExe)) {
    throw "yara64.exe not present at $yaraExe after install"
}

# ---- 3. Optional: register as scheduled task and exit -----------------------
if ($Register) {
    $taskName = 'CTILab-YaraScan'
    $scriptPath = $MyInvocation.MyCommand.Path

    $action = New-ScheduledTaskAction `
        -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger `
        -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
    $principal = New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' -RunLevel Highest

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Force | Out-Null

    Write-Host "Registered scheduled task '$taskName' — scanning every $IntervalMinutes minutes"
    return
}

# ---- 4. Discover rules -------------------------------------------------------
$ruleFiles = Get-ChildItem -Path $RulesDir -Filter '*.yar*' -Recurse -ErrorAction SilentlyContinue
if (-not $ruleFiles) {
    Write-Host "No YARA rules found in $RulesDir — nothing to scan"
    return
}

# ---- 5. Build one combined rule index file (faster than per-file invocation)
$combined = Join-Path $env:TEMP 'yara_combined.yar'
'' | Set-Content $combined
foreach ($rf in $ruleFiles) {
    "include `"$($rf.FullName)`"" | Add-Content $combined
}

# ---- 6. Run the scan and emit JSON lines ------------------------------------
$scanId   = [guid]::NewGuid().ToString('N').Substring(0,8)
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath   = Join-Path $LogDir "yara-$timestamp.log"
$hostname  = $env:COMPUTERNAME
$matchCount = 0

function Write-YaraEvent {
    param([hashtable]$Event)
    $Event['scan_id']     = $scanId
    $Event['host']        = $hostname
    $Event['timestamp']   = (Get-Date).ToString('o')
    $Event | ConvertTo-Json -Compress | Add-Content -Path $logPath
}

# File scans — recursive, per path
foreach ($path in $ScanPaths) {
    if (-not (Test-Path $path)) { continue }
    Write-Host "Scanning $path"

    # -r recursive, -s print strings, -m print meta, -g print tags, -N no warnings
    $output = & $yaraExe -r -s -m -g -N $combined $path 2>&1
    foreach ($line in $output) {
        if ($line -match '^(?<rule>\S+)\s+(?<tags>\[.*?\])?\s*(?<file>[A-Z]:\\.*)$') {
            $matchCount++
            Write-YaraEvent @{
                event_type = 'file_match'
                rule       = $Matches['rule']
                tags       = $Matches['tags']
                target     = $Matches['file']
                scan_path  = $path
            }
        }
    }
}

# Process memory scans — target a curated set of LOLBin / infostealer-typical PIDs
$memoryTargets = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.ProcessName -in @('powershell','pwsh','rundll32','regsvr32','mshta','wscript','cscript','msiexec','certutil')
}
foreach ($proc in $memoryTargets) {
    try {
        $output = & $yaraExe -s -m -g -N $combined $proc.Id 2>&1
        foreach ($line in $output) {
            if ($line -match '^(?<rule>\S+)\s+(?<tags>\[.*?\])?\s*(?<pid>\d+)$') {
                $matchCount++
                Write-YaraEvent @{
                    event_type   = 'memory_match'
                    rule         = $Matches['rule']
                    tags         = $Matches['tags']
                    target_pid   = [int]$Matches['pid']
                    process_name = $proc.ProcessName
                    process_path = $proc.Path
                }
            }
        }
    } catch {
        # Process exited mid-scan, or access denied — expected, don't log noise
    }
}

# ---- 7. Summary event --------------------------------------------------------
Write-YaraEvent @{
    event_type   = 'scan_complete'
    rules_loaded = $ruleFiles.Count
    paths_scanned = $ScanPaths.Count
    processes_scanned = $memoryTargets.Count
    matches_total = $matchCount
}

Write-Host "Scan complete. Matches: $matchCount. Log: $logPath"
