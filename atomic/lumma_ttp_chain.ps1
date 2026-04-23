<#
.SYNOPSIS
    Executes an ordered Atomic Red Team chain that mimics the Lumma Stealer
    kill chain. Designed to generate Sysmon + PowerShell telemetry that
    Splunk detections can fire on.

.DESCRIPTION
    Lumma is an infostealer-as-a-service (Russian-speaking operators, disrupted
    by Microsoft DCU / Operation Endgame in May 2025; affiliate activity and
    successor stealers tracked through 2026). This chain reproduces the
    observable *behaviours* of Lumma through Red Canary's Atomic Red Team
    framework - no malware, no real credential theft. Each atomic is benign
    by design but produces process/file/registry events that match the
    canonical Lumma TTP set.

    TTPs mapped (public reporting: Sekoia, Outpost24, Trend Micro, ESET,
    Microsoft DCU takedown filings):

      Execution / Discovery
        T1059.001  PowerShell
        T1082      System Information Discovery
        T1016      System Network Configuration Discovery
        T1057      Process Discovery
        T1083      File and Directory Discovery

      Defense Evasion
        T1027      Obfuscated Files or Information
        T1140      Deobfuscate/Decode Files or Information

      Credential Access (the infostealer core)
        T1555.003  Credentials from Web Browsers
        T1539      Steal Web Session Cookie
        T1552.001  Credentials in Files

      Collection / C2 / Exfiltration
        T1113      Screen Capture
        T1105      Ingress Tool Transfer
        T1071.001  Application Layer Protocol: Web Protocols
        T1567.002  Exfiltration to Cloud Storage

.PARAMETER DryRun
    Print the Invoke-AtomicTest calls without running them.

.PARAMETER Only
    Run only a subset of TTPs (e.g. -Only 'T1555.003','T1539').

.EXAMPLE
    .\lumma_ttp_chain.ps1
    .\lumma_ttp_chain.ps1 -DryRun
    .\lumma_ttp_chain.ps1 -Only 'T1082','T1016','T1057'

.NOTES
    Run on the isolated detonation VM only. Requires Invoke-AtomicRedTeam and
    atomics library installed (handled by infra/bootstrap/windows_startup.ps1).
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [string[]]$Only
)

$ErrorActionPreference = 'Continue'
Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force

$logDir = 'C:\CTILab\logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$runId   = (Get-Date -Format 'yyyyMMdd-HHmmss')
$logFile = Join-Path $logDir "atomic-lumma-$runId.log"

function Write-Chain($msg) {
    $stamp = (Get-Date).ToString('o')
    $line  = "$stamp  $msg"
    Write-Host $line -ForegroundColor Green
    Add-Content -Path $logFile -Value $line
}

# Ordered chain: discovery -> creds -> collection -> exfil.
# Each entry is { TTP, TestNumbers, Notes }. TestNumbers are indexes into the
# atomics YAML; picked for behaviours that match Lumma reporting and that
# run cleanly on a fresh Windows Server 2022 host.
$chain = @(
    @{ TTP='T1059.001'; Tests=@(1);       Note='PowerShell execution primitive' }
    @{ TTP='T1082';     Tests=@(1,2,3);   Note='System info discovery (systeminfo, wmic, reg)' }
    @{ TTP='T1016';     Tests=@(1,2);     Note='Network config discovery (ipconfig, arp)' }
    @{ TTP='T1057';     Tests=@(1,2);     Note='Process discovery (tasklist, Get-Process)' }
    @{ TTP='T1083';     Tests=@(1,2);     Note='File/dir discovery - userprofile enumeration' }
    @{ TTP='T1027';     Tests=@(2);       Note='Base64-encoded PowerShell payload (obfuscation)' }
    @{ TTP='T1555.003'; Tests=@(1,2,3);   Note='Browser credential store access (Chrome/Edge/Firefox)' }
    @{ TTP='T1539';     Tests=@(1);       Note='Web session cookie theft' }
    @{ TTP='T1552.001'; Tests=@(1);       Note='Credentials in files - recursive search' }
    @{ TTP='T1113';     Tests=@(1);       Note='Screen capture via PowerShell' }
    @{ TTP='T1105';     Tests=@(1);       Note='Ingress tool transfer via PowerShell Invoke-WebRequest' }
    @{ TTP='T1071.001'; Tests=@(1);       Note='HTTP(S) beaconing primitive' }
    @{ TTP='T1567.002'; Tests=@(1);       Note='Exfiltration-to-cloud primitive (benign endpoint)' }
)

Write-Chain "Lumma TTP chain starting - run id: $runId"
Write-Chain "Chain length: $($chain.Count) techniques"

foreach ($step in $chain) {
    $ttp = $step.TTP
    if ($Only -and ($Only -notcontains $ttp)) { continue }

    Write-Chain "--- $ttp | $($step.Note) ---"
    foreach ($testNum in $step.Tests) {
        $cmd = "Invoke-AtomicTest $ttp -TestNumbers $testNum"
        Write-Chain "EXEC: $cmd"
        if ($DryRun) { continue }

        try {
            # Pre-reqs first (downloads helper binaries, creates fake files etc.)
            Invoke-AtomicTest $ttp -TestNumbers $testNum -GetPrereqs -ErrorAction Continue | Out-Null
            Invoke-AtomicTest $ttp -TestNumbers $testNum -ErrorAction Continue
        } catch {
            Write-Chain "ERROR: $ttp test $testNum - $($_.Exception.Message)"
        }

        # Breathing room so events land in time-sortable order.
        Start-Sleep -Seconds 3

        # Cleanup - reverse any persistent artefacts the atomic created.
        try {
            Invoke-AtomicTest $ttp -TestNumbers $testNum -Cleanup -ErrorAction SilentlyContinue | Out-Null
        } catch { }
    }
}

Write-Chain "Lumma TTP chain complete. Log: $logFile"
Write-Chain "Check Splunk for: index=sysmon OR index=wineventlog host=cti-win-detonation earliest=-15m"
