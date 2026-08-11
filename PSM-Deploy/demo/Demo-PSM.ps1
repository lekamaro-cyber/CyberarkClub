<#
.SYNOPSIS
    Standalone DEMO of the PSM deployment engine (no CyberArk media, no admin
    rights, no network). Shows: Test->Set idempotency, plan mode (-WhatIf),
    zone confirmation, secret masking, final summary.

.DESCRIPTION
    Uses the REAL engine (modules/PSM.Common.psm1) but with SIMULATED phases.
    A "world" file (.demo-state/world.json) represents the machine state and
    persists between two runs -> the idempotency is real, not staged:
      - 1st run     : everything CHANGED
      - 2nd run     : everything OK (nothing is redone)
      - with -WhatIf: nothing is modified, you see what WOULD be done
      - with -Reset : you start over from a "pristine" machine

.EXAMPLE
    .\Demo-PSM.ps1 -Reset -NonInteractive            # 1st run: CHANGED everywhere
.EXAMPLE
    .\Demo-PSM.ps1 -NonInteractive                   # 2nd run: OK everywhere (idempotent)
.EXAMPLE
    .\Demo-PSM.ps1 -Reset -NonInteractive -WhatIf    # plan mode: no modification
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $Zone = 'DC1',
    [switch] $Reset,
    [switch] $NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$demoRoot = $PSScriptRoot
$repoRoot = Split-Path $demoRoot -Parent
Import-Module (Join-Path $repoRoot 'modules\PSM.Common.psm1') -Force

$demoState = Join-Path $demoRoot '.demo-state'
$demoLogs  = Join-Path $demoRoot '.demo-logs'
$worldFile = Join-Path $demoState 'world.json'

if ($Reset) {
    Remove-Item $demoState, $demoLogs -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "(demo) State reset: 'pristine' machine." -ForegroundColor DarkGray
}

Initialize-PSMLogging -LogDirectory $demoLogs
Initialize-PSMState   -StateDirectory $demoState

# --- Simulated "world": machine state, persistent between runs ---------------
if (-not (Test-Path $worldFile)) {
    New-Item -ItemType Directory -Path $demoState -Force | Out-Null
    [ordered]@{
        rdsLicense = $false; software = $false; psmInstalled = $false
        registered = $false; hardened = $false
    } | ConvertTo-Json | Set-Content -Path $worldFile
}
function Get-World { Get-Content $worldFile -Raw | ConvertFrom-Json }
function Set-WorldFlag { param([string] $Key) $w = Get-World; $w.$Key = $true; $w | ConvertTo-Json | Set-Content -Path $worldFile }

Write-Host ''
Write-Host '########  DEMO - PSM deployment engine (simulation)  ########' -ForegroundColor White

# --- Secret masking demonstration --------------------------------------------
$fakeSecret = 'S3cr3t-DemoPassword!'
Register-PSMSecret -Secret $fakeSecret
Write-PSMLog -Level INFO -Message "Secret retrieved via PVWA API (demo) = $fakeSecret  <= must show up MASKED in the logs"

# --- Zone confirmation (blunder guard) ---------------------------------------
$zoneCfg = [pscustomobject]@{
    Name = $Zone; PvwaUrl = 'https://pvwa.demo.local'; PvwaAuthMethod = 'LDAP'
}
Confirm-PSMZone -ZoneConfig $zoneCfg -NonInteractive:$NonInteractive

# --- SIMULATED, idempotent phases (same engine as the real script) -----------
Invoke-IdempotentStep -Name 'RDS license (simulated)' `
    -Test { (Get-World).rdsLicense } -Action { Set-WorldFlag 'rdsLicense' } -Confirm:$false

Invoke-IdempotentStep -Name 'Additional software (simulated)' `
    -Test { (Get-World).software } -Action { Start-Sleep -Milliseconds 150; Set-WorldFlag 'software' } -Confirm:$false

Invoke-IdempotentStep -Name 'PSM installation (simulated)' `
    -Test { (Get-World).psmInstalled } -Action { Start-Sleep -Milliseconds 150; Set-WorldFlag 'psmInstalled' } -Confirm:$false

# Reboot point illustration (no real restart in the demo)
if (-not (Get-World).psmInstalled) {
    Write-PSMLog -Level WARN -Message "(demo) Here the real script would schedule the resume and REBOOT."
}

Invoke-IdempotentStep -Name 'Vault registration (simulated)' `
    -Test { (Get-World).registered } -Action { Set-WorldFlag 'registered' } -Confirm:$false

Invoke-IdempotentStep -Name 'Hardening + AppLocker (simulated)' `
    -Test { (Get-World).hardened } -Action { Set-WorldFlag 'hardened' } -Confirm:$false

Write-PSMSummary
Write-Host ''
Write-Host "(demo) Relaunch WITHOUT -Reset to see the idempotency (everything OK)." -ForegroundColor DarkGray
Write-Host "(demo) Logs generated in: $demoLogs" -ForegroundColor DarkGray
