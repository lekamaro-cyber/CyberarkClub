#Requires -RunAsAdministrator
<#
.SYNOPSIS
    READ-ONLY configuration check of a PSM server: the check that closes every
    Deploy-PSM.ps1 run, runnable at any time - also on a PSM that PSM-Deploy
    did not deploy.

.DESCRIPTION
    Changes NOTHING on the server: no state, no log file, nothing bound, granted
    or fixed. Checks (details in modules\PSM.Audit.psm1):
      - PSM service running, version = settings.psd1 PsmVersion;
      - last Hardening run recorded by PSM-Deploy;
      - drive permissions (Users / Authenticated Users / Everyone writing at a
        drive root = drives not hardened);
      - "Allow log on through Remote Desktop Services" vs the zone's session
        accounts (and no account of another zone);
      - local Administrators (PSMAdminConnect in, PSMConnect out);
      - AppLocker enforced;
      - zone / VIP consistency, RDP certificate, component account names.
    One line per check, then one framed alert listing the defects.
    Exit code 0 = no defect, 1 = at least one ALERT.

.PARAMETER Zone
    Zone key in config\zones.psd1. Optional on a server deployed by PSM-Deploy
    (re-read from state\progress.json).

.EXAMPLE
    .\tools\Test-PSMConfiguration.ps1 -Zone NPRFR
#>
[CmdletBinding()]
param([string] $Zone)

$sourcesRoot = Split-Path $PSScriptRoot -Parent

# Same "downloaded from the Internet" cleanup as Deploy-PSM.ps1 (sources only,
# not the server): otherwise each module asks to be confirmed.
Get-ChildItem -LiteralPath $sourcesRoot -Recurse -File -ErrorAction SilentlyContinue |
    Unblock-File -ErrorAction SilentlyContinue

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Get-ChildItem (Join-Path $sourcesRoot 'modules') -Filter '*.psm1' |
    ForEach-Object { Import-Module $_.FullName -Force }
$settings = Import-PowerShellDataFile (Join-Path $sourcesRoot 'config\settings.psd1')
$zones    = Import-PowerShellDataFile (Join-Path $sourcesRoot 'config\zones.psd1')

# PSM-Deploy state of this server, READ only (never created here).
$state     = $null
$statePath = Join-Path (Join-Path $sourcesRoot $settings.Paths.State) 'progress.json'
if (Test-Path -LiteralPath $statePath) { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json }
function Get-StateProperty {
    param([string] $Name)
    if ($state -and ($state.PSObject.Properties.Name -contains $Name)) { return $state.$Name }
    return $null
}

if (-not $Zone) { $Zone = Get-StateProperty -Name 'Zone' }
if (-not $Zone) { throw "-Zone required (no PSM-Deploy state on this server). Zones: $($zones.Keys -join ', ')." }
if (-not $zones.ContainsKey($Zone)) { throw "Unknown zone '$Zone'. Available zones: $($zones.Keys -join ', ')." }

$results = Invoke-PSMConfigurationAudit -Settings $settings -Zones $zones -ZoneKey $Zone `
               -LastHardening (Get-StateProperty -Name 'LastHardening')
if (@($results | Where-Object { $_.Status -eq 'ALERT' }).Count -gt 0) { exit 1 }
exit 0
