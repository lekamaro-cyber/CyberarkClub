<#
.SYNOPSIS
    DEMO autonome du moteur de deploiement PSM (sans media CyberArk, sans droits
    admin, sans reseau). Montre : idempotence Test->Set, mode plan (-WhatIf),
    confirmation de zone, masquage des secrets, recap final.

.DESCRIPTION
    Utilise le VRAI moteur (modules/PSM.Common.psm1) mais avec des phases SIMULEES.
    Un fichier "monde" (.demo-state/world.json) represente l'etat de la machine et
    persiste entre deux executions -> l'idempotence est reelle, pas mise en scene :
      - 1er passage  : tout en CHANGED
      - 2e passage   : tout en OK (rien n'est refait)
      - avec -WhatIf : rien n'est modifie, on voit ce qui SERAIT fait
      - avec -Reset  : on repart d'une machine "vierge"

.EXAMPLE
    .\Demo-PSM.ps1 -Reset -NonInteractive            # 1er passage : CHANGED partout
.EXAMPLE
    .\Demo-PSM.ps1 -NonInteractive                   # 2e passage : OK partout (idempotent)
.EXAMPLE
    .\Demo-PSM.ps1 -Reset -NonInteractive -WhatIf    # mode plan : aucune modification
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
    Write-Host "(demo) Etat reinitialise : machine 'vierge'." -ForegroundColor DarkGray
}

Initialize-PSMLogging -LogDirectory $demoLogs
Initialize-PSMState   -StateDirectory $demoState

# --- "Monde" simule : etat de la machine, persistant entre executions --------
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
Write-Host '########  DEMO — Moteur de deploiement PSM (simulation)  ########' -ForegroundColor White

# --- Demonstration du masquage des secrets -----------------------------------
$fakeSecret = 'S3cr3t-DemoPassword!'
Register-PSMSecret -Secret $fakeSecret
Write-PSMLog -Level INFO -Message "Secret recupere via CCP (demo) = $fakeSecret  <= doit apparaitre MASQUE dans les logs"

# --- Confirmation de zone (anti-bourde) --------------------------------------
$zoneCfg = [pscustomobject]@{
    Name = $Zone; PvwaUrl = 'https://pvwa.demo.local'
    CcpUrl = 'https://ccp.demo.local'; Safe = 'PSM-Components'
}
Confirm-PSMZone -ZoneConfig $zoneCfg -NonInteractive:$NonInteractive

# --- Phases SIMULEES, idempotentes (meme moteur que le vrai script) ----------
Invoke-IdempotentStep -Name 'Licence RDS (simulee)' `
    -Test { (Get-World).rdsLicense } -Action { Set-WorldFlag 'rdsLicense' } -Confirm:$false

Invoke-IdempotentStep -Name 'Logiciels additionnels (simules)' `
    -Test { (Get-World).software } -Action { Start-Sleep -Milliseconds 150; Set-WorldFlag 'software' } -Confirm:$false

Invoke-IdempotentStep -Name 'Installation PSM (simulee)' `
    -Test { (Get-World).psmInstalled } -Action { Start-Sleep -Milliseconds 150; Set-WorldFlag 'psmInstalled' } -Confirm:$false

# Illustration du point de reboot (aucun redemarrage reel en demo)
if (-not (Get-World).psmInstalled) {
    Write-PSMLog -Level WARN -Message "(demo) Ici le vrai script programmerait la reprise et REBOOTERAIT."
}

Invoke-IdempotentStep -Name 'Enregistrement Vault (simule)' `
    -Test { (Get-World).registered } -Action { Set-WorldFlag 'registered' } -Confirm:$false

Invoke-IdempotentStep -Name 'Hardening + AppLocker (simules)' `
    -Test { (Get-World).hardened } -Action { Set-WorldFlag 'hardened' } -Confirm:$false

Write-PSMSummary
Write-Host ''
Write-Host "(demo) Relance SANS -Reset pour voir l'idempotence (tout en OK)." -ForegroundColor DarkGray
Write-Host "(demo) Logs generes dans : $demoLogs" -ForegroundColor DarkGray
