<#
.SYNOPSIS
    Distributes the PSM sources from the CPM to the PSM servers, per type.

.DESCRIPTION
    Runs ON the CPM (which reaches every PSM on SMB/445). For each selected
    server:
      1. composes the staging tree of its TYPE (common base + overlays\<TYPE>,
         the overlay always wins) - installers\ and software.psd1 differ per
         type, hence no single source tree;
      2. pushes it to \\<server>\D$\...\PSM-Deploy with robocopy /MIR,
         PRESERVING the server's local state\ and logs\ folders;
      3. authenticates with the credential of the server's DATACENTER: one
         admin account per datacenter, prompted once per datacenter
         (Get-Credential, never written to disk). DatacenterAccounts declares
         the expected account per datacenter: when it is the CURRENT session
         account, no prompt at all (integrated auth); otherwise the prompt
         comes pre-filled with it.
    One server's failure does not stop the others (summary + exit code 1).

.PARAMETER Type
    Restrict to one or more server types (PRD, DRP, PREPRD, PRDNPR).

.PARAMETER Server
    Restrict to one or more server names (as in distribution.psd1).

.PARAMETER SkipStaging
    Push the EXISTING staging trees without recomposing them (faster when
    only re-pushing to additional servers).

.EXAMPLE
    # Dry-run: shows what would be composed/pushed, prompts for nothing
    .\Distribute-PSMSources.ps1 -WhatIf

.EXAMPLE
    # All the PRD servers
    .\Distribute-PSMSources.ps1 -Type PRD

.EXAMPLE
    # One server only
    .\Distribute-PSMSources.ps1 -Server FRPRDSRV10013
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]] $Type,
    [string[]] $Server,
    [switch]   $SkipStaging
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Config = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'config\distribution.psd1')

# Reuse the PSM-Deploy toolbox (logging) from the base tree - no duplicate framework.
$commonModule = Join-Path $Config.SourceRoot 'modules\PSM.Common.psm1'
if (-not (Test-Path $commonModule)) {
    throw ("PSM.Common.psm1 not found under SourceRoot ($commonModule): the PSM-Deploy base tree " +
           "must sit at distribution.psd1 SourceRoot ($($Config.SourceRoot)).")
}
Import-Module $commonModule -Force
Import-Module (Join-Path $PSScriptRoot 'modules\PSM.Distribute.psm1') -Force
Initialize-PSMLogging -LogDirectory (Join-Path $PSScriptRoot 'logs')

# --- Inventory validation + target selection --------------------------------
$targets = @($Config.Servers)
foreach ($s in $targets) {
    foreach ($k in 'Name', 'Type', 'Datacenter') {
        if (-not $s[$k]) { throw "distribution.psd1: a Servers entry is missing '$k' (Name/Type/Datacenter are required)." }
    }
    if ($s.Type -notin $Config.ServerTypes) {
        throw "distribution.psd1: server '$($s.Name)': type '$($s.Type)' unknown (ServerTypes: $($Config.ServerTypes -join ', '))."
    }
}
if ($Type)   { $targets = @($targets | Where-Object { $_.Type -in $Type }) }
if ($Server) { $targets = @($targets | Where-Object { $_.Name -in $Server }) }
if (-not $targets) {
    throw "No target server selected (filters: Type=$($Type -join ',') Server=$($Server -join ',')). Check distribution.psd1."
}
Write-PSMLog -Level INFO -Message ("=== Source distribution | {0} server(s): {1} ===" -f `
    $targets.Count, (($targets | ForEach-Object { "$($_.Name) [$($_.Type)/$($_.Datacenter)]" }) -join ', '))

# --- Staging composition (one tree per distinct type) ------------------------
$neededTypes = @($targets | ForEach-Object { $_.Type } | Sort-Object -Unique)
foreach ($t in $neededTypes) {
    $staging = Join-Path $Config.StagingRoot $t
    $overlay = Join-Path $Config.OverlayRoot $t
    if ($SkipStaging) {
        if (-not (Test-Path $staging)) { throw "-SkipStaging: staging tree missing for type '$t' ($staging) - run once without -SkipStaging." }
        Write-PSMLog -Level INFO -Message "Staging '$t' reused as-is (-SkipStaging): $staging"
        continue
    }
    if ($WhatIfPreference) {
        Write-PSMLog -Level INFO -Message "WhatIf: staging '$t' would be composed (base $($Config.SourceRoot) + overlay $overlay) -> $staging"
        continue
    }
    if (-not (Test-Path $overlay)) {
        Write-PSMLog -Level WARN -Message "No overlay for type '$t' ($overlay): these servers receive the BASE tree only."
    }
    $n = Build-PSMStagingTree -BaseRoot $Config.SourceRoot -OverlayPath $overlay -StagingPath $staging
    if ($n -eq 0) { Write-PSMLog -Level OK      -Message "Staging '$t' already up to date: $staging" }
    else          { Write-PSMLog -Level CHANGED -Message "Staging '$t' composed (base + overlay): $staging" }
}

# --- One credential per DISTINCT datacenter among the targets ----------------
# DatacenterAccounts declares WHO is supposed to reach each datacenter:
#   - declared account == the current session -> no prompt, no $credByDc entry
#     (the push then runs without New-PSDrive, under the operator's own token);
#   - declared but different -> Get-Credential pre-filled with it;
#   - not declared -> plain Get-Credential.
$dcAccounts = $Config['DatacenterAccounts']
if (-not $dcAccounts) { $dcAccounts = @{} }
$currentUser = "$env:USERDOMAIN\$env:USERNAME"
$credByDc = @{}
if (-not $WhatIfPreference) {
    foreach ($dc in @($targets | ForEach-Object { $_.Datacenter } | Sort-Object -Unique)) {
        $declared = $dcAccounts[$dc]
        if ($declared -and ($declared -ieq $currentUser)) {
            Write-PSMLog -Level INFO -Message "Datacenter '$dc': declared account '$declared' IS the current session - no credential prompt (integrated authentication)."
            continue
        }
        $dcServers = (@($targets | Where-Object { $_.Datacenter -eq $dc } | ForEach-Object { $_.Name })) -join ', '
        $msg = "Admin account for datacenter '$dc' (SMB admin-share access to: $dcServers)"
        $cred = if ($declared) { Get-Credential -UserName $declared -Message $msg }
                else           { Get-Credential -Message $msg }
        if (-not $cred) { throw "Distribution canceled: no credential provided for datacenter '$dc'." }
        $credByDc[$dc] = $cred
    }
}

# --- Push (one server's failure does not stop the others) --------------------
$results = @()
foreach ($srv in $targets) {
    $staging = Join-Path $Config.StagingRoot $srv.Type
    # D:\PSMSources\PSM-Deploy -> \\<server>\D$\PSMSources\PSM-Deploy
    $unc = '\\{0}\{1}' -f $srv.Name, ($Config.TargetPath -replace '^([A-Za-z]):\\', '$1$\')
    if ($WhatIfPreference) {
        Write-PSMLog -Level INFO -Message "WhatIf: '$staging' would be mirrored to '$unc' (state\ and logs\ preserved)."
        $status = 'WHATIF'
    }
    else {
        try {
            $code = Push-PSMSourcesToServer -ServerName $srv.Name -StagingPath $staging `
                        -TargetUnc $unc -Credential $credByDc[$srv.Datacenter]
            if ($code -eq 0) { $status = 'OK';      Write-PSMLog -Level OK      -Message "$($srv.Name): already in sync ($unc)." }
            else             { $status = 'CHANGED'; Write-PSMLog -Level CHANGED -Message "$($srv.Name): sources updated ($unc)." }
        }
        catch {
            $status = 'FAILED'
            Write-PSMLog -Level ERROR -Message "$($srv.Name): push failed - $($_.Exception.Message)"
        }
    }
    $results += [pscustomobject]@{ Server = $srv.Name; Type = $srv.Type; Datacenter = $srv.Datacenter; Status = $status }
}

# --- Summary -----------------------------------------------------------------
Write-PSMLog -Level INFO -Message '=== Distribution summary ==='
foreach ($r in $results) {
    $lvl = switch ($r.Status) { 'FAILED' { 'ERROR' } 'CHANGED' { 'CHANGED' } 'OK' { 'OK' } default { 'INFO' } }
    Write-PSMLog -Level $lvl -Message ("{0,-20} {1,-8} {2,-6} {3}" -f $r.Server, $r.Type, $r.Datacenter, $r.Status)
}
$failed = @($results | Where-Object { $_.Status -eq 'FAILED' })
if ($failed) {
    Write-PSMLog -Level ERROR -Message "$($failed.Count) server(s) FAILED - fix and relaunch with -Server $(($failed | ForEach-Object { $_.Server }) -join ',') -SkipStaging."
    exit 1
}
exit 0
