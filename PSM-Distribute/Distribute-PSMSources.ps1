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
      3. authenticates through a CYBERARK-backed credential CASCADE: the
         operator logs on to the PVWA once (concurrent session, auto-reconnect
         on 401), then per server tries (a) the DOMAIN push account fetched
         once from the Vault (PushAccount), (b) the machine's own LOCAL
         account from the Vault (LocalAdminUserName + exact address match),
         (c) a manual credential prompt. Each attempt is logged; no password
         ever touches the disk.
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
    [switch]   $SkipStaging,

    # PVWA account of the operator. When omitted, requested interactively
    # (with validation and retry) - same behavior as Deploy-PSM.ps1.
    [pscredential] $PvwaCredential
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
Import-Module (Join-Path $Config.SourceRoot 'modules\PSM.Pvwa.psm1') -Force   # PVWA session + Vault lookups (reused)
Import-Module (Join-Path $PSScriptRoot 'modules\PSM.Distribute.psm1') -Force
Initialize-PSMLogging -LogDirectory (Join-Path $PSScriptRoot 'logs')

# --- Inventory validation + target selection --------------------------------
$targets = @($Config.Servers)
foreach ($s in $targets) {
    foreach ($k in 'Name', 'Type') {
        if (-not $s[$k]) { throw "distribution.psd1: a Servers entry is missing '$k' (Name/Type are required)." }
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
$localAdmin = $Config['LocalAdminUserName']
$pushUser   = if ($Config['PushAccount']) { $Config['PushAccount']['UserName'] } else { $null }
if (-not $WhatIfPreference -and -not $localAdmin -and -not $pushUser) {
    Write-PSMLog -Level WARN -Message ("Neither PushAccount.UserName nor LocalAdminUserName is set in distribution.psd1: " +
        'EVERY server will fall back to a manual credential prompt.')
}
Write-PSMLog -Level INFO -Message ("=== Source distribution | {0} server(s): {1} ===" -f `
    $targets.Count, (($targets | ForEach-Object { "$($_.Name) [$($_.Type)]" }) -join ', '))

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

# --- CyberArk/PVWA session (same flow as the PSM registration) ---------------
# One CONCURRENT PVWA logon for the whole run: the operator is usually ALSO
# logged on the PVWA portal from the CPM - without concurrentSession the Vault
# invalidates one of the two sessions (observed: 401s mid-run). Every Vault
# call goes through Invoke-PvwaWithReconnect: on a dead session (401/timeout)
# it reconnects ONCE with the in-memory credential and retries.
$session  = $null
$pvwaCred = $null
if (-not $WhatIfPreference) {
    $logon = Connect-PvwaSessionWithRetry -PvwaUrl $Config.Pvwa.Url `
                -AuthMethod $Config.Pvwa.AuthMethod -ZoneName 'CPM distribution' `
                -Credential $PvwaCredential -ConcurrentSession `
                -SkipCertificateCheck:$Config.Pvwa.SkipCertificateCheck
    $session  = $logon.Session
    $pvwaCred = $logon.Credential
}

function Invoke-PvwaWithReconnect {
    # Same pattern as the registration rename retry in Deploy-PSM.ps1: a Vault
    # call failing on a DEAD SESSION is retried once after a fresh logon (no
    # secret ever written to disk).
    param([Parameter(Mandatory)] [scriptblock] $Call)
    try { return & $Call }
    catch {
        if ($_.Exception.Message -notmatch '\(401\)|Unauthorized|timed out|timeout') { throw }
        Write-PSMLog -Level WARN -Message "PVWA session lost ($($_.Exception.Message)) - reconnecting and retrying once..."
        $script:session = Connect-PvwaSession -PvwaUrl $Config.Pvwa.Url -Credential $pvwaCred `
                              -AuthMethod $Config.Pvwa.AuthMethod -ConcurrentSession `
                              -SkipCertificateCheck:$Config.Pvwa.SkipCertificateCheck
        return & $Call
    }
}

# --- DOMAIN push account (PRIMARY credential, optional) ----------------------
# One Vault account with admin-share access to ALL machines, fetched once and
# reused for every server. Empty UserName = disabled (per-machine local
# accounts are then tried directly).
$pushCfg    = $Config['PushAccount']
$domainCred = $null
if (-not $WhatIfPreference -and $pushCfg -and $pushCfg['UserName']) {
    $logonName = $pushCfg['LogonName']
    if (-not $logonName) {
        if (-not $pushCfg['Address']) {
            throw "distribution.psd1: PushAccount needs 'LogonName' (e.g. 'FRANCE\svcpsmpush') or 'Address' (to build <UserName>@<Address>)."
        }
        $logonName = "$($pushCfg.UserName)@$($pushCfg['Address'])"   # UPN logon
    }
    $acct = Invoke-PvwaWithReconnect { Get-PvwaAccountPassword -Session $session `
                -UserName $pushCfg.UserName -Address $pushCfg['Address'] -Safe $pushCfg['Safe'] }
    $domainCred = [System.Management.Automation.PSCredential]::new($logonName, $acct.Credential.Password)
    Write-PSMLog -Level OK -Message "Domain push account retrieved from the Vault: $logonName (primary credential for every server)."
}

# --- Push: per-server credential CASCADE -------------------------------------
#   1) domain push account  2) machine local account (Vault)  3) manual prompt
# One server's failure does not stop the others.
$results = @()
try {
    foreach ($srv in $targets) {
        $staging = Join-Path $Config.StagingRoot $srv.Type
        # D:\PSMSources\PSM-Deploy -> \\<server>\D$\PSMSources\PSM-Deploy
        $unc = '\\{0}\{1}' -f $srv.Name, ($Config.TargetPath -replace '^([A-Za-z]):\\', '$1$\')
        if ($WhatIfPreference) {
            $who = if ($pushCfg -and $pushCfg['UserName']) { "the domain push account '$($pushCfg.UserName)'" }
                   elseif ($localAdmin) { "$($srv.Name)\$localAdmin" }
                   else { 'a manually prompted account' }
            Write-PSMLog -Level INFO -Message "WhatIf: '$staging' would be mirrored to '$unc' as $who (state\ and logs\ preserved)."
            $status = 'WHATIF'
        }
        else {
            try {
                $code = $null
                # 1) DOMAIN push account (primary).
                if ($domainCred) {
                    try {
                        $code = Push-PSMSourcesToServer -ServerName $srv.Name -StagingPath $staging `
                                    -TargetUnc $unc -Credential $domainCred
                    }
                    catch {
                        Write-PSMLog -Level WARN -Message ("$($srv.Name): push with the domain account '$($domainCred.UserName)' failed " +
                            "($($_.Exception.Message)) - trying the machine's local account...")
                    }
                }
                # 2) Machine LOCAL account from the Vault (accounts spread across
                #    Safes: userName + exact address match, short name or FQDN).
                #    LocalAdminUserName may be a WILDCARD pattern (e.g. '*adm*'):
                #    the SMB logon then uses the REAL name of the matched account.
                if ($null -eq $code -and $localAdmin) {
                    try {
                        $acct = Invoke-PvwaWithReconnect { Get-PvwaAccountPassword -Session $session `
                                    -UserName $localAdmin -Address $srv.Name }
                        $smbCred = [System.Management.Automation.PSCredential]::new(
                                       "$($srv.Name)\$($acct.UserName)", $acct.Credential.Password)
                        $code = Push-PSMSourcesToServer -ServerName $srv.Name -StagingPath $staging `
                                    -TargetUnc $unc -Credential $smbCred
                    }
                    catch {
                        Write-PSMLog -Level WARN -Message ("$($srv.Name): local-account push failed " +
                            "($($_.Exception.Message)) - falling back to a manual credential prompt.")
                    }
                }
                # 3) Manual prompt (last resort): the operator supplies whatever
                #    account works for this machine. Cancel = server FAILED.
                if ($null -eq $code) {
                    $msg = "Account with admin-share access to \\$($srv.Name) (automatic credentials failed)"
                    # No prefill when LocalAdminUserName is a wildcard pattern.
                    $prefill = if ($localAdmin -and $localAdmin.IndexOfAny([char[]]'*?') -lt 0) { "$($srv.Name)\$localAdmin" }
                    $smbCred = if ($prefill) { Get-Credential -UserName $prefill -Message $msg }
                               else          { Get-Credential -Message $msg }
                    if (-not $smbCred) { throw "no credential provided (prompt canceled)." }
                    $code = Push-PSMSourcesToServer -ServerName $srv.Name -StagingPath $staging `
                                -TargetUnc $unc -Credential $smbCred
                }
                if ($code -eq 0) { $status = 'OK';      Write-PSMLog -Level OK      -Message "$($srv.Name): already in sync ($unc)." }
                else             { $status = 'CHANGED'; Write-PSMLog -Level CHANGED -Message "$($srv.Name): sources updated ($unc)." }
            }
            catch {
                $status = 'FAILED'
                Write-PSMLog -Level ERROR -Message "$($srv.Name): push failed - $($_.Exception.Message)"
            }
        }
        $results += [pscustomobject]@{ Server = $srv.Name; Type = $srv.Type; Status = $status }
    }
}
finally {
    if ($session) { Disconnect-PvwaSession -Session $session }
}

# --- Summary -----------------------------------------------------------------
Write-PSMLog -Level INFO -Message '=== Distribution summary ==='
foreach ($r in $results) {
    $lvl = switch ($r.Status) { 'FAILED' { 'ERROR' } 'CHANGED' { 'CHANGED' } 'OK' { 'OK' } default { 'INFO' } }
    Write-PSMLog -Level $lvl -Message ("{0,-20} {1,-8} {2}" -f $r.Server, $r.Type, $r.Status)
}
$failed = @($results | Where-Object { $_.Status -eq 'FAILED' })
if ($failed) {
    Write-PSMLog -Level ERROR -Message "$($failed.Count) server(s) FAILED - fix and relaunch with -Server $(($failed | ForEach-Object { $_.Server }) -join ',') -SkipStaging."
    exit 1
}
exit 0
