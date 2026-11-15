<#
.SYNOPSIS
    Installs (or checks, or removes) the "PSM AppLocker hash repair" scheduled
    task on the PSM servers, from the CPM. Idempotent; one status per server.

.DESCRIPTION
    Same inventory, filters and credential cascade as
    Distribute-PSMSources.ps1 (config\distribution.psd1), but instead of
    pushing the sources, for each selected server:
      1. copies PSM-Deploy\tools\Repair-PSMAppLocker.ps1 (from the CPM's base
         tree) to C:\Program Files\PSM-Deploy\ on the server, over the admin
         share - only when missing or different. A folder under Program Files:
         writable by administrators only (a SYSTEM task must never run a
         script a user could edit);
      2. checks the scheduled task (SYSTEM, highest privileges, at startup +5
         min and every day at 03:00) and registers it only when it is missing
         or different;
      3. reports per server: script OK/CHANGED, task OK/CHANGED, and the task's
         last run and result.
    Credential cascade (as for the push): current session, then the access lot's
    domain account (Vault), then the machine's local account (Vault), then a
    prompt. A NETWORK failure (RPC server unavailable, path not found) stops
    the cascade for that server: another account would not help.

    Network: SMB/445 for the file (like the push) AND the Task Scheduler RPC
    (TCP 135 + dynamic RPC ports, firewall group "Remote Scheduled Tasks
    Management" on the PSM). Without the RPC flow, the server is FAILED with
    "RPC server is unavailable".

    -WhatIf = status report: reads each server with the CURRENT session only
    (no Vault, no prompt), changes nothing.

.PARAMETER Type
    Restrict to one or more server types (PRD, DRP, PREPRD, PRDNPR).

.PARAMETER Server
    Restrict to one or more server names (as in distribution.psd1).

.PARAMETER Remove
    Removes the task and the script from the servers (the Logs folder stays).

.PARAMETER RunNow
    Starts the task right after the check/installation (test). Relaunch with
    -WhatIf a minute later to read its result.

.EXAMPLE
    .\Install-PSMAppLockerTask.ps1 -Server FRPRDSRV10013 -RunNow
.EXAMPLE
    .\Install-PSMAppLockerTask.ps1 -WhatIf          # status of every server, changes nothing
.EXAMPLE
    .\Install-PSMAppLockerTask.ps1 -Type PRD
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]] $Type,
    [string[]] $Server,
    [switch]   $Remove,
    [switch]   $RunNow,
    [string]   $DailyAt = '03:00',
    [int]      $StartupDelayMinutes = 5,
    [pscredential] $PvwaCredential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TaskName  = 'PSM AppLocker hash repair'
$TargetDir = 'C:\Program Files\PSM-Deploy'          # on each PSM (admin-only by default)

$Config = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'config\distribution.psd1')
foreach ($m in 'modules\PSM.Common.psm1', 'modules\PSM.Pvwa.psm1') {
    $p = Join-Path $Config.SourceRoot $m
    if (-not (Test-Path $p)) { throw "$m not found under SourceRoot ($($Config.SourceRoot)): the PSM-Deploy base tree must sit there." }
    Import-Module $p -Force
}
Import-Module (Join-Path $PSScriptRoot 'modules\PSM.RemoteTask.psm1') -Force
Initialize-PSMLogging -LogDirectory (Join-Path $PSScriptRoot 'logs')

$repairScript = Join-Path $Config.SourceRoot 'tools\Repair-PSMAppLocker.ps1'
if (-not $Remove -and -not (Test-Path $repairScript)) {
    throw "Repair script not found: $repairScript (copy the latest PSM-Deploy to $($Config.SourceRoot))."
}
$scriptOnTarget = "$TargetDir\$(Split-Path $repairScript -Leaf)"   # path ON the target (no Join-Path: drive C: is not local)
$spec = Get-PSMRepairTaskSpec -ScriptPath $scriptOnTarget -DailyAt $DailyAt -StartupDelayMinutes $StartupDelayMinutes

# --- Inventory + selection (same rules as Distribute-PSMSources.ps1) ---------
$targets = @($Config.Servers)
foreach ($s in $targets) {
    foreach ($k in 'Name', 'Type') {
        if (-not $s[$k]) { throw "distribution.psd1: a Servers entry is missing '$k'." }
    }
}
if ($Type)   { $targets = @($targets | Where-Object { $_.Type -in $Type }) }
if ($Server) { $targets = @($targets | Where-Object { $_.Name -in $Server }) }
if (-not $targets) {
    throw "No target server selected (filters: Type=$($Type -join ',') Server=$($Server -join ',')). Check distribution.psd1."
}
$what = if ($Remove) { 'REMOVAL' } elseif ($WhatIfPreference) { 'STATUS (WhatIf, current session only)' } else { 'INSTALLATION' }
Write-PSMLog -Level INFO -Message ("=== AppLocker repair task - {0} | {1} server(s): {2} ===" -f `
    $what, $targets.Count, (($targets | ForEach-Object { $_.Name }) -join ', '))

# --- Vault: PVWA logon only when a server actually needs a Vault account -----
$localAdmin   = $Config['LocalAdminUserName']
$pushAccounts = $Config['PushAccounts']; if (-not $pushAccounts) { $pushAccounts = @{} }
$tryCurrent   = if ($Config.Keys -contains 'TryCurrentSession') { [bool]$Config['TryCurrentSession'] } else { $true }
$script:session  = $null
$script:pvwaCred = $null
$pushCredCache   = @{}

function Get-VaultSession {
    if (-not $script:session) {
        $logon = Connect-PvwaSessionWithRetry -PvwaUrl $Config.Pvwa.Url -AuthMethod $Config.Pvwa.AuthMethod `
                    -ZoneName 'CPM - AppLocker task' -Credential $PvwaCredential -ConcurrentSession `
                    -SkipCertificateCheck:$Config.Pvwa.SkipCertificateCheck
        $script:session  = $logon.Session
        $script:pvwaCred = $logon.Credential
    }
    return $script:session
}
function Invoke-PvwaWithReconnect {
    param([Parameter(Mandatory)] [scriptblock] $Call)
    try { return & $Call }
    catch {
        if ($_.Exception.Message -notmatch '\(401\)|Unauthorized|timed out|timeout') { throw }
        Write-PSMLog -Level WARN -Message "PVWA session lost ($($_.Exception.Message)) - reconnecting and retrying once..."
        $script:session = Connect-PvwaSession -PvwaUrl $Config.Pvwa.Url -Credential $script:pvwaCred `
                              -AuthMethod $Config.Pvwa.AuthMethod -ConcurrentSession `
                              -SkipCertificateCheck:$Config.Pvwa.SkipCertificateCheck
        return & $Call
    }
}
function Resolve-PushScope {
    # Access lot of a server: explicit Push, else 'Match' on the name, else Default.
    param([Parameter(Mandatory)] $Srv)
    if ($Srv['Push']) { return $Srv['Push'] }
    foreach ($k in @($pushAccounts.Keys | Where-Object { $_ -ne 'Default' } | Sort-Object)) {
        $m = $pushAccounts[$k]['Match']
        if ($m -and $Srv.Name -like $m) { return $k }
    }
    if ($pushAccounts.ContainsKey('Default')) { return 'Default' }
    return $null
}
function Resolve-PushCredential {
    param([Parameter(Mandatory)] [string] $ScopeKey)
    if ($pushCredCache.ContainsKey($ScopeKey)) { return $pushCredCache[$ScopeKey] }
    $cfg = $pushAccounts[$ScopeKey]
    $logonName = $cfg['LogonName']
    if (-not $logonName) { $logonName = "$($cfg.UserName)@$($cfg['Address'])" }
    $null = Get-VaultSession
    $acct = Invoke-PvwaWithReconnect { Get-PvwaAccountPassword -Session $script:session `
                -UserName $cfg.UserName -Address $cfg['Address'] -Safe $cfg['Safe'] }
    $cred = [System.Management.Automation.PSCredential]::new($logonName, $acct.Credential.Password)
    $pushCredCache[$ScopeKey] = $cred
    return $cred
}

function Invoke-ServerTask {
    <#
        Everything on ONE server with ONE identity ($Credential $null = current
        session): file, then task. Returns the result row; throws on failure.
    #>
    param([Parameter(Mandatory)] $Srv, [pscredential] $Credential)
    $remoteDir = ConvertTo-PSMAdminSharePath -ComputerName $Srv.Name -LocalPath $TargetDir
    $shareRoot = Get-PSMShareRoot -Path $remoteDir
    $row = [ordered]@{ Script = '-'; Task = '-'; LastRun = '-'; LastResult = '-' }
    $drive = Open-PSMAdminShare -ShareRoot $shareRoot -Credential $Credential
    try {
        Assert-PSMAdminShare -ShareRoot $shareRoot
        $svc  = Connect-PSMTaskScheduler -ComputerName $Srv.Name -Credential $Credential
        $task = Get-PSMScheduledTask -Service $svc -Name $TaskName

        if ($Remove) {
            if ($task) {
                if ($PSCmdlet.ShouldProcess("$($Srv.Name): task '$TaskName'", 'remove')) {
                    $svc.GetFolder('\').DeleteTask($TaskName, 0); $row.Task = 'REMOVED'
                } else { $row.Task = 'WOULD REMOVE' }
            } else { $row.Task = 'ABSENT' }
            $remoteFile = Join-Path $remoteDir (Split-Path $scriptOnTarget -Leaf)
            if (Test-Path -LiteralPath $remoteFile) {
                if ($PSCmdlet.ShouldProcess($remoteFile, 'remove')) { Remove-Item -LiteralPath $remoteFile -Force; $row.Script = 'REMOVED' }
                else { $row.Script = 'WOULD REMOVE' }
            } else { $row.Script = 'ABSENT' }
            return [pscustomobject]$row
        }

        $row.Script = Sync-PSMRemoteFile -LocalFile $repairScript -RemoteDir $remoteDir -WhatIf:$WhatIfPreference
        $diff = if ($task) { @(Compare-PSMTaskSpec -Spec $spec -Snapshot (ConvertTo-PSMTaskSnapshot -Task $task)) } else { @('missing') }
        if (-not $diff) { $row.Task = 'OK' }
        elseif ($PSCmdlet.ShouldProcess("$($Srv.Name): task '$TaskName'", 'register')) {
            Register-PSMRepairTask -Service $svc -Name $TaskName -Spec $spec
            Write-PSMLog -Level CHANGED -Message "$($Srv.Name): task registered ($($diff -join '; '))."
            $row.Task = 'CHANGED'
        }
        else {
            Write-PSMLog -Level INFO -Message "$($Srv.Name): task would be registered ($($diff -join '; '))."
            $row.Task = 'WOULD CHANGE'
        }

        $task = Get-PSMScheduledTask -Service $svc -Name $TaskName
        if ($task) {
            if ($RunNow -and -not $WhatIfPreference) {
                [void]$task.Run($null)
                Write-PSMLog -Level INFO -Message "$($Srv.Name): task started (-RunNow) - relaunch with -WhatIf in a minute to read its result."
            }
            $last = [datetime]$task.LastRunTime
            $row.LastRun    = if ($last.Year -lt 2000) { 'never' } else { $last.ToString('yyyy-MM-dd HH:mm') }
            $row.LastResult = Format-PSMTaskResult -Code $task.LastTaskResult
        }
        return [pscustomobject]$row
    }
    finally {
        if ($drive) { Remove-PSDrive -Name $drive.Name -Scope Global -Force -ErrorAction SilentlyContinue }
    }
}

# --- Per server: credential cascade ------------------------------------------
$results = @()
try {
    foreach ($srv in $targets) {
        # Identities to try, in order. Each: label + scriptblock returning the
        # credential ($null = current session), run right away in this loop
        # (it reads $srv / $lot as they are now). Under -WhatIf: current session only.
        $levels = @()
        if ($tryCurrent -or $WhatIfPreference) { $levels += ,@('current session', { $null }) }
        if (-not $WhatIfPreference) {
            $lot = Resolve-PushScope -Srv $srv
            if ($lot) { $levels += ,@("lot '$lot' account", { Resolve-PushCredential -ScopeKey $lot }) }
            if ($localAdmin) {
                $levels += ,@('local account (Vault)', {
                    $null = Get-VaultSession
                    $a = Invoke-PvwaWithReconnect { Get-PvwaAccountPassword -Session $script:session -UserName $localAdmin -Address $srv.Name }
                    [System.Management.Automation.PSCredential]::new("$($srv.Name)\$($a.UserName)", $a.Credential.Password)
                })
            }
            $levels += ,@('manual prompt', {
                $c = Get-Credential -Message "Administrator account for $($srv.Name) (automatic credentials failed)"
                if (-not $c) { throw 'no credential provided (prompt canceled).' }
                $c
            })
        }

        $row = $null; $lastError = 'no identity to try'
        foreach ($lvl in $levels) {
            try {
                $cred = & $lvl[1]
                $row  = Invoke-ServerTask -Srv $srv -Credential $cred
                Write-PSMLog -Level INFO -Message "$($srv.Name): done with the $($lvl[0])."
                break
            }
            catch {
                $lastError = $_.Exception.Message
                if (Test-PSMUnreachableError -Message $lastError) {
                    $lastError = ("$lastError - NETWORK: the CPM must reach the server on SMB/445 and on the Task Scheduler " +
                                  'RPC (TCP 135 + dynamic ports, firewall group "Remote Scheduled Tasks Management").')
                    break
                }
                Write-PSMLog -Level WARN -Message "$($srv.Name): $($lvl[0]) failed ($lastError)."
            }
        }
        if ($row) {
            $status = if ("$($row.Script) $($row.Task)" -match 'WOULD') { 'WOULD CHANGE' }
                      elseif ("$($row.Script) $($row.Task)" -match 'CHANGED|REMOVED') { 'CHANGED' }
                      else { 'OK' }
            $results += [pscustomobject]@{ Server = $srv.Name; Type = $srv.Type; Status = $status; Script = $row.Script
                                           Task = $row.Task; LastRun = $row.LastRun; LastResult = $row.LastResult; Detail = '' }
        }
        else {
            $status = if ($WhatIfPreference) { 'NOT CHECKED' } else { 'FAILED' }
            Write-PSMLog -Level $(if ($WhatIfPreference) { 'WARN' } else { 'ERROR' }) -Message "$($srv.Name): $status - $lastError"
            $results += [pscustomobject]@{ Server = $srv.Name; Type = $srv.Type; Status = $status; Script = '-'
                                           Task = '-'; LastRun = '-'; LastResult = '-'; Detail = $lastError }
        }
    }
}
finally {
    if ($script:session) { Disconnect-PvwaSession -Session $script:session }
}

# --- Summary -----------------------------------------------------------------
Write-PSMLog -Level INFO -Message '=== AppLocker repair task - summary ==='
Write-PSMLog -Level INFO -Message ('{0,-16} {1,-7} {2,-12} {3,-14} {4,-14} {5,-17} {6}' -f 'Server', 'Type', 'Status', 'Script', 'Task', 'Last run', 'Last result')
foreach ($r in $results) {
    $lvl = switch ($r.Status) { 'FAILED' { 'ERROR' } 'NOT CHECKED' { 'WARN' } 'WOULD CHANGE' { 'INFO' } 'CHANGED' { 'CHANGED' } default { 'OK' } }
    $line = '{0,-16} {1,-7} {2,-12} {3,-14} {4,-14} {5,-17} {6}' -f $r.Server, $r.Type, $r.Status, $r.Script, $r.Task, $r.LastRun, $r.LastResult
    if ($r.Detail) { $line += " - $($r.Detail)" }
    Write-PSMLog -Level $lvl -Message $line
}
$failed = @($results | Where-Object { $_.Status -eq 'FAILED' })
if ($failed) {
    Write-PSMLog -Level ERROR -Message "$($failed.Count) server(s) FAILED - relaunch with -Server $(($failed | ForEach-Object { $_.Server }) -join ',')."
    exit 1
}
exit 0
