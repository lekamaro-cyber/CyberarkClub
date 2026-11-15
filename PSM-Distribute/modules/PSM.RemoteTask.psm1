<#
.SYNOPSIS
    Remote scheduled task + file, idempotent, from the CPM: used by
    Install-PSMAppLockerTask.ps1 (AppLocker hash repair task on each PSM).

.DESCRIPTION
    - the file (the script the task runs) goes over the admin share (SMB/445),
      like the source distribution;
    - the task is read / registered through the Task Scheduler API
      (Schedule.Service COM object): remote RPC to the server's Task Scheduler
      (TCP 135 + dynamic RPC ports, Windows firewall group "Remote Scheduled
      Tasks Management" on the target);
    - idempotent: the task's definition is compared with the expected one and
      only re-registered when it differs; the file is only copied when its
      SHA-256 differs.
    No password on a command line or on disk: the credential stays in memory
    (New-PSDrive for SMB, ITaskService.Connect for the Task Scheduler).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SystemIds = @('SYSTEM', 'NT AUTHORITY\SYSTEM', 'S-1-5-18')

function Get-PSMRepairTaskSpec {
    <#
        Expected definition of the repair task: SYSTEM, highest privileges,
        at startup (after a delay) + every day at DailyAt, one action:
        powershell.exe -File <ScriptPath>.
    #>
    param(
        [Parameter(Mandatory)] [string] $ScriptPath,      # path ON the target
        [string] $DailyAt = '03:00',
        [int]    $StartupDelayMinutes = 5
    )
    if ($DailyAt -notmatch '^([01]\d|2[0-3]):[0-5]\d$') { throw "DailyAt '$DailyAt': expected HH:mm (e.g. 03:00)." }
    return [pscustomobject]@{
        Execute     = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        Arguments   = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`""
        RunLevel    = 1                                   # TASK_RUNLEVEL_HIGHEST
        BootDelay   = "PT$($StartupDelayMinutes)M"
        DailyAt     = $DailyAt
        Description = ('Re-pins the AppLocker hash of the PSM allowed files replaced by a patch ' +
                       '(PSM-Deploy tools\Repair-PSMAppLocker.ps1). Installed from the CPM by ' +
                       'PSM-Distribute\Install-PSMAppLockerTask.ps1 - log: Logs\ next to the script.')
    }
}

function ConvertTo-PSMTaskSnapshot {
    <#
        What an EXISTING task does, in the shape of Get-PSMRepairTaskSpec, from
        a registered task (IRegisteredTask, or any object with the same
        properties - tests).
    #>
    param([Parameter(Mandatory)] $Task)
    $def = $Task.Definition
    $actions  = @($def.Actions | ForEach-Object { $_ })
    $triggers = @($def.Triggers | ForEach-Object { $_ })
    $boot  = @($triggers | Where-Object { $_.Type -eq 8 })    # TASK_TRIGGER_BOOT
    $daily = @($triggers | Where-Object { $_.Type -eq 2 })    # TASK_TRIGGER_DAILY
    $at = $null
    if ($daily.Count -eq 1) {
        $m = [regex]::Match([string]$daily[0].StartBoundary, 'T(\d{2}:\d{2})')
        if ($m.Success) { $at = $m.Groups[1].Value }
    }
    return [pscustomobject]@{
        Enabled      = [bool]$Task.Enabled
        ActionCount  = $actions.Count
        Execute      = if ($actions.Count -eq 1 -and $actions[0].Type -eq 0) { [string]$actions[0].Path } else { $null }
        Arguments    = if ($actions.Count -eq 1 -and $actions[0].Type -eq 0) { [string]$actions[0].Arguments } else { $null }
        UserId       = [string]$def.Principal.UserId
        RunLevel     = [int]$def.Principal.RunLevel
        TriggerCount = $triggers.Count
        BootDelay    = if ($boot.Count -eq 1) { [string]$boot[0].Delay } else { $null }
        DailyAt      = $at
        DaysInterval = if ($daily.Count -eq 1) { [int]$daily[0].DaysInterval } else { $null }
    }
}

function Compare-PSMTaskSpec {
    # Differences between the expected definition and an existing task (empty = up to date).
    param([Parameter(Mandatory)] $Spec, [Parameter(Mandatory)] $Snapshot)
    $d = @()
    if (-not $Snapshot.Enabled) { $d += 'task disabled' }
    if ($Snapshot.ActionCount -ne 1 -or $Snapshot.Execute -ine $Spec.Execute -or
        ([string]$Snapshot.Arguments).Trim() -ne $Spec.Arguments) {
        $d += "action '$($Snapshot.Execute) $($Snapshot.Arguments)'"
    }
    if ($Snapshot.UserId -notin $script:SystemIds) { $d += "runs as '$($Snapshot.UserId)'" }
    if ($Snapshot.RunLevel -ne $Spec.RunLevel) { $d += 'not with highest privileges' }
    if ($Snapshot.TriggerCount -ne 2 -or $Snapshot.BootDelay -ne $Spec.BootDelay -or
        $Snapshot.DailyAt -ne $Spec.DailyAt -or $Snapshot.DaysInterval -ne 1) {
        $d += "triggers (startup delay '$($Snapshot.BootDelay)', daily at '$($Snapshot.DailyAt)', $($Snapshot.TriggerCount) trigger(s))"
    }
    return $d
}

function Split-PSMAccountName {
    # 'DOMAIN\user' -> user + DOMAIN; 'user@domain' -> as is, no domain.
    param([Parameter(Mandatory)] [string] $UserName)
    if ($UserName -match '^(?<d>[^\\]+)\\(?<u>.+)$') { return [pscustomobject]@{ User = $Matches.u; Domain = $Matches.d } }
    return [pscustomobject]@{ User = $UserName; Domain = $null }
}

function Connect-PSMTaskScheduler {
    # Task Scheduler of a remote server; current session when no credential.
    param([Parameter(Mandatory)] [string] $ComputerName, [pscredential] $Credential)
    $svc = New-Object -ComObject 'Schedule.Service'
    if ($Credential) {
        $a = Split-PSMAccountName -UserName $Credential.UserName
        $svc.Connect($ComputerName, $a.User, $a.Domain, $Credential.GetNetworkCredential().Password)
    }
    else { $svc.Connect($ComputerName) }
    return $svc
}

function Get-PSMScheduledTask {
    # Registered task, or $null when absent (0x80070002).
    param([Parameter(Mandatory)] $Service, [Parameter(Mandatory)] [string] $Name)
    try { return $Service.GetFolder('\').GetTask($Name) }
    catch {
        if ($_.Exception.HResult -eq -2147024894 -or $_.Exception.Message -match '0x80070002|cannot find the file') { return $null }
        throw
    }
}

function Register-PSMRepairTask {
    # Creates or replaces the task (TASK_CREATE_OR_UPDATE, SYSTEM service account).
    param([Parameter(Mandatory)] $Service, [Parameter(Mandatory)] [string] $Name, [Parameter(Mandatory)] $Spec)
    $def = $Service.NewTask(0)
    $def.RegistrationInfo.Description = $Spec.Description
    $def.RegistrationInfo.Author      = 'PSM-Distribute'
    $def.Principal.UserId    = 'S-1-5-18'
    $def.Principal.LogonType = 5                  # TASK_LOGON_SERVICE_ACCOUNT
    $def.Principal.RunLevel  = $Spec.RunLevel
    $def.Settings.Enabled                    = $true
    $def.Settings.StartWhenAvailable         = $true   # missed 03:00 (server off) -> run at the next start
    $def.Settings.DisallowStartIfOnBatteries = $false
    $def.Settings.StopIfGoingOnBatteries     = $false
    $def.Settings.ExecutionTimeLimit         = 'PT30M'
    $def.Settings.MultipleInstances          = 2       # TASK_INSTANCES_IGNORE_NEW
    $boot = $def.Triggers.Create(8)
    $boot.Delay = $Spec.BootDelay
    $daily = $def.Triggers.Create(2)
    $daily.StartBoundary = "2026-01-01T$($Spec.DailyAt):00"
    $daily.DaysInterval  = 1
    $action = $def.Actions.Create(0)
    $action.Path      = $Spec.Execute
    $action.Arguments = $Spec.Arguments
    [void]$Service.GetFolder('\').RegisterTaskDefinition($Name, $def, 6, 'SYSTEM', $null, 5)
}

function ConvertTo-PSMAdminSharePath {
    # 'C:\Program Files\X' on <server> -> '\\<server>\C$\Program Files\X'
    param([Parameter(Mandatory)] [string] $ComputerName, [Parameter(Mandatory)] [string] $LocalPath)
    if ($LocalPath -notmatch '^([A-Za-z]):\\(.*)$') { throw "Not a local absolute path: $LocalPath" }
    return '\\{0}\{1}$\{2}' -f $ComputerName, $Matches[1].ToUpperInvariant(), $Matches[2]
}

function Get-PSMShareRoot {
    # '\\srv\C$\Program Files\X' -> '\\srv\C$'
    param([Parameter(Mandatory)] [string] $Path)
    $m = [regex]::Match($Path, '^\\\\[^\\]+\\[^\\]+')
    if (-not $m.Success) { throw "Not a UNC path: $Path" }
    return $m.Value
}

function Assert-PSMAdminShare {
    # The admin share answers with the current SMB session (else: no access, or no 445 flow).
    param([Parameter(Mandatory)] [string] $ShareRoot)
    if (-not (Test-Path -LiteralPath $ShareRoot)) { throw "admin share not accessible: $ShareRoot (rights, or SMB/445 flow)" }
}

function Open-PSMAdminShare {
    <#
        Authenticated SMB session to \\<server>\<X>$ for the given credential
        (same method as the source push: New-PSDrive, no password on a command
        line). Returns the PSDrive to remove, or $null for the current session.
    #>
    param([Parameter(Mandatory)] [string] $ShareRoot, [pscredential] $Credential)
    if (-not $Credential) { return $null }
    # A previous attempt under another identity leaves an SMB session that
    # makes Windows refuse a second one (error 1219): best-effort cleanup.
    try { $null = & cmd.exe /c "net use ""$ShareRoot"" /delete /y >nul 2>&1" } catch { }
    $name = 'PSMTASK' + ([guid]::NewGuid().ToString('N').Substring(0, 6))
    return New-PSDrive -Name $name -PSProvider FileSystem -Root $ShareRoot -Credential $Credential -Scope Global -ErrorAction Stop
}

function Sync-PSMRemoteFile {
    <#
        Copies $LocalFile to the folder $RemoteDir (UNC) when missing or
        different (SHA-256). Returns OK, CHANGED, or WOULD CHANGE (-WhatIf).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)] [string] $LocalFile, [Parameter(Mandatory)] [string] $RemoteDir)
    $remoteFile = Join-Path $RemoteDir (Split-Path $LocalFile -Leaf)
    $want = (Get-FileHash -LiteralPath $LocalFile -Algorithm SHA256).Hash
    if ((Test-Path -LiteralPath $remoteFile) -and (Get-FileHash -LiteralPath $remoteFile -Algorithm SHA256).Hash -eq $want) {
        return 'OK'
    }
    if (-not $PSCmdlet.ShouldProcess($remoteFile, 'copy')) { return 'WOULD CHANGE' }
    if (-not (Test-Path -LiteralPath $RemoteDir)) { New-Item -ItemType Directory -Path $RemoteDir -Force | Out-Null }
    Copy-Item -LiteralPath $LocalFile -Destination $remoteFile -Force
    if ((Get-FileHash -LiteralPath $remoteFile -Algorithm SHA256).Hash -ne $want) { throw "copy of $remoteFile not verified (hash differs)." }
    return 'CHANGED'
}

function Test-PSMUnreachableError {
    <#
        $true when the error is about the NETWORK (RPC server unavailable,
        network path not found, name unknown): another credential would not
        help, the credential cascade stops there.
    #>
    param([Parameter(Mandatory)] [string] $Message)
    return [bool]($Message -match '0x800706BA|RPC server is unavailable|network path was not found|network name cannot be found|No such host|0x80070035|0x800706D9')
}

function Format-PSMTaskResult {
    # Readable last result of a task (LastTaskResult).
    param([int64] $Code)
    switch ($Code) {
        0          { return 'OK' }
        1          { return 'file(s) left blocked or error (see the log on the server)' }
        267011     { return 'never run yet' }       # 0x41303
        267009     { return 'running' }             # 0x41301
        default    { return ('0x{0:X8}' -f ([int64]$Code -band 0xFFFFFFFF)) }
    }
}

Export-ModuleMember -Function Get-PSMRepairTaskSpec, ConvertTo-PSMTaskSnapshot, Compare-PSMTaskSpec, `
    Split-PSMAccountName, Connect-PSMTaskScheduler, Get-PSMScheduledTask, Register-PSMRepairTask, `
    ConvertTo-PSMAdminSharePath, Get-PSMShareRoot, Assert-PSMAdminShare, Open-PSMAdminShare, Sync-PSMRemoteFile, Test-PSMUnreachableError, `
    Format-PSMTaskResult
