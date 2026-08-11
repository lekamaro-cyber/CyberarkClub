<#
.SYNOPSIS
    Common functions for the PSM deployment: idempotency, logging,
    secret masking, state machine / resume after reboot, confirmations.

.NOTES
    Foundation module reused by every phase.
    Ansible-style idempotency model: every action = Test -> Set,
    reported as OK / CHANGED / FAILED.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Module-internal state (module scope)
# ---------------------------------------------------------------------------
$script:Secrets       = New-Object System.Collections.Generic.List[string]
$script:StepResults   = New-Object System.Collections.Generic.List[object]
$script:LogTextPath   = $null
$script:LogJsonPath   = $null
$script:StatePath     = $null

# ---------------------------------------------------------------------------
# Logging + secret masking
# ---------------------------------------------------------------------------

function Initialize-PSMLogging {
    <#
        Prepares the log files (text transcript + structured JSON log).
        Call once at orchestrator startup.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $LogDirectory
    )
    if (-not (Test-Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:LogTextPath = Join-Path $LogDirectory "deploy-$stamp.log"
    $script:LogJsonPath = Join-Path $LogDirectory "deploy-$stamp.jsonl"
    Write-PSMLog -Level INFO -Message "Logging initialized ($script:LogTextPath)"
}

function Register-PSMSecret {
    <#
        Registers a sensitive value so that it gets masked in the logs.
        Accepts string or SecureString.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Secret)

    $plain = $null
    if ($Secret -is [securestring]) {
        $plain = [System.Net.NetworkCredential]::new('', $Secret).Password
    }
    else {
        $plain = [string]$Secret
    }
    if (-not [string]::IsNullOrEmpty($plain) -and -not $script:Secrets.Contains($plain)) {
        $script:Secrets.Add($plain)
    }
}

function Protect-PSMMessage {
    # Replaces any value registered as a secret with asterisks.
    param([string] $Message)
    foreach ($s in $script:Secrets) {
        if ($s) { $Message = $Message.Replace($s, '********') }
    }
    return $Message
}

function Write-PSMLog {
    [CmdletBinding()]
    param(
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR', 'OK', 'CHANGED')]
        [string] $Level = 'INFO',
        [Parameter(Mandatory)] [string] $Message
    )
    $safe = Protect-PSMMessage -Message $Message
    $ts   = Get-Date -Format 'o'
    $line = "[{0}] [{1,-7}] {2}" -f $ts, $Level, $safe

    switch ($Level) {
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'WARN'    { Write-Host $line -ForegroundColor Yellow }
        'OK'      { Write-Host $line -ForegroundColor Green }
        'CHANGED' { Write-Host $line -ForegroundColor Cyan }
        'DEBUG'   { Write-Verbose $line }
        default   { Write-Host $line }
    }

    if ($script:LogTextPath) { Add-Content -Path $script:LogTextPath -Value $line }
    if ($script:LogJsonPath) {
        $obj = [ordered]@{ ts = $ts; level = $Level; message = $safe }
        Add-Content -Path $script:LogJsonPath -Value ($obj | ConvertTo-Json -Compress)
    }
}

# ---------------------------------------------------------------------------
# Elevation
# ---------------------------------------------------------------------------

function Test-PSMElevation {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [Security.Principal.WindowsPrincipal]::new($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-PSMElevation {
    if (-not (Test-PSMElevation)) {
        throw "The script must run with administrator (elevated) rights."
    }
    Write-PSMLog -Level OK -Message "Administrator context confirmed."
}

# ---------------------------------------------------------------------------
# Idempotency core: Test -> Set
# ---------------------------------------------------------------------------

function Invoke-IdempotentStep {
    <#
        Runs an idempotent step.
        -Test   : scriptblock returning $true when the target state is already met.
        -Action : scriptblock applying the target state (only when Test = $false).
        Honors -WhatIf / -Confirm via ShouldProcess.
        Returns: 'OK' (already compliant), 'CHANGED' (applied), 'WHATIF', 'FAILED'.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [string]      $Name,
        [Parameter(Mandatory)] [scriptblock] $Test,
        [Parameter(Mandatory)] [scriptblock] $Action
    )

    $status = 'OK'
    try {
        if (& $Test) {
            Write-PSMLog -Level OK -Message "[$Name] already compliant."
            $status = 'OK'
        }
        elseif ($PSCmdlet.ShouldProcess($Name, 'Apply')) {
            & $Action
            Write-PSMLog -Level CHANGED -Message "[$Name] applied."
            $status = 'CHANGED'
        }
        else {
            Write-PSMLog -Level INFO -Message "[$Name] not compliant -> would be changed (WhatIf)."
            $status = 'WHATIF'
        }
    }
    catch {
        Write-PSMLog -Level ERROR -Message "[$Name] failed: $($_.Exception.Message)"
        $status = 'FAILED'
        $script:StepResults.Add([pscustomobject]@{ Step = $Name; Status = $status })
        throw   # fail-fast (see spec)
    }

    $script:StepResults.Add([pscustomobject]@{ Step = $Name; Status = $status })
    return $status
}

function Write-PSMSummary {
    # Ansible-style final summary (Step | Status).
    Write-Host ''
    Write-Host '====================== SUMMARY ========================' -ForegroundColor White
    foreach ($r in $script:StepResults) {
        $color = switch ($r.Status) {
            'OK'      { 'Green' }
            'CHANGED' { 'Cyan' }
            'WHATIF'  { 'Yellow' }
            'FAILED'  { 'Red' }
            default   { 'Gray' }
        }
        Write-Host ("  {0,-40} {1}" -f $r.Step, $r.Status) -ForegroundColor $color
    }
    Write-Host '=======================================================' -ForegroundColor White
}

# ---------------------------------------------------------------------------
# State machine / resume after reboot
# ---------------------------------------------------------------------------

function Initialize-PSMState {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $StateDirectory)
    if (-not (Test-Path $StateDirectory)) {
        New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
    }
    $script:StatePath = Join-Path $StateDirectory 'progress.json'
    if (-not (Test-Path $script:StatePath)) {
        @{ completedPhases = @() } | ConvertTo-Json | Set-Content -Path $script:StatePath
    }
}

function Get-PSMConfigValue {
    <#
        Safely reads an OPTIONAL key from a config table (psd1 hashtable or
        pscustomobject) under StrictMode; returns $null when absent.
        Useful for optional keys (e.g. a zone's PSMConnect accounts).
    #>
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [string] $Key
    )
    if ($null -eq $Config) { return $null }
    if ($Config -is [System.Collections.IDictionary]) {
        if ($Config.Contains($Key)) { return $Config[$Key] }
        return $null
    }
    $prop = $Config.PSObject.Properties[$Key]
    if ($prop) { return $prop.Value }
    return $null
}

function Get-PSMInstallPaths {
    <#
        Derives the installation paths from the SINGLE SOURCE Install.InstallDir
        (settings.psd1). Avoids repeating the install folder in several places:
          - InstallDir   : installation folder (injected into InstallationConfig.xml)
          - PsmDir       : <InstallDir>\PSM
          - RecordingDir : Install.RecordingDir when set, otherwise <PsmDir>\Recordings
          - HardeningDir : <PsmDir>\Hardening (PSMHardening.ps1 & co scripts)
        Changing InstallDir once is enough to realign everything.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Settings)

    $install    = Get-PSMConfigValue -Config $Settings -Key 'Install'
    $installDir = Get-PSMConfigValue -Config $install  -Key 'InstallDir'
    if (-not $installDir) { throw "settings.psd1: Install.InstallDir not set (single source of the installation folder)." }

    $psmDir = Join-Path $installDir 'PSM'
    $rec    = Get-PSMConfigValue -Config $install -Key 'RecordingDir'
    if (-not $rec) { $rec = Join-Path $psmDir 'Recordings' }

    return [pscustomobject]@{
        InstallDir   = $installDir
        PsmDir       = $psmDir
        RecordingDir = $rec
        HardeningDir = Join-Path $psmDir 'Hardening'
    }
}

function Test-PSMSettingsDrift {
    <#
        The config (settings.psd1) is copied then hand-edited by the team:
        when the script evolves, a missing key = silently inactive feature
        (e.g. RenameComponents absent -> no renaming, without any error).
        Compares the loaded config against the keys expected by THIS version
        of the script and WARNs when keys are missing. Never blocks.
        Returns the list of missing keys (empty when compliant).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Settings)

    $expected = @(
        'PsmVersion',
        'Rds.LicenseMode', 'Rds.LicenseServers',
        'Install.MediaRelativePath', 'Install.InstallationAutomationSubPath', 'Install.Stages',
        'Install.InstallDir', 'Install.RecordingDir', 'Install.Injections',
        'Registration.VaultAddressXPath', 'Registration.VaultAddressAttribute',
        'Registration.RenameComponents', 'Registration.AppUserPattern', 'Registration.GwUserPattern',
        'Registration.RenameServerIds',
        'Hardening.NonBlocking', 'Hardening.HardeningDir', 'Hardening.ScriptAccountVariables',
        'Paths.State', 'Paths.Logs'
    )
    $missing = @()
    foreach ($keyPath in $expected) {
        $node = $Settings
        foreach ($part in $keyPath.Split('.')) {
            $node = Get-PSMConfigValue -Config $node -Key $part
            if ($null -eq $node) { break }
        }
        if ($null -eq $node) { $missing += $keyPath }
    }
    if ($missing) {
        Write-PSMLog -Level WARN -Message ("settings.psd1: key(s) MISSING compared to this version of the script -> " +
            ($missing -join ', ') + ". The corresponding features are INACTIVE: copy these keys over " +
            "from the branch's config\settings.psd1 (keeping your local values).")
    }
    return $missing
}

function Test-PSMDomainAccount {
    <#
        Checks that a "DOMAIN\user" account resolves to a SID on Windows.
        Catches upfront (PreFlight) the unresolvable accounts that would make the
        Hardening fail much later ("identity references could not be translated") -
        typical trap: sAMAccountName truncated to 20 characters, different from the
        Name/CN displayed in the AD console.
    #>
    param([Parameter(Mandatory)] [string] $Account)
    try {
        [void]([System.Security.Principal.NTAccount]$Account).Translate([System.Security.Principal.SecurityIdentifier])
        return $true
    }
    catch { return $false }
}

function Test-PSMLocalAdminMember {
    <#
        Checks whether a "DOMAIN\user" account is a member of the machine's local
        Administrators group, DIRECTLY OR TRANSITIVELY (e.g. through a per-server
        AD ACL group placed in the local group). Comparison by SID.
        Returns $true / $false, or $null when the membership could not be
        evaluated (domain unreachable, unresolvable foreign SIDs...).

        Used at PreFlight to confirm the AD provisioning done ahead of time:
          - PSMAdminConnect MUST be a local Administrator (live session
            monitoring/shadowing requires it);
          - PSMConnect must NOT be one (user sessions run under it).
    #>
    param([Parameter(Mandatory)] [string] $Account)
    try {
        $sid = ([System.Security.Principal.NTAccount]$Account).Translate([System.Security.Principal.SecurityIdentifier]).Value
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $ctx = [System.DirectoryServices.AccountManagement.PrincipalContext]::new(
                   [System.DirectoryServices.AccountManagement.ContextType]::Machine)
        $grp = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ctx, 'Administrators')
        if (-not $grp) { return $null }
        foreach ($m in $grp.GetMembers($true)) {   # $true = recursive (expands domain groups)
            if ($m.Sid.Value -eq $sid) { return $true }
        }
        return $false
    }
    catch { return $null }
}

function Get-PSMStateDir {
    # Returns the state folder (parent of progress.json), set by Initialize-PSMState.
    # Used by the stage engine to write the patched copies of the *Config.xml files.
    if (-not $script:StatePath) {
        throw "State not initialized: call Initialize-PSMState before Get-PSMStateDir."
    }
    return Split-Path $script:StatePath -Parent
}

function Reset-PSMState {
    <#
        Resets the deployment state: empty progress.json (no phase completed)
        + purges the patched copies of the *Config.xml files (regenerated on the
        next run). Touches NEITHER the media, NOR the logs, NOR the machine.
        Used to "start from scratch" after uninstalling/cleaning the PSM, without
        letting stale state skip phases (e.g. the actual Installation).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not $script:StatePath) {
        throw "State not initialized: call Initialize-PSMState before Reset-PSMState."
    }
    if ($PSCmdlet.ShouldProcess($script:StatePath, 'Reset the state (progress.json)')) {
        @{ completedPhases = @() } | ConvertTo-Json | Set-Content -Path $script:StatePath
        $configDir = Join-Path (Split-Path $script:StatePath -Parent) 'config'
        if (Test-Path $configDir) { Remove-Item -Path $configDir -Recurse -Force }
        Write-PSMLog -Level WARN -Message "State reset: the deployment will restart from the first phase (PreFlight)."
    }
}

function Test-PSMPhaseComplete {
    param([Parameter(Mandatory)] [string] $Phase)
    $state = Get-Content $script:StatePath -Raw | ConvertFrom-Json
    return ($state.completedPhases -contains $Phase)
}

function Set-PSMPhaseComplete {
    param([Parameter(Mandatory)] [string] $Phase)
    $state = Get-Content $script:StatePath -Raw | ConvertFrom-Json
    $list  = @($state.completedPhases) + $Phase | Select-Object -Unique
    $state.completedPhases = $list
    $state | ConvertTo-Json | Set-Content -Path $script:StatePath
    Write-PSMLog -Level INFO -Message "Phase '$Phase' marked as completed."
}

function Get-PSMStateValue {
    # Reads a free-form value from the state (progress.json); $null when absent.
    param([Parameter(Mandatory)] [string] $Name)
    $state = Get-Content $script:StatePath -Raw | ConvertFrom-Json
    if ($state.PSObject.Properties.Name -contains $Name) { return $state.$Name }
    return $null
}

function Set-PSMStateValue {
    # Persists a free-form value into the state (progress.json), leaving other keys untouched.
    param([Parameter(Mandatory)] [string] $Name, $Value)
    $state = Get-Content $script:StatePath -Raw | ConvertFrom-Json
    if ($state.PSObject.Properties.Name -contains $Name) {
        $state.$Name = $Value
    }
    else {
        $state | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
    $state | ConvertTo-Json | Set-Content -Path $script:StatePath
}

function Register-PSMResumeTask {
    <#
        Creates a scheduled task that relaunches the orchestrator AT LOGON of the
        installing admin (supervised resume), inside THEIR interactive session:
        prompts (PVWA Get-Credential) work and no secret is stored.
        Automatically resumes at the first phase not yet completed.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $ScriptPath,
        [Parameter(Mandatory)] [string] $Zone,
        [string] $User     = [Security.Principal.WindowsIdentity]::GetCurrent().Name,
        [string] $TaskName = 'PSM-Deploy-Resume'
    )
    if ($PSCmdlet.ShouldProcess($TaskName, 'Create resume task (AtLogOn)')) {
        # -Zone is passed explicitly (otherwise the mandatory parameter blocks after reboot).
        $argument  = "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$ScriptPath`" -Resume -Zone $Zone"
        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argument
        $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $User
        $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Principal $principal -Force | Out-Null
        Write-PSMLog -Level INFO -Message "Resume task '$TaskName' registered (AtLogOn, user $User, zone $Zone)."
    }
}

function Unregister-PSMResumeTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([string] $TaskName = 'PSM-Deploy-Resume')
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        if ($PSCmdlet.ShouldProcess($TaskName, 'Remove resume task')) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-PSMLog -Level INFO -Message "Resume task '$TaskName' removed."
        }
    }
}

# ---------------------------------------------------------------------------
# Interactive zone confirmation (blunder guard: wrong zone = wrong Vault)
# ---------------------------------------------------------------------------

function Confirm-PSMZone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $ZoneConfig,
        [switch] $NonInteractive
    )
    Write-Host ''
    Write-Host "Target zone : $($ZoneConfig.Name)"        -ForegroundColor Yellow
    Write-Host "  PVWA     : $($ZoneConfig.PvwaUrl)"
    Write-Host "  Auth     : $($ZoneConfig.PvwaAuthMethod)"
    Write-Host "  Hostname : $env:COMPUTERNAME"
    if ($NonInteractive) {
        Write-PSMLog -Level WARN -Message "Non-interactive mode: zone '$($ZoneConfig.Name)' accepted without confirmation."
        return
    }
    $answer = Read-Host "Confirm deployment on this zone? (type YES)"
    if ($answer -ne 'YES') {
        throw "Zone not confirmed by the operator. Aborting."
    }
    Write-PSMLog -Level OK -Message "Zone '$($ZoneConfig.Name)' confirmed."
}

Export-ModuleMember -Function *-PSM*, Invoke-IdempotentStep
