<#
.SYNOPSIS
    PSM "Installation" and "PostInstallation" phases: driving the CyberArk
    stages (Execute-Stage.ps1) through the PSM.Stages engine.

.DESCRIPTION
    We do not install anything ourselves: we run the CyberArk framework stages
    (Installation = silent setup via PSMInstallationTemplate.iss;
    PostInstallation = PSMConnect/PSMAdminConnect configuration, etc.).
    Idempotency is ensured at two levels: our phase tracking (progress.json)
    and each CyberArk step's PreCheck (already-done steps are skipped).

    Each function returns the Invoke-PSMStage result object
    ({ Succeeded, RestartRequired, LogPath, ... }); the orchestrator handles the reboot.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-PSMInstalled {
    # Detection: presence of the PSM service (used by the validation phase).
    param([string] $ExpectedVersion)
    $svc = Get-Service -Name 'CyberArk Privileged Session Manager' -ErrorAction SilentlyContinue
    return [bool]$svc
}

function Invoke-PSMInstall {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot
    )
    # Install / recordings folders derived from the SINGLE SOURCE Install.InstallDir
    # and injected into a copy of InstallationConfig.xml (media intact). These two
    # fields are "owned" by InstallDir/RecordingDir: passed as ExtraInjections, they
    # win over a possible duplicate in Install.Injections.Installation (do not
    # re-enter them there).
    $paths = Get-PSMInstallPaths -Settings $Settings
    $extra = @{
        "//Parameter[@Name='InstallationDirectory']" = @{ Attribute = 'Value'; Value = $paths.InstallDir }
        "//Parameter[@Name='RecordingDirectory']"    = @{ Attribute = 'Value'; Value = $paths.RecordingDir }
    }
    $stage = Resolve-PSMStageConfig -Settings $Settings -SourcesRoot $SourcesRoot `
                -StageKey 'Installation' -ExtraInjections $extra
    return Invoke-PSMStage -StageName 'Installation' `
                           -ExecuteStagePath $stage.ExecuteStage `
                           -ConfigFilePath   $stage.ConfigFilePath
}

function Invoke-PSMPostInstall {
    # NB: the PSMConnect/PSMAdminConnect session accounts are NOT configured here
    # (PostInstallationConfig.xml has no parameter for them) but on the Hardening
    # side (Set-PSMConnectAccounts -> variables of PSMHardening.ps1 /
    # PSMConfigureAppLocker.ps1).
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot
    )
    $stage = Resolve-PSMStageConfig -Settings $Settings -SourcesRoot $SourcesRoot -StageKey 'PostInstallation'
    return Invoke-PSMStage -StageName 'PostInstallation' `
                           -ExecuteStagePath $stage.ExecuteStage `
                           -ConfigFilePath   $stage.ConfigFilePath
}

function Get-PSMServiceExePath {
    # Executable the PSM service runs (CAPSM.exe), read from the service itself:
    # $null when there is no PSM service, '' when its path cannot be read.
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='Cyberark Privileged Session Manager'" -ErrorAction SilentlyContinue
    if (-not $svc) { return $null }
    # PathName: "D:\CyberArk\PSM\CAPSM.exe" [args] (quoted or not).
    $m = [regex]::Match([string]$svc.PathName, '^\s*"?(?<exe>[^"]+?\.exe)')
    if (-not $m.Success -or -not (Test-Path $m.Groups['exe'].Value)) { return '' }
    return $m.Groups['exe'].Value
}

function Get-PSMInstalledVersion {
    <#
        Version of the PSM ALREADY installed on this machine, read from the
        machine itself (never from config): the file version of the executable
        the PSM service runs (CAPSM.exe), whatever its install folder.
        Returns:
          $null         -> no PSM service (fresh machine);
          [version]     -> e.g. 14.0.5.57 / 12.6.x;
          'Unreadable'  -> service present but its version could not be read.
    #>
    $exe = Get-PSMServiceExePath
    if ($null -eq $exe) { return $null }
    if (-not $exe) { return 'Unreadable' }
    $fv = [regex]::Match([string](Get-Item $exe).VersionInfo.FileVersion, '^\d+(\.\d+){1,3}')
    if (-not $fv.Success) { return 'Unreadable' }
    return [version]$fv.Value
}

function Get-PSMInstalledPsmDir {
    <#
        PSM folder of the PSM ALREADY installed (folder of CAPSM.exe), read from
        the service: right on a PSM installed elsewhere than settings.psd1
        Install.InstallDir (e.g. an older PSM in C:\Program Files (x86)\CyberArk\PSM).
        Falls back to the folder derived from settings.psd1 when the service
        path cannot be read; $null when there is no PSM service.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Settings)
    $exe = Get-PSMServiceExePath
    if ($null -eq $exe) { return $null }
    if ($exe) { return Split-Path $exe -Parent }
    return (Get-PSMInstallPaths -Settings $Settings).PsmDir
}

# ---------------------------------------------------------------------------
# Upgrade (-Upgrade): helpers around the CyberArk wizard
# ---------------------------------------------------------------------------

function ConvertTo-PSMFullVersion {
    # '14.0.5' / '14.0.5.57' / '14.00.0005' / [version] -> [version] with 4 parts
    # (missing parts = 0), so that versions of different shapes compare; $null
    # when unreadable.
    param($Value)
    $m = [regex]::Match([string]$Value, '^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?')
    if (-not $m.Success) { return $null }
    $p = @(1..4 | ForEach-Object { if ($m.Groups[$_].Success) { [int]$m.Groups[$_].Value } else { 0 } })
    return [version]::new($p[0], $p[1], $p[2], $p[3])
}

function Get-PSMMediaSetup {
    <#
        PSM installer of the media: the setup.exe under media\PSM that carries a
        product version - the one whose product name mentions the Session
        Manager when several do, otherwise the highest version.
        Returns { Path; Version ([version], 4 parts); Product }. Throws when none.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot
    )
    $mediaPsm = Join-Path $SourcesRoot $Settings.Install.MediaRelativePath
    $cands = @(Get-ChildItem -LiteralPath $mediaPsm -Recurse -File -Filter 'setup.exe' -ErrorAction SilentlyContinue |
        ForEach-Object {
            [pscustomobject]@{ Path = $_.FullName; Version = (ConvertTo-PSMFullVersion $_.VersionInfo.ProductVersion)
                               Product = [string]$_.VersionInfo.ProductName }
        } | Where-Object { $_.Version })
    if (-not $cands) { throw "No setup.exe carrying a product version under $mediaPsm - is the CyberArk media there?" }
    $named = @($cands | Where-Object { $_.Product -match 'Session Manager' })
    $pool  = if ($named) { $named } else { $cands }
    return @($pool | Sort-Object Version -Descending)[0]
}

function Test-PSMPendingReboot {
    # Reasons for a pending reboot (empty = none). Callers wrap in @().
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'roles/features servicing (CBS)' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update' }
    try {
        if ((Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop).GetValue('PendingFileRenameOperations', $null)) {
            $reasons += 'pending file renames'
        }
    }
    catch { }
    return $reasons
}

function Get-PSMOtherSessions {
    # User names of the OTHER sessions open on this machine (active or
    # disconnected), from quser. quser writes "No User exists" on stderr when
    # there is none: read in a Continue scope (PS 5.1 stderr trap). Callers wrap in @().
    try {
        $lines = @(& { $ErrorActionPreference = 'Continue'; & quser.exe 2>&1 } | Where-Object { $_ -is [string] })
    }
    catch { return @() }
    return @($lines | Select-Object -Skip 1 | Where-Object { $_ -notmatch '^\s*>' } |
        ForEach-Object { ($_.Trim() -split '\s+')[0] } |
        Where-Object { $_ -and $_ -ne $env:USERNAME } | Select-Object -Unique)
}

function Wait-PSMInstallerProcesses {
    <#
        Waits until no installer process started since -Since is left. The
        media's setup.exe can return while the InstallShield engine still runs
        (seen on FRPRDSRV10013: the wizard was still "repairing" when the script
        went on). The Windows Installer service itself (msiexec /V) is ignored.
        Returns $false after -TimeoutMinutes (WARN), $true otherwise.
    #>
    param(
        [Parameter(Mandatory)] [datetime] $Since,
        [int] $TimeoutMinutes = 180
    )
    $names     = @('setup.exe', 'ISSetup.exe', 'ISBEW64.exe', 'IDriver.exe', 'msiexec.exe')
    $deadline  = (Get-Date).AddMinutes($TimeoutMinutes)
    $announced = $false
    while ($true) {
        $left = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            ($names -contains $_.Name) -and $_.CreationDate -and ($_.CreationDate -ge $Since) -and
            ([string]$_.CommandLine -notmatch '\s/V(\s|$)') })
        if (-not $left) { return $true }
        if (-not $announced) {
            Write-PSMLog -Level INFO -Message ("Waiting for the installer to finish (" +
                (($left | ForEach-Object { "$($_.Name) #$($_.ProcessId)" }) -join ', ') + ')...')
            $announced = $true
        }
        if ((Get-Date) -gt $deadline) {
            Write-PSMLog -Level WARN -Message "Installer processes still running after $TimeoutMinutes min - going on."
            return $false
        }
        Start-Sleep -Seconds 10
    }
}

function Backup-PSMConfiguration {
    <#
        Copy of the PSM configuration before an upgrade: basic_psm.ini, Vault\
        (cred files, vault.ini) and Hardening\. Next to the PSM folder, out of
        the installer's reach: <InstallDir>\PSM-Backup-<label>-<stamp>, readable
        by Administrators and SYSTEM ONLY (protected ACL set BEFORE the copy, so
        the copied cred files are never more exposed than in the PSM folder).
        Returns the backup folder (also under -WhatIf, nothing created then).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $PsmDir,
        [Parameter(Mandatory)] [string] $Label
    )
    $dest = Join-Path (Split-Path $PsmDir -Parent) ('PSM-Backup-{0}-{1}' -f $Label, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    if (-not $PSCmdlet.ShouldProcess($dest, 'Back up the PSM configuration')) {
        Write-PSMLog -Level INFO -Message "WhatIf: the PSM configuration would be backed up to $dest."
        return $dest
    }
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-32-544', 'S-1-5-18') {   # Administrators, SYSTEM
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier $sid), 'FullControl',
            'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $dest -AclObject $acl

    $jobs = @(
        @{ From = $PsmDir;                         To = $dest;                         What = @('basic_psm.ini') }
        @{ From = (Join-Path $PsmDir 'Vault');     To = (Join-Path $dest 'Vault');     What = @('/E') }
        @{ From = (Join-Path $PsmDir 'Hardening'); To = (Join-Path $dest 'Hardening'); What = @('/E') }
    )
    foreach ($j in $jobs) {
        if (-not (Test-Path -LiteralPath $j.From)) {
            Write-PSMLog -Level WARN -Message "Backup: $($j.From) not found - skipped."
            continue
        }
        # /COPY:DAT: the copies inherit the protected ACL above. Exit code 0-7 = success.
        & robocopy.exe $j.From $j.To @($j.What) /COPY:DAT /R:1 /W:1 /NP /NFL /NDL /NJH /NJS | Out-Null
        if ($LASTEXITCODE -ge 8) {
            throw "Backup of $($j.From) failed (robocopy exit code $LASTEXITCODE) - nothing was upgraded."
        }
    }
    Write-PSMLog -Level OK -Message "PSM configuration backed up to $dest (Administrators/SYSTEM only)."
    return $dest
}

Export-ModuleMember -Function Invoke-PSMInstall, Invoke-PSMPostInstall, Test-PSMInstalled, Get-PSMInstalledVersion, Get-PSMInstalledPsmDir,
    ConvertTo-PSMFullVersion, Get-PSMMediaSetup, Test-PSMPendingReboot, Get-PSMOtherSessions, Backup-PSMConfiguration,
    Wait-PSMInstallerProcesses
