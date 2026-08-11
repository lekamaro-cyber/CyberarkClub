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

Export-ModuleMember -Function Invoke-PSMInstall, Invoke-PSMPostInstall, Test-PSMInstalled
