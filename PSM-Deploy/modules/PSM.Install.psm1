<#
.SYNOPSIS
    Phases "Installation" et "PostInstallation" du PSM : pilotage des stages
    CyberArk (Execute-Stage.ps1) via le moteur PSM.Stages.

.DESCRIPTION
    On n'installe pas nous-memes : on lance les stages du framework CyberArk
    (Installation = setup silencieux via PSMInstallationTemplate.iss ;
    PostInstallation = configuration PSMConnect/PSMAdminConnect, etc.).
    L'idempotence est assuree a deux niveaux : notre suivi de phases (progress.json)
    et le PreCheck de chaque step CyberArk (les steps deja faits se sautent).

    Chaque fonction renvoie l'objet resultat de Invoke-PSMStage
    ({ Succeeded, RestartRequired, LogPath, ... }) ; l'orchestrateur gere le reboot.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-PSMInstalled {
    # Detection : presence du service PSM (utilisee par la phase de validation).
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
    $paths = Get-PSMStagePaths -Settings $Settings -SourcesRoot $SourcesRoot -StageKey 'Installation'
    return Invoke-PSMStage -StageName 'Installation' `
                           -ExecuteStagePath $paths.ExecuteStage `
                           -ConfigFilePath   $paths.Config
}

function Invoke-PSMPostInstall {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot
    )
    $paths = Get-PSMStagePaths -Settings $Settings -SourcesRoot $SourcesRoot -StageKey 'PostInstallation'
    return Invoke-PSMStage -StageName 'PostInstallation' `
                           -ExecuteStagePath $paths.ExecuteStage `
                           -ConfigFilePath   $paths.Config
}

Export-ModuleMember -Function Invoke-PSMInstall, Invoke-PSMPostInstall, Test-PSMInstalled
