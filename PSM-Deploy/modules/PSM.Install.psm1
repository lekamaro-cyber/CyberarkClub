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
    # Dossier d'install / enregistrements derives de la SOURCE UNIQUE Install.InstallDir
    # et injectes dans une copie de InstallationConfig.xml (media intact). Ces deux champs
    # sont "possedes" par InstallDir/RecordingDir : passes en ExtraInjections, ils priment
    # sur un eventuel doublon dans Install.Injections.Installation (a ne pas resaisir la).
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
    # NB : les comptes de session PSMConnect/PSMAdminConnect ne se configurent PAS
    # ici (PostInstallationConfig.xml n'a aucun parametre pour eux) mais cote
    # Hardening (Set-PSMConnectAccounts -> variables de PSMHardening.ps1 /
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
