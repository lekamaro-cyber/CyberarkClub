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
    $stage = Resolve-PSMStageConfig -Settings $Settings -SourcesRoot $SourcesRoot -StageKey 'Installation'
    return Invoke-PSMStage -StageName 'Installation' `
                           -ExecuteStagePath $stage.ExecuteStage `
                           -ConfigFilePath   $stage.ConfigFilePath
}

function Invoke-PSMPostInstall {
    <#
        Stage PostInstallation. Injecte (si fournis par la zone) les comptes de
        session PSM PSMConnect / PSMAdminConnect (comptes de DOMAINE) dans une COPIE
        de PostInstallationConfig.xml -> media intact, aucune edition manuelle du XML.
        Les mots de passe ne sont PAS injectes (geres dans le Safe PSM cote Vault).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        $ZoneConfig     # comptes PSMConnect/PSMAdminConnect de la zone (facultatif)
    )
    $extra = @{}
    if ($ZoneConfig) {
        $pi   = $Settings.PostInstallation
        $attr = if ($pi -and $pi.UserNameAttribute) { $pi.UserNameAttribute } else { 'Value' }

        $accountMap = @{
            PSMConnectUserName      = if ($pi) { $pi.PSMConnectXPath }      else { $null }
            PSMAdminConnectUserName = if ($pi) { $pi.PSMAdminConnectXPath } else { $null }
        }
        foreach ($zoneKey in $accountMap.Keys) {
            $userName = Get-PSMConfigValue -Config $ZoneConfig -Key $zoneKey
            if (-not $userName) { continue }
            $xpath = $accountMap[$zoneKey]
            if (-not $xpath) {
                throw "settings.psd1 : PostInstallation XPath manquant pour '$zoneKey' (zone fournit '$userName')."
            }
            $extra[$xpath] = @{ Attribute = $attr; Value = $userName }
        }
    }

    $stage = Resolve-PSMStageConfig -Settings $Settings -SourcesRoot $SourcesRoot `
                -StageKey 'PostInstallation' -ExtraInjections $extra
    return Invoke-PSMStage -StageName 'PostInstallation' `
                           -ExecuteStagePath $stage.ExecuteStage `
                           -ConfigFilePath   $stage.ConfigFilePath
}

Export-ModuleMember -Function Invoke-PSMInstall, Invoke-PSMPostInstall, Test-PSMInstalled
