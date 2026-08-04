<#
.SYNOPSIS
    Phase "Hardening" : stage CyberArk "Hardening" via Execute-Stage.ps1.

.DESCRIPTION
    Le stage Hardening applique le durcissement CyberArk et les regles AppLocker
    (RunTheHardeningScript, SetupAppLockerRules...). La personnalisation "maison"
    se fait dans HardeningConfig.xml et les CSV du dossier Hardening du media
    (PSMConfigureRemoteSessionControl.csv, PSMHideDrives.csv, etc.), remplis par
    l'equipe - pas de politique AppLocker separee a maintenir de notre cote.

    Renvoie l'objet resultat de Invoke-PSMStage ; l'orchestrateur gere le reboot.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-PSMHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot
    )
    $paths = Get-PSMStagePaths -Settings $Settings -SourcesRoot $SourcesRoot -StageKey 'Hardening'
    return Invoke-PSMStage -StageName 'Hardening' `
                           -ExecuteStagePath $paths.ExecuteStage `
                           -ConfigFilePath   $paths.Config
}

Export-ModuleMember -Function Invoke-PSMHardening
