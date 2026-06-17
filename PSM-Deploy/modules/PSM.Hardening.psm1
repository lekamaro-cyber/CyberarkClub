<#
.SYNOPSIS
    Phase "Hardening" : durcissement CyberArk complet + politique AppLocker maitrisee.

.DESCRIPTION
    - Hardening : execution de PSMHardening.ps1 fourni par CyberArk.
    - AppLocker : on N'UTILISE PAS la politique par defaut telle quelle ; on
      applique une politique CONTROLEE, versionnee avec ce depot
      (applocker/PSMConfigureAppLocker.xml), afin de garder la main et d'y
      inclure les binaires additionnels installes a la phase precedente.

    Important : toute application ajoutee via software.psd1 doit avoir sa regle
    correspondante dans la politique AppLocker embarquee, sinon elle sera bloquee.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-PSMHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot
    )

    $hardeningRoot = Join-Path $SourcesRoot $Settings.Hardening.ScriptsRelativePath
    $appLockerXml  = Join-Path $SourcesRoot 'applocker\PSMConfigureAppLocker.xml'

    # --- Hardening principal --------------------------------------------------
    Invoke-IdempotentStep -Name 'Hardening CyberArk (PSMHardening)' `
        -Test   {
            # TODO (deploiement) : marqueur de hardening deja applique
            # (ex: cle registre/marqueur fichier pose par le script CyberArk).
            $false
        } `
        -Action {
            $script = Join-Path $hardeningRoot 'PSMHardening.ps1'
            if (-not (Test-Path $script)) {
                throw "PSMHardening.ps1 introuvable : $script"
            }
            # & $script   # TODO (deploiement) : decommenter au branchement reel
            throw "STUB : brancher ici l'execution de PSMHardening.ps1."
        }

    # --- Politique AppLocker controlee ---------------------------------------
    Invoke-IdempotentStep -Name 'Politique AppLocker controlee' `
        -Test   {
            # TODO (deploiement) : comparer la politique effective au XML embarque
            # (hash du XML pose en marqueur) pour rester idempotent.
            $false
        } `
        -Action {
            if (-not (Test-Path $appLockerXml)) {
                throw "Politique AppLocker introuvable : $appLockerXml"
            }
            # PSMConfigureAppLocker.ps1 consomme un XML de configuration.
            # On lui fournit NOTRE Xml controle plutot que celui par defaut.
            # TODO (deploiement) : appeler PSMConfigureAppLocker.ps1 avec $appLockerXml.
            throw "STUB : appliquer la politique AppLocker embarquee ($appLockerXml)."
        }
}

Export-ModuleMember -Function Invoke-PSMHardening
