<#
.SYNOPSIS
    Phase "Installation du binaire PSM" via les scripts d'automatisation CyberArk.

.DESCRIPTION
    On s'appuie sur les scripts d'installation automatisee fournis par CyberArk
    (media 12.6 / 14.0). Cette phase est idempotente : si le PSM est deja
    installe (et a la bonne version), elle ne fait rien.

    Le bloc d'installation reel differe legerement entre 12.6 et 14.0 ; il est
    selectionne via settings.psd1 (PsmVersion + chemins).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-PSMInstalled {
    # Detection idempotente : presence du service + (option) version.
    param([string] $ExpectedVersion)
    $svc = Get-Service -Name 'CyberArk Privileged Session Manager' -ErrorAction SilentlyContinue
    if (-not $svc) { return $false }
    # TODO (deploiement) : comparer aussi la version installee a $ExpectedVersion.
    return $true
}

function Invoke-PSMInstall {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot
    )

    $version   = $Settings.PsmVersion
    $mediaPath = Join-Path $SourcesRoot $Settings.Install.MediaRelativePath

    Invoke-IdempotentStep -Name "Installation PSM $version" `
        -Test   { Test-PSMInstalled -ExpectedVersion $version } `
        -Action {
            if (-not (Test-Path $mediaPath)) {
                throw "Media PSM introuvable : $mediaPath (deposer le media dans le dossier sources)."
            }
            # ---------------------------------------------------------------
            # TODO (deploiement) : appeler le script d'automatisation CyberArk.
            # Exemple de structure (a adapter au media reel 12.6 / 14.0) :
            #
            #   $auto = Join-Path $mediaPath $Settings.Install.AutomationScript
            #   & $auto @($Settings.Install.AutomationArgs)
            #
            # Les fichiers de reponse (silent) sont a placer dans le media et
            # references via settings.psd1 (Install.ResponseFile).
            # ---------------------------------------------------------------
            throw "STUB : brancher ici le script d'automatisation CyberArk ($version)."
        }
}

Export-ModuleMember -Function Invoke-PSMInstall, Test-PSMInstalled
