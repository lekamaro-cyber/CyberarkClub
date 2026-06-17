<#
.SYNOPSIS
    Phase "Logiciels additionnels" : installation generique pilotee par config.

.DESCRIPTION
    Chaque application est decrite dans software.psd1 par :
      - Name          : libelle
      - Installer      : chemin de l'installeur (relatif au dossier sources)
      - Arguments      : arguments d'installation silencieuse
      - DetectTest     : scriptblock renvoyant $true si deja installe (idempotence)
    Le PSM "couvre tout" ; ces binaires sont les clients/outils ajoutes ensuite.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-PSMSoftware {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $SoftwareList,
        [Parameter(Mandatory)] [string] $SourcesRoot
    )

    foreach ($app in $SoftwareList) {
        $detect = [scriptblock]::Create($app.DetectTest)
        Invoke-IdempotentStep -Name "Logiciel : $($app.Name)" `
            -Test   $detect `
            -Action {
                $installer = Join-Path $SourcesRoot $app.Installer
                if (-not (Test-Path $installer)) {
                    throw "Installeur introuvable pour '$($app.Name)' : $installer"
                }
                Write-PSMLog -Level INFO -Message "Installation de $($app.Name)..."
                $p = Start-Process -FilePath $installer -ArgumentList $app.Arguments `
                        -Wait -PassThru -NoNewWindow
                if ($p.ExitCode -ne 0 -and $app.SuccessExitCodes -notcontains $p.ExitCode) {
                    throw "$($app.Name) : code de sortie $($p.ExitCode)."
                }
            }
    }
}

Export-ModuleMember -Function Invoke-PSMSoftware
