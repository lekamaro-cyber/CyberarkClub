<#
.SYNOPSIS
    "Additional software" phase: generic config-driven installation.

.DESCRIPTION
    Each application is described in software.psd1 by:
      - Name           : label
      - Installer      : installer path (relative to the sources folder)
      - Arguments      : silent-install arguments
      - DetectTest     : scriptblock returning $true when already installed (idempotency)
    The PSM "covers everything"; these binaries are the clients/tools added afterwards.
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
        Invoke-IdempotentStep -Name "Software: $($app.Name)" `
            -Test   $detect `
            -Action {
                $installer = Join-Path $SourcesRoot $app.Installer
                if (-not (Test-Path $installer)) {
                    throw "Installer not found for '$($app.Name)': $installer"
                }
                Write-PSMLog -Level INFO -Message "Installing $($app.Name)..."
                $p = Start-Process -FilePath $installer -ArgumentList $app.Arguments `
                        -Wait -PassThru -NoNewWindow
                if ($p.ExitCode -ne 0 -and $app.SuccessExitCodes -notcontains $p.ExitCode) {
                    throw "$($app.Name): exit code $($p.ExitCode)."
                }
            }
    }
}

Export-ModuleMember -Function Invoke-PSMSoftware
