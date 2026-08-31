<#
.SYNOPSIS
    "Additional software" phase: generic config-driven installation.

.DESCRIPTION
    Each application is described in software.psd1 by ONE of two shapes:

    INSTALLER mode (silent MSI/EXE):
      - Name           : label
      - Installer      : installer path (relative to the sources folder)
      - Arguments      : silent-install arguments
      - DetectTest     : scriptblock returning $true when already installed (idempotency)

    COPY mode (portable apps: no installer, just files/folders to drop):
      - Name           : label
      - Source         : file OR folder, relative to the sources folder
      - Destination    : absolute path on the server (created if needed; a folder
                         source has its CONTENT copied into it)
      - DetectTest     : optional here - defaults to Test-Path <Destination>.
                         Provide a finer test (e.g. on a copied .exe) when the
                         destination folder can pre-exist.

    Common to both:
      - Optional       : $true -> when the app is NOT installed and its
                         installer/source is not staged, WARN and skip instead of
                         failing (the same sources tree then works with or
                         without the media staged).
    The PSM "covers everything"; these binaries are the clients/tools added afterwards.
    REMINDER: copied .exe binaries must be allowed in the AppLocker policy too.
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
        # Entry shape: INSTALLER mode (Installer+Arguments) or COPY mode
        # (Source+Destination) - exactly one of the two. ($app['Key'] indexing:
        # a missing key is simply $null, StrictMode-safe.)
        $isCopy = [bool]$app['Source']
        if ($isCopy -eq [bool]$app['Installer']) {
            throw ("software.psd1: entry '$($app.Name)' must declare EITHER 'Installer' (silent install) " +
                   "OR 'Source' + 'Destination' (file copy), not both/neither.")
        }
        if ($isCopy -and -not $app['Destination']) {
            throw "software.psd1: entry '$($app.Name)': 'Destination' is required with 'Source' (copy mode)."
        }
        # Payload staged under the sources tree (installer file, or file/folder to copy).
        $payload = Join-Path $SourcesRoot $(if ($isCopy) { $app.Source } else { $app.Installer })

        # DetectTest: mandatory in installer mode; in copy mode it defaults to
        # the destination existing (provide a finer test - e.g. on a copied
        # .exe - when the destination folder can pre-exist).
        $detectExpr = $app['DetectTest']
        if (-not $detectExpr) {
            if (-not $isCopy) { throw "software.psd1: entry '$($app.Name)': 'DetectTest' is required (idempotency)." }
            $detectExpr = "(Test-Path '$($app.Destination)')"
        }
        $detect = [scriptblock]::Create($detectExpr)

        # Optional entry (e.g. test-only tooling): not installed AND payload
        # not staged -> WARN skip, never a deployment failure.
        if ([bool]$app['Optional']) {
            if (-not (Test-Path $payload) -and -not (& $detect)) {
                Write-PSMLog -Level WARN -Message "Software: '$($app.Name)' is optional and its installer/source is not staged ($payload) - skipped."
                continue
            }
        }
        Invoke-IdempotentStep -Name "Software: $($app.Name)" `
            -Test   $detect `
            -Action {
                if (-not (Test-Path $payload)) {
                    if ($isCopy) { throw "Copy source not found for '$($app.Name)': $payload" }
                    throw "Installer not found for '$($app.Name)': $payload"
                }
                if ($isCopy) {
                    # Portable app: plain file copy, no installer involved.
                    $dst = $app.Destination
                    if (-not (Test-Path $dst)) { New-Item -ItemType Directory -Path $dst -Force | Out-Null }
                    if (Test-Path $payload -PathType Container) {
                        Copy-Item -Path (Join-Path $payload '*') -Destination $dst -Recurse -Force
                    }
                    else {
                        Copy-Item -Path $payload -Destination $dst -Force
                    }
                    Write-PSMLog -Level INFO -Message "'$($app.Name)': files copied to $dst."
                    return
                }
                Write-PSMLog -Level INFO -Message "Installing $($app.Name)..."
                if ([System.IO.Path]::GetExtension($payload) -ieq '.msi') {
                    # MSI packages must go through msiexec (launching the .msi
                    # directly does not reliably pass the silent arguments).
                    $p = Start-Process -FilePath 'msiexec.exe' `
                            -ArgumentList "/i `"$payload`" $($app.Arguments)" `
                            -Wait -PassThru -NoNewWindow
                }
                else {
                    $p = Start-Process -FilePath $payload -ArgumentList $app.Arguments `
                            -Wait -PassThru -NoNewWindow
                }
                if ($p.ExitCode -ne 0 -and $app.SuccessExitCodes -notcontains $p.ExitCode) {
                    throw "$($app.Name): exit code $($p.ExitCode)."
                }
            }
    }
}

Export-ModuleMember -Function Invoke-PSMSoftware
