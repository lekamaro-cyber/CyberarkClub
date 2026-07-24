<#
.SYNOPSIS
    Phase "Prerequis OS" : role RD Session Host, licence RDS, .NET, services, registre.

.NOTES
    Chaque action passe par Invoke-IdempotentStep (Test -> Set).
    Renvoie $true si un reboot est requis (installation du role RDS).
    Valeurs reelles (serveur de licence, mode) lues depuis settings.psd1.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-PSMPrereqs {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings
    )

    $rebootRequired   = $false
    $script:__reboot  = $false

    # --- Role RD Session Host -------------------------------------------------
    Invoke-IdempotentStep -Name 'Role RD Session Host' `
        -Test   { (Get-WindowsFeature -Name RDS-RD-Server).Installed } `
        -Action {
            $r = Install-WindowsFeature -Name RDS-RD-Server -IncludeManagementTools
            if ($r.RestartNeeded -ne 'No') { $script:__reboot = $true }
        }
    if ($script:__reboot) { $rebootRequired = $true; $script:__reboot = $false }

    # --- Mode de licence RDS + serveur de licence -----------------------------
    # TODO (deploiement) : valider les cles registre selon la version d'OS.
    $licMode = $Settings.Rds.LicenseMode          # 'PerUser' | 'PerDevice'
    # Accepte un tableau OU une chaine unique ; on normalise en liste ordonnee.
    $licSrvList = @($Settings.Rds.LicenseServers) | Where-Object { $_ }
    $licSrvStr  = $licSrvList -join ','            # valeur registre = liste separee par des virgules
    $rdKey      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

    Invoke-IdempotentStep -Name "Mode licence RDS ($licMode)" `
        -Test   {
            $modeVal = if ($licMode -eq 'PerUser') { 4 } else { 2 }
            (Get-ItemProperty -Path $rdKey -Name 'LicensingMode' -ErrorAction SilentlyContinue).LicensingMode -eq $modeVal
        } `
        -Action {
            if (-not (Test-Path $rdKey)) { New-Item -Path $rdKey -Force | Out-Null }
            $modeVal = if ($licMode -eq 'PerUser') { 4 } else { 2 }
            Set-ItemProperty -Path $rdKey -Name 'LicensingMode' -Value $modeVal -Type DWord
        }

    Invoke-IdempotentStep -Name "Serveur(s) de licence RDS ($licSrvStr)" `
        -Test   {
            $cur = (Get-ItemProperty -Path "$rdKey" -Name 'LicenseServers' -ErrorAction SilentlyContinue).LicenseServers
            # Comparaison insensible aux espaces autour des virgules.
            ($cur -replace '\s*,\s*', ',') -eq $licSrvStr
        } `
        -Action {
            if (-not (Test-Path $rdKey)) { New-Item -Path $rdKey -Force | Out-Null }
            Set-ItemProperty -Path $rdKey -Name 'LicenseServers' -Value $licSrvStr -Type String
        }

    # --- .NET / fonctionnalites requises (TODO: completer selon version PSM) --
    # Invoke-IdempotentStep -Name '.NET Framework 4.x' -Test {...} -Action {...}

    return $rebootRequired
}

Export-ModuleMember -Function Invoke-PSMPrereqs
