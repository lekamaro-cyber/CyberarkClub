<#
.SYNOPSIS
    Phases "prerequis" : stages CyberArk Readiness + Prerequisites (Execute-Stage.ps1)
    + configuration locale de la licence RD Session Host.

.DESCRIPTION
    - Readiness / Prerequisites : pilotes via le framework CyberArk (installation
      du role RDS, .NET, NLA, RDS Security Layer...). Le reboot eventuel est
      signale par restartRequired et gere par l'orchestrateur.
    - Licence RDS : la config du mode + du/des serveur(s) de licence reste de
      notre cote (site-specific), appliquee APRES l'installation du role RDS.
    - Test-PSMLicenseServers : controle de connectivite (utilise en pre-vol).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PSMRegValue {
    <#
        Lecture registre robuste : renvoie la valeur, ou $null si la cle/valeur
        n'existe pas (evite l'exception StrictMode sur une propriete absente).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name
    )
    try {
        $key = Get-Item -Path $Path -ErrorAction Stop
        return $key.GetValue($Name, $null)
    }
    catch {
        return $null
    }
}

function Test-PSMLicenseServers {
    <#
        Controle de connectivite vers le/les serveur(s) de licence RDS.
        Port 135 = RPC endpoint mapper (utilise par le service de licences RDS).
        Non bloquant : journalise OK/WARN et renvoie $true si tous joignables.
    #>
    [CmdletBinding()]
    param(
        [string[]] $Servers,
        [int]      $Port      = 135,
        [int]      $TimeoutMs = 3000
    )
    $allOk = $true
    foreach ($srv in (@($Servers) | Where-Object { $_ })) {
        $ok = $false
        try {
            $client = [System.Net.Sockets.TcpClient]::new()
            $iar    = $client.BeginConnect($srv, $Port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                $client.EndConnect($iar)
                $ok = $client.Connected
            }
            $client.Close()
        }
        catch { $ok = $false }

        if ($ok) {
            Write-PSMLog -Level OK   -Message "Serveur de licence RDS joignable : $srv (TCP $Port)."
        }
        else {
            Write-PSMLog -Level WARN -Message "Serveur de licence RDS INJOIGNABLE : $srv (TCP $Port) - verifier DNS/pare-feu."
            $allOk = $false
        }
    }
    return $allOk
}

function Invoke-PSMReadiness {
    # Stage CyberArk "Readiness" (CheckOS, CheckSystemRequirements, .NET, domaine...).
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot
    )
    $stage = Resolve-PSMStageConfig -Settings $Settings -SourcesRoot $SourcesRoot -StageKey 'Readiness'
    return Invoke-PSMStage -StageName 'Readiness' `
                           -ExecuteStagePath $stage.ExecuteStage `
                           -ConfigFilePath   $stage.ConfigFilePath
}

function Invoke-PSMPrerequisites {
    # Stage CyberArk "Prerequisites" (InstallRDS, DisableNLA, RDS Security Layer, .NET...).
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot
    )
    $stage = Resolve-PSMStageConfig -Settings $Settings -SourcesRoot $SourcesRoot -StageKey 'Prerequisites'
    return Invoke-PSMStage -StageName 'Prerequisites' `
                           -ExecuteStagePath $stage.ExecuteStage `
                           -ConfigFilePath   $stage.ConfigFilePath
}

function Invoke-PSMRdsLicensing {
    <#
        Configure le mode et le/les serveur(s) de licence RD Session Host
        (valeur registre 'LicenseServers' = liste separee par des virgules).
        A executer APRES l'installation du role RDS (stage Prerequisites).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)] $Settings)

    $licMode    = $Settings.Rds.LicenseMode
    $licSrvList = @($Settings.Rds.LicenseServers) | Where-Object { $_ }
    $licSrvStr  = $licSrvList -join ','
    $rdKey      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

    Invoke-IdempotentStep -Name "Mode licence RDS ($licMode)" `
        -Test   {
            $modeVal = if ($licMode -eq 'PerUser') { 4 } else { 2 }
            (Get-PSMRegValue -Path $rdKey -Name 'LicensingMode') -eq $modeVal
        } `
        -Action {
            if (-not (Test-Path $rdKey)) { New-Item -Path $rdKey -Force | Out-Null }
            $modeVal = if ($licMode -eq 'PerUser') { 4 } else { 2 }
            Set-ItemProperty -Path $rdKey -Name 'LicensingMode' -Value $modeVal -Type DWord
        }

    Invoke-IdempotentStep -Name "Serveur(s) de licence RDS ($licSrvStr)" `
        -Test   {
            $cur = Get-PSMRegValue -Path $rdKey -Name 'LicenseServers'
            ((($cur -as [string]) -replace '\s*,\s*', ',')) -eq $licSrvStr
        } `
        -Action {
            if (-not (Test-Path $rdKey)) { New-Item -Path $rdKey -Force | Out-Null }
            Set-ItemProperty -Path $rdKey -Name 'LicenseServers' -Value $licSrvStr -Type String
        }
}

Export-ModuleMember -Function Invoke-PSMReadiness, Invoke-PSMPrerequisites, `
                              Invoke-PSMRdsLicensing, Test-PSMLicenseServers, Get-PSMRegValue
