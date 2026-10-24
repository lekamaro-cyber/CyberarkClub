<#
.SYNOPSIS
    "Prerequisites" phases: CyberArk Readiness + Prerequisites stages (Execute-Stage.ps1)
    + local RD Session Host licensing configuration.

.DESCRIPTION
    - Readiness / Prerequisites: driven through the CyberArk framework (RDS role
      installation, .NET, NLA, RDS Security Layer...). A possible reboot is
      signaled via restartRequired and handled by the orchestrator.
    - RDS licensing: the mode + license server(s) config stays on our side
      (site-specific), applied AFTER the RDS role installation.
    - Test-PSMLicenseServers: connectivity check (used during pre-flight).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PSMRegValue {
    <#
        Robust registry read: returns the value, or $null when the key/value
        does not exist (avoids the StrictMode exception on a missing property).
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

function Test-PSMTcpReachable {
    # TCP connect test with a timeout ($true = the port answered).
    param(
        [Parameter(Mandatory)] [string] $Server,
        [int] $Port      = 135,
        [int] $TimeoutMs = 3000
    )
    $ok = $false
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $iar    = $client.BeginConnect($Server, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $client.EndConnect($iar)
            $ok = $client.Connected
        }
        $client.Close()
    }
    catch { $ok = $false }
    return $ok
}

function Test-PSMLicenseServers {
    <#
        Connectivity check towards the RDS license server(s).
        Port 135 = RPC endpoint mapper (used by the RDS licensing service).
        Non-blocking: logs OK/WARN and returns $true when all are reachable.
    #>
    [CmdletBinding()]
    param(
        [string[]] $Servers,
        [int]      $Port      = 135,
        [int]      $TimeoutMs = 3000
    )
    $allOk = $true
    foreach ($srv in (@($Servers) | Where-Object { $_ })) {
        $ok = Test-PSMTcpReachable -Server $srv -Port $Port -TimeoutMs $TimeoutMs
        if ($ok) {
            Write-PSMLog -Level OK   -Message "RDS license server reachable: $srv (TCP $Port)."
        }
        else {
            Write-PSMLog -Level WARN -Message "RDS license server UNREACHABLE: $srv (TCP $Port) - check DNS/firewall."
            $allOk = $false
        }
    }
    return $allOk
}

function Get-PSMLicenseServerOrder {
    <#
        Order in which the license servers are written: the ones REACHABLE
        from this server first, then the others - kept in the list (DR: the
        flows between datacenters are closed today, the other DC's server may
        be needed later). Config order is kept inside each group; none
        reachable = config order (WARN).
    #>
    [CmdletBinding()]
    param(
        [string[]] $Servers,
        [int]      $Port      = 135,
        [int]      $TimeoutMs = 3000
    )
    $list = @(@($Servers) | Where-Object { $_ })
    if ($list.Count -le 1) { return $list }
    $reachable   = @()
    $unreachable = @()
    foreach ($srv in $list) {
        if (Test-PSMTcpReachable -Server $srv -Port $Port -TimeoutMs $TimeoutMs) { $reachable += $srv }
        else                                                                    { $unreachable += $srv }
    }
    if (-not $reachable) {
        Write-PSMLog -Level WARN -Message ("RDS license servers: NONE reachable (TCP $Port) among $($list -join ', ') - " +
            'written in config order, check DNS/firewall.')
        return $list
    }
    $ordered = @($reachable + $unreachable)
    Write-PSMLog -Level INFO -Message ("RDS license servers: reachable first -> $($ordered -join ', ')" +
        $(if ($unreachable) { " (not reachable from here, kept after for DR: $($unreachable -join ', '))" }))
    return $ordered
}

function Invoke-PSMReadiness {
    # CyberArk "Readiness" stage (CheckOS, CheckSystemRequirements, .NET, domain...).
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
    # CyberArk "Prerequisites" stage (InstallRDS, DisableNLA, RDS Security Layer, .NET...).
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
        Configures the RD Session Host licensing mode and license server(s)
        ('LicenseServers' registry value = comma-separated list, the servers
        reachable from this machine first - see Get-PSMLicenseServerOrder).
        To be run AFTER the RDS role installation (Prerequisites stage).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)] $Settings)

    $licMode    = $Settings.Rds.LicenseMode
    $licSrvList = @(Get-PSMLicenseServerOrder -Servers $Settings.Rds.LicenseServers)
    $licSrvStr  = $licSrvList -join ','
    $rdKey      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

    Invoke-IdempotentStep -Name "RDS licensing mode ($licMode)" `
        -Test   {
            $modeVal = if ($licMode -eq 'PerUser') { 4 } else { 2 }
            (Get-PSMRegValue -Path $rdKey -Name 'LicensingMode') -eq $modeVal
        } `
        -Action {
            if (-not (Test-Path $rdKey)) { New-Item -Path $rdKey -Force | Out-Null }
            $modeVal = if ($licMode -eq 'PerUser') { 4 } else { 2 }
            Set-ItemProperty -Path $rdKey -Name 'LicensingMode' -Value $modeVal -Type DWord
        }

    Invoke-IdempotentStep -Name "RDS license server(s) ($licSrvStr)" `
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
                              Invoke-PSMRdsLicensing, Test-PSMLicenseServers, Get-PSMLicenseServerOrder, Get-PSMRegValue
