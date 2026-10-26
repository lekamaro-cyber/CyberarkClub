#Requires -RunAsAdministrator
<#
.SYNOPSIS
    READ-ONLY check of a PSM server before (re)running the CyberArk
    Prerequisites stage (InstallRDS: RD Session Host + RD Connection Broker).

.DESCRIPTION
    Written after FRDRPSRV10017: "Unable to install RD Connection Broker role
    service", then InstallRDS looping. Checks the usual causes and changes
    NOTHING on the server:
      - pending reboot (a role removal is only finished after a reboot);
      - state of the RDS / WID features (Available, Installed, *Pending, Removed);
      - leftovers of a previous Connection Broker (services, rdcms database
        in C:\Windows\WID);
      - "Log on as a service" right for the WID service: a GPO that defines it
        without NT SERVICE\ALL SERVICES keeps WID - so the Broker - from starting;
      - PowerShell remoting (WinRM) to the server's own FQDN, used by the RDS
        deployment;
      - DNS: the FQDN resolves to an address of this server;
      - domain secure channel, Windows Modules Installer, free space on C:;
      - PSM-Deploy state: where the next run resumes.
    One line per check = OK / WARN / KO with the fix. Exit code 0 = no KO.

.EXAMPLE
    .\tools\Test-PSMRdsReadiness.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$script:Results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [ValidateSet('OK', 'WARN', 'KO')] [string] $Status,
        [string] $Check,
        [string] $Detail
    )
    $script:Results.Add([pscustomobject]@{ Status = $Status; Check = $Check; Detail = $Detail })
    $color = @{ OK = 'Green'; WARN = 'Yellow'; KO = 'Red' }[$Status]
    Write-Host ("[{0,-4}] {1}: {2}" -f $Status, $Check, $Detail) -ForegroundColor $color
}

function Invoke-Check {
    # Runs one check; an unexpected error is reported as WARN and never stops the script.
    param([string] $Check, [scriptblock] $Body)
    try { & $Body }
    catch { Add-Result WARN $Check "check could not run: $($_.Exception.Message)" }
}

function Get-RegValue {
    # Registry value or $null (StrictMode-safe).
    param([string] $Path, [string] $Name)
    try { return (Get-Item -Path $Path -ErrorAction Stop).GetValue($Name, $null) } catch { return $null }
}

$domain = (Get-CimInstance Win32_ComputerSystem).Domain
$fqdn   = "$env:COMPUTERNAME.$domain"
$rdsFeatures = @('RDS-Connection-Broker', 'RDS-RD-Server', 'Windows-Internal-Database')

Write-Host ''
Write-Host "=== RDS readiness check - $fqdn - $(Get-Date -Format 'yyyy-MM-dd HH:mm') (read-only) ===" -ForegroundColor White

# --- 1. Pending reboot ----------------------------------------------------------
Invoke-Check 'Pending reboot' {
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons += 'roles/features servicing (CBS)'
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons += 'Windows Update'
    }
    $pfro = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
    if ($reasons) {
        Add-Result KO 'Pending reboot' "YES ($($reasons -join ', ')) - reboot BEFORE relaunching (an uninstall is not finished)."
    }
    elseif ($pfro) {
        Add-Result WARN 'Pending reboot' 'pending file renames only (often harmless) - a reboot clears it.'
    }
    else {
        Add-Result OK 'Pending reboot' 'none.'
    }
}

# --- 2. RDS / WID features --------------------------------------------------------
Invoke-Check 'RDS / WID features' {
    foreach ($f in @(Get-WindowsFeature -Name $rdsFeatures)) {
        $state = [string]$f.InstallState
        switch ($state) {
            'Available' { Add-Result OK   "Feature $($f.Name)" 'not installed (clean - the Prerequisites stage installs it).' }
            'Installed' { Add-Result WARN "Feature $($f.Name)" 'still INSTALLED - fine if it works, otherwise uninstall + reboot before relaunching.' }
            'Removed'   { Add-Result KO   "Feature $($f.Name)" 'payload REMOVED (Uninstall-WindowsFeature -Remove) - the install will need a source (-Source / Windows Update).' }
            default     { Add-Result KO   "Feature $($f.Name)" "$state - reboot to finish the operation." }
        }
    }
}

# --- 3. Leftover Connection Broker services --------------------------------------
Invoke-Check 'Broker services' {
    $cbInstalled = [string](Get-WindowsFeature -Name 'RDS-Connection-Broker').InstallState -eq 'Installed'
    $svc = @(Get-Service -Name 'Tssdis', 'RDMS', 'TScPubRPC' -ErrorAction SilentlyContinue)
    $list = ($svc | ForEach-Object { "$($_.Name)=$($_.Status)" }) -join ', '
    if (-not $cbInstalled) {
        if ($svc) { Add-Result KO 'Broker services' "still registered although the Broker is not installed ($list) - reboot to finish the removal." }
        else      { Add-Result OK 'Broker services' 'none left.' }
    }
    elseif (@($svc | Where-Object { $_.Name -eq 'Tssdis' -and $_.Status -ne 'Running' })) {
        Add-Result KO 'Broker services' "Broker installed but its service is not running ($list) - see the System event log."
    }
    else {
        Add-Result OK 'Broker services' "Broker installed ($list)."
    }
}

# --- 4. Leftover WID database of the Broker --------------------------------------
Invoke-Check 'WID database' {
    $cbInstalled  = [string](Get-WindowsFeature -Name 'RDS-Connection-Broker').InstallState -eq 'Installed'
    $widInstalled = [string](Get-WindowsFeature -Name 'Windows-Internal-Database').InstallState -eq 'Installed'
    $rdcms = @(Get-ChildItem -Path 'C:\Windows\WID\Data' -Filter 'rdcms*' -ErrorAction SilentlyContinue)
    if ($rdcms -and -not $cbInstalled) {
        Add-Result KO 'WID database' ("Broker database left by a previous attempt ($(($rdcms | ForEach-Object { $_.Name }) -join ', ')) - " +
            'with WID uninstalled and after the reboot, delete C:\Windows\WID, otherwise the new Broker cannot create its database.')
    }
    elseif (-not $widInstalled -and (Test-Path 'C:\Windows\WID')) {
        Add-Result WARN 'WID database' 'C:\Windows\WID still present although WID is not installed - delete it to start clean.'
    }
    else {
        Add-Result OK 'WID database' $(if ($rdcms) { 'Broker database present (Broker installed).' } else { 'no leftover.' })
    }
}

# --- 5. "Log on as a service" for the WID service --------------------------------
Invoke-Check 'Log on as a service (WID)' {
    # Service SID of WID (computed by sc.exe even when WID is not installed).
    $widSid = $null
    if (((& sc.exe showsid 'MSSQL$MICROSOFT##WID') -join ' ') -match 'S-1-5-80(-\d+){5}') { $widSid = $Matches[0] }

    # Effective right (local policy + GPO), exported to a temp file then deleted.
    $tmp = Join-Path $env:TEMP ("psm-rights-{0}.inf" -f [guid]::NewGuid().ToString('N'))
    & secedit.exe /export /cfg $tmp /areas USER_RIGHTS /quiet | Out-Null
    $line = @(Get-Content -Path $tmp -ErrorAction SilentlyContinue | Where-Object { $_ -match '^SeServiceLogonRight\s*=' }) | Select-Object -First 1
    Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
    $sids = @()
    if ($line) {
        foreach ($h in (($line -split '=', 2)[1]).Split(',')) {
            $h = $h.Trim().TrimStart('*')
            if (-not $h) { continue }
            if ($h -like 'S-1-*') { $sids += $h; continue }
            try   { $sids += ([System.Security.Principal.NTAccount]$h).Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { $sids += $h }
        }
    }
    # Defined by a GPO? (RSoP, precedence 1 = winning GPO)
    $gpo = $null
    try {
        $gpo = Get-CimInstance -Namespace 'root\rsop\computer' -ClassName 'RSOP_UserPrivilegeRight' `
                   -Filter "UserRight='SeServiceLogonRight' AND precedence=1" -ErrorAction Stop | Select-Object -First 1
    }
    catch { }

    if ($sids -contains 'S-1-5-80-0') {
        Add-Result OK 'Log on as a service (WID)' "granted to NT SERVICE\ALL SERVICES$(if ($gpo) { ' (GPO-defined)' })."
    }
    elseif ($widSid -and ($sids -contains $widSid)) {
        Add-Result OK 'Log on as a service (WID)' "granted to the WID service account$(if ($gpo) { ' (GPO-defined: check it stays after the next gpupdate)' })."
    }
    elseif ($gpo) {
        Add-Result KO 'Log on as a service (WID)' ("defined by a GPO WITHOUT NT SERVICE\ALL SERVICES nor the WID account -> the WID service " +
            "(Broker database) cannot start -> 'Unable to install RD Connection Broker'. Ask the AD team to add " +
            "NT SERVICE\ALL SERVICES to 'Log on as a service' in that GPO ($($gpo.GPOID)).")
    }
    else {
        Add-Result WARN 'Log on as a service (WID)' 'NT SERVICE\ALL SERVICES not granted (local policy) - the WID setup normally adds its own account.'
    }
}

# --- 6. PowerShell remoting to the own FQDN (used by the RDS deployment) ---------
Invoke-Check 'WinRM remoting' {
    $w = Get-Service -Name 'WinRM' -ErrorAction Stop
    if ($w.Status -ne 'Running') {
        Add-Result KO 'WinRM remoting' "WinRM service is $($w.Status) - the RDS deployment needs it (Start-Service WinRM)."
        return
    }
    try {
        $r = Invoke-Command -ComputerName $fqdn -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
        Add-Result OK 'WinRM remoting' "Invoke-Command $fqdn -> $r."
    }
    catch {
        Add-Result KO 'WinRM remoting' "Invoke-Command $fqdn FAILS ($($_.Exception.Message)) - the RDS deployment uses it (WinRM listener, SPN, Kerberos, firewall)."
    }
}

# --- 7. DNS: the FQDN points to this server --------------------------------------
Invoke-Check 'DNS' {
    $dnsIps   = @(Resolve-DnsName -Name $fqdn -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress })
    $localIps = @(Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { $_.IPAddress })
    $mine     = @($dnsIps | Where-Object { $localIps -contains $_ })
    $foreign  = @($dnsIps | Where-Object { $localIps -notcontains $_ })
    if (-not $mine) {
        Add-Result KO 'DNS' "$fqdn resolves to $($dnsIps -join ', '), none of them is on this server ($($localIps -join ', ')) - fix the DNS record."
    }
    elseif ($foreign) {
        Add-Result WARN 'DNS' "$fqdn also resolves to $($foreign -join ', ') (not on this server) - stale record to clean up."
    }
    else {
        Add-Result OK 'DNS' "$fqdn -> $($dnsIps -join ', ')."
    }
}

# --- 8. Domain secure channel ----------------------------------------------------
Invoke-Check 'Domain secure channel' {
    if (Test-ComputerSecureChannel -ErrorAction Stop) { Add-Result OK 'Domain secure channel' "OK ($domain)." }
    else { Add-Result KO 'Domain secure channel' 'BROKEN - Test-ComputerSecureChannel -Repair (domain admin) or rejoin the domain.' }
}

# --- 9. Windows Modules Installer (role installs) --------------------------------
Invoke-Check 'Windows Modules Installer' {
    $ti = Get-Service -Name 'TrustedInstaller' -ErrorAction Stop
    if ([string]$ti.StartType -eq 'Disabled') { Add-Result KO 'Windows Modules Installer' 'service DISABLED - roles/features cannot be installed.' }
    else { Add-Result OK 'Windows Modules Installer' "start type $($ti.StartType)." }
}

# --- 10. Free space on C: ---------------------------------------------------------
Invoke-Check 'Free space C:' {
    $freeGb = [math]::Round((Get-PSDrive -Name C -ErrorAction Stop).Free / 1GB, 1)
    if     ($freeGb -lt 3)  { Add-Result KO   'Free space C:' "$freeGb GB - too low for the roles install." }
    elseif ($freeGb -lt 10) { Add-Result WARN 'Free space C:' "$freeGb GB - low." }
    else                    { Add-Result OK   'Free space C:' "$freeGb GB." }
}

# --- 11. PSM-Deploy state ---------------------------------------------------------
Invoke-Check 'PSM-Deploy state' {
    $statePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'state\progress.json'
    if (-not (Test-Path $statePath)) {
        Add-Result OK 'PSM-Deploy state' 'no state\progress.json - the next run starts from the beginning.'
    }
    else {
        $done  = @((Get-Content -Path $statePath -Raw | ConvertFrom-Json).completedPhases)
        $order = 'PreFlight', 'Readiness', 'Prerequisites', 'RdsLicensing', 'Software', 'Installation',
                 'PostInstallation', 'Registration', 'Hardening', 'Validation'
        $next  = @($order | Where-Object { $done -notcontains $_ }) | Select-Object -First 1
        Add-Result OK 'PSM-Deploy state' "completed: $(if ($done) { $done -join ', ' } else { 'none' }) - next run resumes at: $(if ($next) { $next } else { 'nothing left' })."
    }
    if (Get-ScheduledTask -TaskName 'PSM-Deploy-Resume' -ErrorAction SilentlyContinue) {
        Add-Result WARN 'PSM-Deploy state' "resume task 'PSM-Deploy-Resume' is armed: the deployment relaunches at the next logon."
    }
}

# --- Summary ------------------------------------------------------------------------
$ko   = @($script:Results | Where-Object { $_.Status -eq 'KO' })
$warn = @($script:Results | Where-Object { $_.Status -eq 'WARN' })
Write-Host ''
if ($ko) {
    Write-Host "NOT READY: $($ko.Count) KO, $($warn.Count) WARN - fix the KO lines, then run this check again." -ForegroundColor Red
    exit 1
}
Write-Host "READY to relaunch ($($warn.Count) WARN to read): .\Deploy-PSM.ps1 -Zone <zone>" -ForegroundColor Green
exit 0
