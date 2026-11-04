#Requires -RunAsAdministrator
<#
.SYNOPSIS
    READ-ONLY inventory of a PSM server, to compare a PSM installed by hand
    (production) with what PSM-Deploy does - "did we miss anything?".

.DESCRIPTION
    Self-contained: copy this file alone onto any PSM (no PSM-Deploy sources
    needed). Changes NOTHING; prints plain text, one section per topic:
      1. machine (OS, domain, OU, drives)          8. hardening traces + PostInstallation
      2. CyberArk products and registry keys          indicators (DFSS, certificate chain,
      3. PSM service and folders                      IE ESC, Explorer policies, drive ACLs)
      4. PSM configuration (basic_psm.ini,         9. AppLocker (effective policy, Exe rules,
         Vault.ini, cred file user names)             PSMConfigureAppLocker.xml entries)
      5. accounts, local groups, user rights      10. installed software
      6. GPOs applied to the computer             11. client tools found on disk, Oracle env
      7. RDS (roles, licensing, RDP-Tcp,          12. non-Microsoft scheduled tasks
         Terminal Services policies)              13. certificates + RDP binding, firewall, proxy
    No secret is read: cred files give only their Username / AppType lines,
    INI keys whose name looks like a secret are skipped. Account names, IPs and
    paths ARE shown (that is the point): mask them before sharing outside.

.EXAMPLE
    .\Get-PSMInventory.ps1 | Out-File C:\Temp\psm-inventory.txt -Width 250
    # then paste the file's content
#>
[CmdletBinding()]
param(
    # PSM folder; empty -> read from the PSM service
    [string] $PsmDir
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Helpers (output = plain strings on the pipeline, so Out-File works)
# ---------------------------------------------------------------------------
function Invoke-Section {
    param([string] $Title, [scriptblock] $Body)
    ''
    "==== $Title " + ('=' * [Math]::Max(3, 74 - $Title.Length))
    try { & $Body }
    catch { "  ! section failed: $($_.Exception.Message)" }
}

function Out-Table {
    # Objects -> one wide text table (console width independent).
    param([Parameter(ValueFromPipeline)] $InputObject)
    begin   { $all = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $all.Add($InputObject) } }
    end {
        if ($all.Count) { ($all | Format-Table -AutoSize -Wrap | Out-String -Width 250).TrimEnd() }
        else            { '  (none)' }
    }
}

function Get-RegValues {
    # Values of a registry key as Name/Value rows; nothing when the key is absent.
    param([string] $Path, [string[]] $Only)
    try { $k = Get-Item -LiteralPath $Path -ErrorAction Stop } catch { return }
    foreach ($n in $k.GetValueNames()) {
        if ($Only -and ($Only -notcontains $n)) { continue }
        $v = $k.GetValue($n)
        $text = if ($v -is [byte[]]) { "(binary, $($v.Length) bytes)" } else { (@($v) -join ', ') }
        if ($text.Length -gt 120) { $text = $text.Substring(0, 117) + '...' }
        [pscustomobject]@{ Key = (Split-Path $Path -Leaf); Name = $(if ($n) { $n } else { '(default)' }); Value = $text }
    }
}

function ConvertTo-AccountName {
    param([string] $Sid)
    try { ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value }
    catch { $Sid }
}

function Get-LocalGroupMemberNames {
    # Members of a local group through ADSI (works with orphaned SIDs, unlike Get-LocalGroupMember).
    param([string] $GroupName)
    try {
        $g = [ADSI]"WinNT://$env:COMPUTERNAME/$GroupName,group"
        @($g.psbase.Invoke('Members') | ForEach-Object {
            ([string]$_.GetType().InvokeMember('AdsPath', 'GetProperty', $null, $_, $null)) -replace '^WinNT://', '' -replace '/', '\'
        })
    }
    catch { @("! $($_.Exception.Message)") }
}

function Find-ClientTools {
    # Breadth-first search, depth-limited, skipping heavy folders (recordings...).
    param([string[]] $Roots, [string[]] $Patterns, [int] $MaxDepth = 4)
    $skip  = '^(Windows|Users|ProgramData|Recordings|PSMSources|PSM-Backup.*|\$Recycle\.Bin|System Volume Information|WinSxS|Installer|assembly|Recovery|PerfLogs)$'
    $queue = New-Object System.Collections.Queue
    foreach ($r in $Roots) { if (Test-Path -LiteralPath $r) { $queue.Enqueue(@($r, 0)) } }
    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        $dir = $item[0]; $depth = $item[1]
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)) {
            foreach ($p in $Patterns) {
                if ($f.Name -like $p) {
                    [pscustomobject]@{ File = $f.FullName; Version = $f.VersionInfo.FileVersion }
                    break
                }
            }
        }
        if ($depth -lt $MaxDepth) {
            foreach ($d in @(Get-ChildItem -LiteralPath $dir -Directory -ErrorAction SilentlyContinue)) {
                if ($d.Name -notmatch $skip) { $queue.Enqueue(@($d.FullName, $depth + 1)) }
            }
        }
    }
}

# PSM folder from the service (CAPSM.exe) unless given.
$svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='Cyberark Privileged Session Manager'" -ErrorAction SilentlyContinue
if (-not $PsmDir -and $svc) {
    $m = [regex]::Match([string]$svc.PathName, '^\s*"?(?<exe>[^"]+?\.exe)')
    if ($m.Success) { $PsmDir = Split-Path $m.Groups['exe'].Value -Parent }
}

"PSM INVENTORY (read-only) - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm') - by $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
"PSM folder: $(if ($PsmDir) { $PsmDir } else { 'not found (no PSM service?)' })"

# ---------------------------------------------------------------------------
Invoke-Section '1. Machine' {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    "  OS      : $($os.Caption) $($os.Version) (build $($os.BuildNumber)), installed $($os.InstallDate)"
    "  Domain  : $($cs.Domain)"
    try {
        $r = ([adsisearcher]"(&(objectCategory=computer)(sAMAccountName=$env:COMPUTERNAME`$))").FindOne()
        "  OU      : $(if ($r) { $r.Properties['distinguishedname'][0] } else { 'not found in AD' })"
    }
    catch { "  OU      : ! $($_.Exception.Message)" }
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' |
        Select-Object DeviceID, @{ n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB) } }, @{ n = 'FreeGB'; e = { [math]::Round($_.FreeSpace / 1GB, 1) } }, VolumeName |
        Out-Table
}

Invoke-Section '2. CyberArk products and registry' {
    $uninst = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty $uninst -ErrorAction SilentlyContinue |
        Where-Object { ($_.PSObject.Properties.Name -contains 'DisplayName') -and ("$($_.DisplayName) $($_.Publisher)" -match 'CyberArk') } |
        Select-Object DisplayName, DisplayVersion, InstallLocation, InstallDate | Out-Table
    '  Registry HKLM\SOFTWARE\WOW6432Node\CyberArk:'
    Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\CyberArk' -Recurse -Depth 1 -ErrorAction SilentlyContinue |
        ForEach-Object { '    ' + ($_.Name -replace '^HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\CyberArk\\', '') }
}

Invoke-Section '3. PSM service and folders' {
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'CyberArk|PSM' -or $_.DisplayName -match 'CyberArk' } |
        Select-Object Name, State, StartMode, StartName | Out-Table
    if ($PsmDir -and (Test-Path -LiteralPath $PsmDir)) {
        '  Sub-folders of the PSM folder:'
        Get-ChildItem -LiteralPath $PsmDir -Directory | ForEach-Object { "    $($_.Name)  ($($_.LastWriteTime.ToString('yyyy-MM-dd')))" }
    }
}

Invoke-Section '4. PSM configuration (no secret)' {
    if (-not $PsmDir) { '  no PSM folder'; return }
    $secret = 'pass|pwd|secret|key|token'
    foreach ($ini in @((Join-Path $PsmDir 'basic_psm.ini'), (Join-Path $PsmDir 'Vault\Vault.ini'))) {
        "  -- $ini"
        if (-not (Test-Path -LiteralPath $ini)) { '    (absent)'; continue }
        Get-Content -LiteralPath $ini | Where-Object { $_ -match '^\s*[^#;\s][^=]*=' } | ForEach-Object {
            $name = ($_ -split '=', 2)[0].Trim()
            if ($name -match $secret) { "    $name = (skipped)" } else { "    $($_.Trim())" }
        }
    }
    '  -- cred files (Username / AppType lines only)'
    Get-ChildItem -LiteralPath (Join-Path $PsmDir 'Vault') -Filter '*.cred' -ErrorAction SilentlyContinue | ForEach-Object {
        $lines = @(Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*(Username|AppType)\s*=' })
        "    $($_.Name): $($lines -join ' | ')"
    }
}

Invoke-Section '5. Accounts, local groups, user rights' {
    foreach ($g in @(@{ Sid = 'S-1-5-32-544' }, @{ Sid = 'S-1-5-32-555' })) {
        $name = (ConvertTo-AccountName $g.Sid) -replace '^.*\\', ''
        "  Local group '$name':"
        Get-LocalGroupMemberNames $name | ForEach-Object { "    $_" }
    }
    foreach ($lg in @(Get-LocalGroup -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'PSM' })) {
        "  Local group '$($lg.Name)':"
        Get-LocalGroupMemberNames $lg.Name | ForEach-Object { "    $_" }
    }
    '  Local users named *PSM*:'
    Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'PSM' } |
        Select-Object Name, Enabled, LastLogon, PasswordExpires | Out-Table
    '  User rights (effective policy):'
    $tmp = Join-Path $env:TEMP ("psm-inv-{0}.inf" -f [guid]::NewGuid().ToString('N'))
    try {
        & secedit.exe /export /cfg $tmp /areas USER_RIGHTS /quiet | Out-Null
        $rights = 'SeRemoteInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeInteractiveLogonRight',
                  'SeDenyInteractiveLogonRight', 'SeServiceLogonRight', 'SeBatchLogonRight', 'SeDenyNetworkLogonRight'
        $lines = @(Get-Content -LiteralPath $tmp -ErrorAction SilentlyContinue)
        foreach ($right in $rights) {
            $l = $lines | Where-Object { $_ -match "^$right\s*=" } | Select-Object -First 1
            $who = if ($l) { ((($l -split '=', 2)[1]).Split(',') | ForEach-Object { ConvertTo-AccountName $_.Trim().TrimStart('*') }) -join ', ' } else { '(not defined)' }
            "    $right = $who"
        }
    }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

Invoke-Section '6. GPOs applied to the computer' {
    Get-CimInstance -Namespace 'root\rsop\computer' -ClassName RSOP_GPO -ErrorAction Stop |
        Select-Object Name, Enabled, FilterAllowed, AccessDenied | Sort-Object Name | Out-Table
    $w = Get-CimInstance -Namespace 'root\rsop\computer' -ClassName RSOP_UserPrivilegeRight `
             -Filter "UserRight='SeRemoteInteractiveLogonRight' AND precedence=1" -ErrorAction SilentlyContinue | Select-Object -First 1
    "  'Allow log on through RDS' set by: $(if ($w) { $w.GPOID } else { 'local policy (no GPO)' })"
}

Invoke-Section '7. RDS' {
    Get-WindowsFeature -Name 'RDS-*', 'Windows-Internal-Database' -ErrorAction SilentlyContinue |
        Where-Object { $_.InstallState -ne 'Available' } | Select-Object Name, InstallState | Out-Table
    '  Licensing / RDP-Tcp / Terminal Server:'
    @(
        Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core' -Only 'LicensingMode'
        Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters\LicenseServers'
        Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Only 'fDenyTSConnections', 'fSingleSessionPerUser'
        Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Only 'PortNumber', 'SecurityLayer',
            'UserAuthentication', 'MinEncryptionLevel', 'MaxIdleTime', 'MaxDisconnectionTime', 'MaxConnectionTime', 'fResetBroken',
            'fInheritMaxIdleTime', 'fInheritMaxDisconnectionTime', 'fInheritReconnectSame', 'fDisableCdm', 'fDisableCpm', 'fDisableClip'
    ) | Out-Table
    '  Terminal Services policies (GPO):'
    Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' | Out-Table
}

Invoke-Section '8. Hardening traces and PostInstallation indicators' {
    if ($PsmDir) {
        $hd = Join-Path $PsmDir 'Hardening'
        "  -- $hd (customized files show a later date):"
        Get-ChildItem -LiteralPath $hd -File -ErrorAction SilentlyContinue |
            Select-Object Name, Length, @{ n = 'Modified'; e = { $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm') } } | Out-Table
    }
    '  -- drive roots: Allow ACEs of Users / Authenticated Users / Everyone'
    foreach ($d in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { "$($_.DeviceID)\" })) {
        $rules = (Get-Acl -LiteralPath $d).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
            Where-Object { @('S-1-5-32-545', 'S-1-5-11', 'S-1-1-0') -contains $_.IdentityReference.Value -and [string]$_.AccessControlType -eq 'Allow' }
        $txt = @($rules | ForEach-Object { "$(ConvertTo-AccountName $_.IdentityReference.Value): $($_.FileSystemRights) [$($_.PropagationFlags)]" })
        "    $d $(if ($txt) { $txt -join ' ; ' } else { 'none (hardened)' })"
    }
    '  -- PostInstallation indicators (DFSS, certificate chain timeouts, IE ESC) and Explorer/System policies:'
    @(
        Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System' -Only 'EnableCpuQuota'
        Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Services\TSFairShare\Disk' -Only 'EnableFairShare'
        Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Services\TSFairShare\NetFS' -Only 'EnableFairShare'
        Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\ChainEngine\Config'
        Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Only 'IsInstalled'
        Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Only 'IsInstalled'
        Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Only 'DisableCAD', 'DontDisplayLastUserName',
            'EnableLUA', 'ConsentPromptBehaviorAdmin', 'LegalNoticeCaption', 'InactivityTimeoutSecs'
    ) | Out-Table
    '  (IE ESC: IsInstalled 0 = off. Active Setup {A509B1A7} = administrators, {A509B1A8} = users.)'
}

Invoke-Section '9. AppLocker' {
    $s = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    "  AppIDSvc: $(if ($s) { "$($s.Status), $($s.StartType)" } else { 'absent' })"
    [xml]$pol = Get-AppLockerPolicy -Effective -Xml
    foreach ($rc in @($pol.SelectNodes('//RuleCollection'))) {
        $rules = @($rc.ChildNodes | Where-Object { $_.LocalName -like '*Rule' })
        "  Collection $($rc.Type): mode $($rc.GetAttribute('EnforcementMode')), $($rules.Count) rule(s)"
    }
    '  Exe rules:'
    @($pol.SelectNodes("//RuleCollection[@Type='Exe']/*") | Where-Object { $_.LocalName -like '*Rule' } | ForEach-Object {
        $cond = $_.SelectSingleNode('Conditions/*')
        $what = if (-not $cond) { '' }
                elseif ($cond.LocalName -eq 'FilePathCondition')      { "Path $($cond.GetAttribute('Path'))" }
                elseif ($cond.LocalName -eq 'FilePublisherCondition') { "Publisher $($cond.GetAttribute('PublisherName')) / $($cond.GetAttribute('ProductName')) / $($cond.GetAttribute('BinaryName'))" }
                else { "Hash $(@($cond.SelectNodes('FileHash') | ForEach-Object { $_.GetAttribute('SourceFileName') }) -join ', ')" }
        [pscustomobject]@{
            Action = $_.GetAttribute('Action'); User = ConvertTo-AccountName $_.GetAttribute('UserOrGroupSid')
            Rule = $_.GetAttribute('Name'); Condition = $what
            Exceptions = @($_.SelectNodes('Exceptions/*')).Count
        }
    }) | Out-Table
    if ($PsmDir) {
        $x = Join-Path $PsmDir 'Hardening\PSMConfigureAppLocker.xml'
        "  -- $x (applications the CyberArk AppLocker script allows):"
        if (Test-Path -LiteralPath $x) {
            [xml]$cfg = Get-Content -LiteralPath $x -Raw
            @($cfg.SelectNodes('//Application') | ForEach-Object {
                [pscustomobject]@{ Name = $_.GetAttribute('Name'); Type = $_.GetAttribute('Type'); Method = $_.GetAttribute('Method')
                                   SessionType = $_.GetAttribute('SessionType'); Path = $_.GetAttribute('Path') }
            }) | Out-Table
        }
        else { '    (absent)' }
    }
}

Invoke-Section '10. Installed software (no updates)' {
    $uninst = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty $uninst -ErrorAction SilentlyContinue |
        Where-Object { ($_.PSObject.Properties.Name -contains 'DisplayName') -and $_.DisplayName -and
                       $_.DisplayName -notmatch '^(Update for|Security Update|Hotfix)|\(KB\d+\)' } |
        Select-Object DisplayName, DisplayVersion, Publisher -Unique | Sort-Object DisplayName | Out-Table
}

Invoke-Section '11. Client tools on disk and Oracle environment' {
    Find-ClientTools -Roots @('C:\', 'D:\') -MaxDepth 4 -Patterns @(
        'sqlplus.exe', 'sqldeveloper*.exe', 'toad.exe', 'ssms.exe', 'chrome.exe', 'chromedriver.exe', 'msedge.exe',
        'msedgedriver.exe', 'putty.exe', 'winscp.exe', 'privateark.exe', 'tnsnames.ora') | Out-Table
    foreach ($v in 'ORACLE_HOME', 'TNS_ADMIN', 'NLS_LANG') {
        "  $v = $([Environment]::GetEnvironmentVariable($v, 'Machine'))"
    }
    '  System PATH entries:'
    ([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') | Where-Object { $_ } | ForEach-Object { "    $_" }
}

Invoke-Section '12. Scheduled tasks (non-Microsoft)' {
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
        Select-Object TaskPath, TaskName, State, @{ n = 'RunAs'; e = { $_.Principal.UserId } },
                      @{ n = 'Action'; e = { (@($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' ; ') } } |
        Out-Table
}

Invoke-Section '13. Certificates, RDP binding, firewall, proxy' {
    Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Select-Object Thumbprint, Subject, @{ n = 'Expires'; e = { $_.NotAfter.ToString('yyyy-MM-dd') } }, HasPrivateKey | Out-Table
    $ts = Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'" -ErrorAction SilentlyContinue
    "  RDP-Tcp certificate: $(if ($ts) { $ts.SSLCertificateSHA1Hash } else { 'not readable' })"
    Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Out-Table
    '  WinHTTP proxy:'
    (& netsh.exe winhttp show proxy) | Where-Object { $_ -match '\S' } | ForEach-Object { "    $($_.Trim())" }
    '  Chrome policies (HKLM):'
    Get-RegValues 'HKLM:\SOFTWARE\Policies\Google\Chrome' | Out-Table
}

''
"==== End of inventory ($env:COMPUTERNAME) " + ('=' * 40)
