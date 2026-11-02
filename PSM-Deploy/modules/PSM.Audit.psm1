<#
.SYNOPSIS
    READ-ONLY configuration check of a PSM server: end of every Deploy-PSM.ps1
    run (deployment and -RedoHardening) and tools\Test-PSMConfiguration.ps1.

.DESCRIPTION
    Reports configuration DEFECTS, changes NOTHING (no fix applied: each alert
    says what to do). Works on a PSM that PSM-Deploy did not deploy (PSM folder
    read from the service). Checks:
      - PSM service running, installed version = settings.psd1 PsmVersion;
      - last Hardening stage run by PSM-Deploy (state\progress.json);
      - drive permissions: Users / Authenticated Users / Everyone must not be
        able to write at the root of the local fixed drives (left as Windows
        set them when the CyberArk RunHardening step fails, e.g. EDR);
      - "Allow log on through Remote Desktop Services": the zone's session
        accounts listed, no session account of ANOTHER zone (zones.psd1 only,
        no server mapping);
      - local Administrators: PSMAdminConnect in, PSMConnect out;
      - AppLocker: Application Identity service running, Exe rules enforced;
      - zone / VIP consistency, RDP certificate, component account names.
    One line per check (OK / ALERT / INFO), then ONE framed alert listing the
    defects. An unexpected error is INFO ("check could not run"), never a stop.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AuditResults = New-Object System.Collections.Generic.List[object]

# Broad principals that must not write at a drive root of a PSM.
$script:BroadSids = @{ 'S-1-5-32-545' = 'BUILTIN\Users'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-1-0' = 'Everyone' }
# Write-type rights: create files / folders, delete children, delete, change
# permissions, take ownership, GENERIC_ALL, GENERIC_WRITE.
$script:WriteMask = 0x2 -bor 0x4 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000

function Add-PSMAuditResult {
    param(
        [Parameter(Mandatory)] [ValidateSet('OK', 'ALERT', 'INFO')] [string] $Status,
        [Parameter(Mandatory)] [string] $Check,
        [Parameter(Mandatory)] [string] $Detail,
        [string[]] $Lines = @()
    )
    $script:AuditResults.Add([pscustomobject]@{ Status = $Status; Check = $Check; Detail = $Detail; Lines = $Lines })
    $level = @{ OK = 'OK'; ALERT = 'WARN'; INFO = 'INFO' }[$Status]
    Write-PSMLog -Level $level -Message "Check [$Check] $Detail"
    foreach ($l in $Lines) { Write-PSMLog -Level $level -Message "    $l" }
}

function Invoke-PSMAuditCheck {
    # Runs one check; an unexpected error is reported as INFO and never stops the others.
    param([Parameter(Mandatory)] [string] $Check, [Parameter(Mandatory)] [scriptblock] $Body)
    try { & $Body }
    catch { Add-PSMAuditResult -Status INFO -Check $Check -Detail "check could not run: $($_.Exception.Message)" }
}

function ConvertTo-PSMAccountName {
    # Account name of a SID for display; the input when it does not translate.
    param([string] $Sid)
    try { return ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

function ConvertFrom-PSMUserRightLine {
    # SIDs of a secedit USER_RIGHTS line ("SeXxx = *S-1-5-32-544,DOMAIN\name");
    # a name that does not resolve is kept as is. Callers wrap in @().
    param([string] $Line)
    $sids = @()
    if (-not $Line -or $Line -notmatch '=') { return $sids }
    foreach ($h in (($Line -split '=', 2)[1]).Split(',')) {
        $h = $h.Trim().TrimStart('*')
        if (-not $h) { continue }
        if ($h -like 'S-1-*') { $sids += $h; continue }
        try   { $sids += ([System.Security.Principal.NTAccount]$h).Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $sids += $h }
    }
    return $sids
}

function Get-PSMUserRightSids {
    # Accounts holding a user right on this machine (effective policy, GPO
    # included), via secedit /export to a temp file deleted right after.
    param([Parameter(Mandatory)] [string] $Right)
    $tmp = Join-Path $env:TEMP ("psm-rights-{0}.inf" -f [guid]::NewGuid().ToString('N'))
    try {
        & secedit.exe /export /cfg $tmp /areas USER_RIGHTS /quiet | Out-Null
        if (-not (Test-Path -LiteralPath $tmp)) { throw "secedit /export produced no file (exit code $LASTEXITCODE)." }
        $line = @(Get-Content -LiteralPath $tmp | Where-Object { $_ -match ('^' + [regex]::Escape($Right) + '\s*=') }) | Select-Object -First 1
    }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    return @(ConvertFrom-PSMUserRightLine -Line $line)
}

function Get-PSMUserRightSource {
    # Who sets a user right: the winning GPO (RSoP precedence 1) or the local policy.
    param([Parameter(Mandatory)] [string] $Right)
    try {
        $w = Get-CimInstance -Namespace 'root\rsop\computer' -ClassName 'RSOP_UserPrivilegeRight' `
                 -Filter "UserRight='$Right' AND precedence=1" -ErrorAction Stop | Select-Object -First 1
    }
    catch { return 'local policy (GPO result not readable)' }
    if (-not $w) { return 'local policy (no GPO defines it)' }
    $name = [string]$w.GPOID
    if ($name -like 'CN=*') {
        try { $n = [string](([adsi]('LDAP://' + $w.GPOID)).displayName); if ($n) { $name = $n } } catch { }
    }
    return "GPO '$name'"
}

function Get-PSMZoneSessionAccounts {
    # Session accounts (PSMConnect / PSMAdminConnect) declared by a zone, with
    # their SID ($null when the account does not resolve). Callers wrap in @().
    param([Parameter(Mandatory)] $ZoneConfig)
    $rows = @()
    foreach ($key in 'PSMConnectUserName', 'PSMAdminConnectUserName') {
        $acct = Get-PSMConfigValue -Config $ZoneConfig -Key $key
        if (-not $acct) { continue }
        $sid = $null
        try { $sid = ([System.Security.Principal.NTAccount][string]$acct).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
        $rows += [pscustomobject]@{ Key = $key; Account = [string]$acct; Sid = $sid }
    }
    return $rows
}

function Compare-PSMSessionLogonRight {
    <#
        PURE: SIDs holding the RDS logon right vs the session accounts.
          -Mine   : the selected zone's accounts (objects with Account, Sid)
          -Others : the other zones' accounts (objects with Account, Sid, Zone)
        Returns @{ Missing = zone accounts not listed; Foreign = accounts of
        another zone that are listed }. An account shared by two zones is
        never "foreign".
    #>
    param([string[]] $Granted = @(), [object[]] $Mine = @(), [object[]] $Others = @())
    $mineSids = @($Mine | Where-Object { $_.Sid } | ForEach-Object { $_.Sid })
    $missing  = @($Mine | Where-Object { -not $_.Sid -or $Granted -notcontains $_.Sid })
    $seen = @{}
    $foreign = @()
    foreach ($o in $Others) {
        if (-not $o.Sid -or $mineSids -contains $o.Sid -or $Granted -notcontains $o.Sid -or $seen.ContainsKey($o.Sid)) { continue }
        $seen[$o.Sid] = $true
        $foreign += $o
    }
    return @{ Missing = $missing; Foreign = $foreign }
}

function Get-PSMBroadWriteAces {
    <#
        PURE: the Allow ACEs letting Users / Authenticated Users / Everyone
        write (rules with IdentityReference = SID, FileSystemRights,
        AccessControlType, PropagationFlags). Returns display strings.
    #>
    param([object[]] $Rules = @())
    $out = @()
    foreach ($r in $Rules) {
        $sid = if ($r.IdentityReference -is [System.Security.Principal.IdentityReference]) { $r.IdentityReference.Value } else { [string]$r.IdentityReference }
        if (-not $script:BroadSids.ContainsKey($sid)) { continue }
        if ([string]$r.AccessControlType -ne 'Allow') { continue }
        $rights = [int]$r.FileSystemRights
        if (-not ($rights -band $script:WriteMask)) { continue }
        $text = [string]$r.FileSystemRights
        if ($text -match '^-?\d+$') {   # generic bits have no enum name
            $names = @()
            if ($rights -band 0x10000000) { $names += 'GENERIC_ALL' }
            if ($rights -band 0x40000000) { $names += 'GENERIC_WRITE' }
            if ($names) { $text = $names -join ', ' }
        }
        $scope = if ([string]$r.PropagationFlags -match 'InheritOnly') { 'subfolders and files only' } else { 'this folder' }
        $out += "$($script:BroadSids[$sid]): $text ($scope)"
    }
    return $out
}

function Invoke-PSMConfigurationAudit {
    <#
        Runs every check (see the module header), prints one framed alert with
        the defects, returns the results (Status OK / ALERT / INFO, Check,
        Detail, Lines). READ-ONLY.
          -LastHardening    : state value 'LastHardening' written by Deploy-PSM
                              ($null = no run recorded on this server);
          -RdpCertificateOk : result of the RdpCertificate phase that just ran;
                              omitted -> checked here, report only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Zones,
        [Parameter(Mandatory)] [string] $ZoneKey,
        $LastHardening,
        [Nullable[bool]] $RdpCertificateOk
    )
    $script:AuditResults.Clear()
    $zoneCfg = $Zones[$ZoneKey]
    Write-PSMLog -Level INFO -Message "=== Configuration check (read-only) - $env:COMPUTERNAME - zone '$ZoneKey' ==="

    Invoke-PSMAuditCheck 'PSM service' {
        $svc = Get-Service -Name 'CyberArk Privileged Session Manager' -ErrorAction SilentlyContinue
        if (-not $svc) { Add-PSMAuditResult ALERT 'PSM service' 'not found - the PSM is not installed.'; return }
        $installed = Get-PSMInstalledVersion
        $expected  = [string]$Settings.PsmVersion
        $version   = if ($installed -is [version]) { "$installed" } else { 'version unreadable' }
        if ([string]$svc.Status -ne 'Running') {
            Add-PSMAuditResult ALERT 'PSM service' "$($svc.Status) ($version) - no session can open. See <PSM>\Logs\PSMConsole.log."
        }
        elseif (($installed -is [version]) -and $expected -and ('{0}.{1}' -f $installed.Major, $installed.Minor) -ne $expected) {
            Add-PSMAuditResult ALERT 'PSM service' "running, but version $installed is not the target $expected (settings.psd1 PsmVersion)."
        }
        else { Add-PSMAuditResult OK 'PSM service' "running ($version)." }
    }

    Invoke-PSMAuditCheck 'Hardening (last run)' {
        if ($null -eq $LastHardening) {
            Add-PSMAuditResult INFO 'Hardening (last run)' ('no Hardening run recorded by PSM-Deploy on this server (deployed before this check ' +
                'existed, or not by PSM-Deploy) - see the drive permissions check.')
        }
        elseif ([bool]$LastHardening.Succeeded) {
            Add-PSMAuditResult OK 'Hardening (last run)' "succeeded ($($LastHardening.Date))."
        }
        else {
            Add-PSMAuditResult ALERT 'Hardening (last run)' "FAILED ($($LastHardening.Date)): $($LastHardening.ErrorData)" -Lines @(
                "CyberArk log: $(if ($LastHardening.LogPath) { $LastHardening.LogPath } else { 'not given by the stage' })",
                "Fix the cause (e.g. EDR exclusion), then: .\Deploy-PSM.ps1 -Zone $ZoneKey -RedoHardening")
        }
    }

    Invoke-PSMAuditCheck 'Drive permissions' {
        $found = @()
        $drives = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object { "$($_.DeviceID)\" })
        foreach ($d in $drives) {
            $rules = (Get-Acl -LiteralPath $d).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            foreach ($a in @(Get-PSMBroadWriteAces -Rules @($rules))) { $found += "$d  $a" }
        }
        if ($found) {
            Add-PSMAuditResult ALERT 'Drive permissions' "users can write at the root of $((@($found | ForEach-Object { $_.Split(' ')[0] }) | Select-Object -Unique) -join ', ') - drives NOT hardened." -Lines (@($found) + @(
                'The CyberArk RunHardening step removes these permissions; they stay when it fails (e.g. EDR blocking C:\).',
                "Fix the cause, then: .\Deploy-PSM.ps1 -Zone $ZoneKey -RedoHardening"))
        }
        else { Add-PSMAuditResult OK 'Drive permissions' "no write access for Users / Authenticated Users / Everyone at the root of $($drives -join ', ')." }
    }

    Invoke-PSMAuditCheck 'RDS logon right' {
        $mine = @(Get-PSMZoneSessionAccounts -ZoneConfig $zoneCfg)
        if (-not $mine) {
            Add-PSMAuditResult INFO 'RDS logon right' "zone '$ZoneKey' declares no session account (PSMConnectUserName / PSMAdminConnectUserName) - nothing to compare."
            return
        }
        $others = @()
        foreach ($k in @($Zones.Keys | Where-Object { $_ -ne $ZoneKey } | Sort-Object)) {
            foreach ($a in @(Get-PSMZoneSessionAccounts -ZoneConfig $Zones[$k])) {
                $others += [pscustomobject]@{ Account = $a.Account; Sid = $a.Sid; Zone = $k }
            }
        }
        $right   = 'SeRemoteInteractiveLogonRight'
        $granted = @(Get-PSMUserRightSids -Right $right)
        $cmp     = Compare-PSMSessionLogonRight -Granted $granted -Mine $mine -Others $others
        if (-not $cmp.Missing -and -not $cmp.Foreign) {
            Add-PSMAuditResult OK 'RDS logon right' ("'Allow log on through Remote Desktop Services' lists the zone's session accounts " +
                "($(($mine | ForEach-Object { $_.Account }) -join ', ')) and no account of another zone.")
            return
        }
        $source = Get-PSMUserRightSource -Right $right
        $lines = @()
        foreach ($m in $cmp.Missing) {
            $why = if ($m.Sid) { 'not listed (groups are not expanded)' } else { 'does NOT resolve in the domain' }
            $lines += "MISSING   : $($m.Account) (zone '$ZoneKey') - $($why): PSM sessions under it are refused at RDP logon."
        }
        foreach ($f in $cmp.Foreign) {
            $lines += "OTHER ZONE: $($f.Account) (zone '$($f.Zone)') - never used by this PSM: the zones are no longer separated."
        }
        $holders = @($granted | ForEach-Object { ConvertTo-PSMAccountName -Sid $_ })
        $lines += "Listed now: $(if ($holders) { $holders -join ', ' } else { 'nobody' })"
        $lines += "Set by    : $source"
        if ($source -like "GPO *") { $lines += 'A GPO overrides the local policy at every refresh: the fix is on the AD side (one GPO per zone).' }
        else                        { $lines += "Local policy: .\Deploy-PSM.ps1 -Zone $ZoneKey -RedoHardening grants the zone's accounts again." }
        Add-PSMAuditResult ALERT 'RDS logon right' "does not match zone '$ZoneKey'." -Lines $lines
    }

    Invoke-PSMAuditCheck 'Local Administrators' {
        $adminAcct = Get-PSMConfigValue -Config $zoneCfg -Key 'PSMAdminConnectUserName'
        $connAcct  = Get-PSMConfigValue -Config $zoneCfg -Key 'PSMConnectUserName'
        if (-not $adminAcct -and -not $connAcct) {
            Add-PSMAuditResult INFO 'Local Administrators' "zone '$ZoneKey' declares no session account - nothing to compare."
            return
        }
        $bad = @()
        $unknown = @()
        if ($adminAcct) {
            $m = Test-PSMLocalAdminMember -Account $adminAcct
            if ($m -eq $false) { $bad += "$adminAcct is NOT a local Administrator - PVWA live session monitoring (shadowing) fails." }
            elseif ($null -eq $m) { $unknown += $adminAcct }
        }
        if ($connAcct) {
            $m = Test-PSMLocalAdminMember -Account $connAcct
            if ($m -eq $true) { $bad += "$connAcct IS a local Administrator - user sessions run under it: remove it (per-server AD ACL group)." }
            elseif ($null -eq $m) { $unknown += $connAcct }
        }
        if ($bad) { Add-PSMAuditResult ALERT 'Local Administrators' 'session accounts membership is wrong.' -Lines $bad }
        elseif ($unknown) { Add-PSMAuditResult INFO 'Local Administrators' "membership could not be verified for $($unknown -join ', ')." }
        else { Add-PSMAuditResult OK 'Local Administrators' "$adminAcct is a local Administrator, $connAcct is not." }
    }

    Invoke-PSMAuditCheck 'AppLocker' {
        $svc = Get-Service -Name 'AppIDSvc' -ErrorAction Stop
        [xml]$pol = Get-AppLockerPolicy -Effective -Xml
        $exe   = $pol.SelectSingleNode("//RuleCollection[@Type='Exe']")
        $rules = if ($exe) { @($exe.ChildNodes | Where-Object { $_.LocalName -like '*Rule' }).Count } else { 0 }
        $mode  = if ($exe) { [string]$exe.GetAttribute('EnforcementMode') } else { '' }
        if ([string]$svc.Status -ne 'Running') {
            Add-PSMAuditResult ALERT 'AppLocker' "Application Identity service (AppIDSvc) is $($svc.Status) - the AppLocker rules are NOT enforced."
        }
        elseif ($rules -eq 0) {
            Add-PSMAuditResult ALERT 'AppLocker' 'no Exe rule in the effective policy - the RunApplocker step did not apply it.'
        }
        elseif ($mode -eq 'AuditOnly') {
            Add-PSMAuditResult ALERT 'AppLocker' "$rules Exe rule(s) in AUDIT ONLY - nothing is blocked."
        }
        else { Add-PSMAuditResult OK 'AppLocker' "AppIDSvc running, $rules Exe rule(s) enforced." }
    }

    Invoke-PSMAuditCheck 'Zone (VIP)' {
        $z = Test-PSMZoneByVip -Zones $Zones -ZoneKey $ZoneKey
        if ($z -eq $false) { Add-PSMAuditResult ALERT 'Zone (VIP)' "$env:COMPUTERNAME is not behind a VIP of zone '$ZoneKey' (see the ZONE CHECK above)." }
        elseif ($z)        { Add-PSMAuditResult OK    'Zone (VIP)' "behind a VIP of zone '$ZoneKey'." }
        else               { Add-PSMAuditResult INFO  'Zone (VIP)' "zone '$ZoneKey' declares no VIP - nothing to cross-check." }
    }

    Invoke-PSMAuditCheck 'RDP certificate' {
        $ok = if ($null -ne $RdpCertificateOk) { [bool]$RdpCertificateOk } else { Invoke-PSMRdpCertificate -ZoneConfig $zoneCfg -ReportOnly }
        if ($ok) { Add-PSMAuditResult OK    'RDP certificate' 'nothing to report (see the RDP certificate lines above).' }
        else     { Add-PSMAuditResult ALERT 'RDP certificate' 'see the RDP CERTIFICATE alert above.' }
    }

    Invoke-PSMAuditCheck 'Component accounts' {
        $regCfg = Get-PSMConfigValue -Config $Settings -Key 'Registration'
        if (-not $regCfg -or -not (Get-PSMConfigValue -Config $regCfg -Key 'RenameComponents')) {
            Add-PSMAuditResult INFO 'Component accounts' 'Registration.RenameComponents is off - no naming convention to check.'
            return
        }
        $psmDir = Get-PSMInstalledPsmDir -Settings $Settings
        if (-not $psmDir) { Add-PSMAuditResult INFO 'Component accounts' 'no PSM installed.'; return }
        $rows = @(Get-PSMComponentAccountNames -Settings $Settings -PsmDir $psmDir)
        if (@($rows | Where-Object { $_.Current -eq '(unknown)' })) {
            Add-PSMAuditResult INFO 'Component accounts' "names not readable (basic_psm.ini / cred files under $psmDir)."
            return
        }
        $todo = @($rows | Where-Object { $_.Current -cne $_.Target })
        if ($todo) {
            Add-PSMAuditResult ALERT 'Component accounts' 'do not match the naming convention (settings.psd1 AppUserPattern / GwUserPattern).' -Lines @(
                $todo | ForEach-Object { "$($_.Role): $($_.Current) -> expected $($_.Target)" })
        }
        else { Add-PSMAuditResult OK 'Component accounts' "$(($rows | ForEach-Object { $_.Current }) -join ' / ') match the convention." }
    }

    $alerts = @($script:AuditResults | Where-Object { $_.Status -eq 'ALERT' })
    if ($alerts) {
        $lines = @()
        foreach ($a in $alerts) {
            $lines += "- $($a.Check): $($a.Detail)"
            foreach ($l in $a.Lines) { $lines += "    $l" }
        }
        $lines += 'This check changed nothing: fix each point, then run it again (.\tools\Test-PSMConfiguration.ps1).'
        Write-PSMAlert -Title "CONFIGURATION CHECK - $($alerts.Count) defect(s) on $env:COMPUTERNAME" -Lines $lines
    }
    else {
        $notRun = @($script:AuditResults | Where-Object { $_.Detail -like 'check could not run*' }).Count
        Write-PSMLog -Level OK -Message ("Configuration check: no defect found ($($script:AuditResults.Count) checks" +
            $(if ($notRun) { ", $notRun could not run - see the INFO lines" }) + ').')
    }
    return $script:AuditResults.ToArray()
}

Export-ModuleMember -Function Invoke-PSMConfigurationAudit, ConvertFrom-PSMUserRightLine, Compare-PSMSessionLogonRight,
    Get-PSMBroadWriteAces, Get-PSMUserRightSids, Get-PSMZoneSessionAccounts
