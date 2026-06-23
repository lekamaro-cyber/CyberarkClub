<#
.SYNOPSIS
    Verifies that a list of (account / server) pairs from a CSV is properly
    onboarded in CyberArk, then for each account retrieves:
      - its Safe
      - the list of all groups/members (permissions) of the Safe
      - the "external" domain group (excluding default groups)
      - the manager of that domain group, read from Active Directory.

.DESCRIPTION
    Relies on the CyberArk PVWA REST API (logon -> account search ->
    safe members -> logoff) and on ADSI (System.DirectoryServices) to resolve
    domain groups and their manager (ManagedBy attribute). ADSI needs NO RSAT module.

    The searched pair is:
        username (CSV column)  ==  userName of the CyberArk account
        host     (CSV column)  ==  address  of the CyberArk account (loose match)

    NO COMMAND-LINE ARGUMENTS: every setting (PVWA URL, credentials, file paths,
    options...) is hard-coded in the CONFIGURATION section right below. Just edit
    that section and run the script (e.g. from PowerShell ISE / VS Code / right-click
    "Run with PowerShell").

    The input CSV can be the output of extractSudoRootV0.7.ps1
    (Audit_Privileges_Unix_YYYY-MM.csv): the script reads its CA_Candidate column
    to decide whether a non-onboarded account is a real anomaly (CA_Candidate =
    YES/YES-SSH) or expected (NO = no privilege / offline host).

.NOTES
    Requires PowerShell 5.1+ . AD resolution uses ADSI (no RSAT module needed);
    it only runs when $SkipADLookup is left to $false.
#>

# =====================================================================================
# ============================  CONFIGURATION (EDIT THIS)  =============================
# =====================================================================================
# No command-line arguments: everything is set here. Just run the script.

# --- PVWA / CyberArk ---
$PvwaUrl  = 'https://oneconnection.intra.corp'   # <-- EDIT: PVWA URL
$AuthType = 'LDAP'                               # 'CyberArk' | 'LDAP' | 'RADIUS'

# --- PVWA credentials ---
# Leave $PvwaPassword empty ('') for a secure prompt at runtime (recommended).
# You may hard-code the password, but it will then be stored in CLEAR TEXT.
$PvwaUsername = ''                               # e.g. 'svc_cyberark_admin' (empty = full prompt)
$PvwaPassword = ''                               # empty = prompt at runtime

# --- Files ---
# Input CSV: account/server pairs (columns inventory,host,username...).
# Can also be the output of extractSudoRootV0.7.ps1 (UserSam,Server,...,CA_Candidate):
# columns and delimiter are auto-detected.
$CsvPath    = "$PSScriptRoot\Input\accounts.csv"
# Output: leave EMPTY to add the analysis columns to the input file itself (no new
# file, same rows, 1:1). Set a path only if you want a separate results file.
$OutputPath = ''

# --- CyberArk accounts source ---
# The script ALWAYS downloads all accounts once (extraction), saves them to the
# file below, then closes the session before processing (matching + AD), which
# runs offline.
$AccountsExtractPath = "$PSScriptRoot\Input\cyberark_accounts.csv"

# --- Input CSV columns (leave 'Auto' for auto-detection) ---
$UsernameColumn  = 'Auto'          # e.g. 'UserSam' / 'username' / 'userName'
$HostColumn      = 'Auto'          # e.g. 'Server' / 'host' / 'address'
$CandidateColumn = 'CA_Candidate'  # CyberArk candidacy column (extractSudoRoot)
$CsvDelimiter    = 'Auto'          # 'Auto' (detects , or ;), otherwise ',' or ';'

# --- host <-> CyberArk address matching ---
$AddressMatch = 'Hostname'         # 'Hostname' (short name) | 'Exact' | 'Contains'

# --- Domain group selection on the safe ---
# Primary rule: the domain group shares the last N characters of the safe name
# (e.g. safe 'HAR-G-FR-UNX-C-NPR' and group 'FR-G-GU-HAR-UNX-C-NPR' both end with
# 'C-NPR'). Set to 0 to disable this rule.
$SafeGroupSuffixLength = 5

# --- Active Directory ---
# Optional: target a specific domain controller to avoid referral latency.
# Leave empty ('') to let Windows pick the DC automatically.
$AdServer = ''                     # e.g. 'dc01.intra.corp'

# Domain (DNS name) hosting the groups. Used as the AD server when $AdServer is empty.
$AdDomain = ''                     # e.g. 'intra.corp'

# Additional domains to search when a group is NOT found in the default domain/OU.
# Tried in order, after the default domain. (Requires reachability / trust.)
$AdExtraDomains = @()              # e.g. @('emea.corp', 'apac.corp')

# OU that contains the domain groups granted on the safes. When set, the script
# enumerates this OU ONCE (all groups + their ManagedBy) to build an in-memory map,
# which is far faster than one AD query per group.
$GroupsOU = ''                     # e.g. 'OU=PAM-Groups,OU=Groups,DC=intra,DC=corp'

# When a group is NOT found in the OU map, optionally search the whole domain for it.
# Set to $false if the OU already contains every relevant group (avoids any domain scan).
$DomainSearchFallback = $true

# --- Options ---
$SkipADLookup        = $false      # $true = do not query Active Directory
$SkipIPCheck         = $false      # $true = do not attempt the IP fallback (DNS)
$SkipCertificateCheck = $false     # $true = ignore the PVWA TLS validation
$DebugMode           = $true       # $true = print in detail EVERYTHING the script does
$MaxAccounts         = 10          # max number of accounts (rows) to process; 0 = all

# --- Default safe groups to exclude in order to isolate the external domain group ---
# Exact names:
$DefaultSafeGroups = @(
    'Vault Admins', 'Auditors', 'Backup Users', 'DR Users', 'Master',
    'Notification Engineers', 'Operators', 'PVWAUsers', 'PVWAMonitor',
    'PVWAAppUsers', 'PVWAGWAccounts', 'PVWAGWUser', 'PSMUsers', 'PSMAppUsers',
    'PSMMaster', 'PSMP_ADB_AppUsers', 'Administrator', 'Administrators',
    'Batch', 'PasswordManager', 'ApproverGroup', 'AIMWebService',
    'ApplicationManagers', 'EPVMaintenanceUsers', 'xrayGroup',
    'PAM_CyberArk_Manager'
)
# Wildcard patterns for org-specific default "business" groups,
# e.g. FR_GUA_PAM_Auth_Admins / _Auditors / _Safe_Managers, PAM_CyberArk_Manager...
$DefaultSafeGroupPatterns = @(
    '*_PAM_Auth_*',      # FR_GUA_PAM_Auth_Admins / _Auditors / _Safe_Managers
    'PAM_CyberArk_*',    # PAM_CyberArk_Manager
    '*_Auth_Admins',
    '*_Auth_Auditors',
    '*_Auth_Safe_Managers',
    '*_Safe_Managers'
)
# =====================================================================================
# ==============================  END OF CONFIGURATION  ===============================
# =====================================================================================

$Credential = $null

#region ----------------------------------------------------------- Prerequisites & TLS
$ErrorActionPreference = 'Stop'

# Force TLS 1.2 (PVWA often rejects older protocols)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

if ($SkipCertificateCheck) {
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $script:IrmExtra = @{ SkipCertificateCheck = $true }
    }
    else {
        add-type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
            }
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        $script:IrmExtra = @{}
    }
}
else {
    $script:IrmExtra = @{}
}

$PvwaUrl = $PvwaUrl.TrimEnd('/')
$ApiBase = "$PvwaUrl/PasswordVault/api"

# Active Directory access uses ADSI (System.DirectoryServices), which does NOT
# require the RSAT ActiveDirectory module. It works on any domain-joined host,
# including hardened PAM servers. AD is only used when $SkipADLookup is $false.
#endregion

#region ----------------------------------------------------------- CyberArk functions
function Invoke-PvwaLogon {
    param([pscredential]$Cred, [string]$Type)

    $url = "$ApiBase/auth/$Type/Logon"
    $body = @{
        username          = $Cred.UserName
        password          = $Cred.GetNetworkCredential().Password
        concurrentSession = $true
    } | ConvertTo-Json

    Write-Verbose "Logon on $url (AuthType=$Type)"
    $token = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType 'application/json' @script:IrmExtra
    # The returned token is a string (sometimes quoted) to put in the Authorization header
    return ($token -replace '"', '')
}

function Invoke-PvwaLogoff {
    param([string]$Token)
    try {
        Invoke-RestMethod -Uri "$ApiBase/auth/Logoff" -Method Post `
            -Headers @{ Authorization = $Token } @script:IrmExtra | Out-Null
    }
    catch { Write-Verbose "Logoff: $($_.Exception.Message)" }
}

function Get-HttpStatusCode {
    <#  Extract the HTTP status code from a terminating error (PS 5.1 & Core).  #>
    param($ErrorRecord)
    try { if ($ErrorRecord.Exception.Response) { return [int]$ErrorRecord.Exception.Response.StatusCode } } catch {}
    if ("$($ErrorRecord.Exception.Message)" -match '\((\d{3})\)') { return [int]$Matches[1] }
    return 0
}

function Invoke-PvwaRequest {
    <#  Wrapper around Invoke-RestMethod that uses $script:Token and, on a 401
        (expired/lost session), automatically re-logs in and retries the request.  #>
    param([string]$Url, [string]$Method = 'Get', $Body = $null)

    $tries = 0
    while ($true) {
        $tries++
        try {
            $headers = @{ Authorization = $script:Token }
            if ($Body) {
                return Invoke-RestMethod -Uri $Url -Method $Method -Headers $headers -Body $Body -ContentType 'application/json' @script:IrmExtra
            }
            return Invoke-RestMethod -Uri $Url -Method $Method -Headers $headers @script:IrmExtra
        }
        catch {
            $status = Get-HttpStatusCode $_
            if ($status -eq 401 -and $tries -le $script:MaxRelogon) {
                Write-Host "    Session lost (401) -> re-logon ($tries/$script:MaxRelogon)..." -ForegroundColor Yellow
                Start-Sleep -Milliseconds 500
                $script:Token = Invoke-PvwaLogon -Cred $script:Credential -Type $script:AuthType
                continue   # retry the same request with the fresh token
            }
            throw
        }
    }
}

function Get-PvwaAllAccounts {
    <#  Downloads ALL accounts once (paged). One bulk extraction instead of
        one search per CSV row, so the session can be closed quickly afterwards.  #>
    $all = @()
    $offset = 0
    $limit = 1000

    do {
        $url = "$ApiBase/Accounts?limit=$limit&offset=$offset"
        $resp = Invoke-PvwaRequest -Url $url
        if ($resp.value) { $all += $resp.value }
        $offset += $limit
        $hasMore = ($null -ne $resp.value) -and ($resp.value.Count -eq $limit)
        Write-Host "    ... $($all.Count) accounts loaded" -ForegroundColor Gray
    } while ($hasMore)

    return $all
}

function Get-PvwaSafeMembers {
    param([string]$SafeName)
    $url = "$ApiBase/Safes/$([uri]::EscapeDataString($SafeName))/Members?limit=1000"
    $resp = Invoke-PvwaRequest -Url $url
    return $resp.value
}
#endregion

#region ----------------------------------------------------------- Matching helpers
# Caches to avoid repeated network round-trips (DNS / Active Directory)
$script:DnsCache = @{}
$script:AdCache = @{}      # group name -> resolution (fallback direct AD search)
$script:GroupMap = @{}     # group name / sAMAccountName -> { GroupName; ManagedBy } from the OU
$script:MgrCache = @{}     # manager DN -> { Name; Email }
$script:GroupMapBuilt = $false

function Get-AdSearchRoot {
    <#  Returns a System.DirectoryServices.DirectoryEntry for the search root:
        the given DN if provided, otherwise the domain root (from $AdDomain or RootDSE).
        Honors $AdServer / $AdDomain as the LDAP server.  #>
    param([string]$Dn)
    $srv = if ($AdServer) { $AdServer } elseif ($AdDomain) { $AdDomain } else { $null }
    if (-not $Dn) {
        if ($AdDomain) { $Dn = 'DC=' + ($AdDomain -replace '\.', ',DC=') }
        else { try { $Dn = "$(([adsi]'LDAP://RootDSE').defaultNamingContext)" } catch { $Dn = '' } }
    }
    $path = if ($srv) { "LDAP://$srv/$Dn" } else { "LDAP://$Dn" }
    return New-Object System.DirectoryServices.DirectoryEntry($path)
}

function Build-GroupManagerMap {
    <#  Enumerate the configured OU ONCE (all groups + their ManagedBy) into
        $script:GroupMap via ADSI. Much faster than one query per group.  #>
    if ($SkipADLookup) { Write-Host "OU group map skipped: AD lookup disabled (`$SkipADLookup = `$true)." -ForegroundColor Yellow; return }
    if (-not $GroupsOU) { Write-Host "OU group map skipped: `$GroupsOU is empty (will search AD per group)." -ForegroundColor Yellow; return }
    try {
        $root = Get-AdSearchRoot -Dn $GroupsOU
        $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
        $ds.Filter = '(objectClass=group)'
        $ds.PageSize = 1000
        [void]$ds.PropertiesToLoad.Add('name')
        [void]$ds.PropertiesToLoad.Add('samaccountname')
        [void]$ds.PropertiesToLoad.Add('managedby')
        $found = $ds.FindAll()
        $n = 0
        foreach ($r in $found) {
            $nm = if ($r.Properties['name'].Count) { "$($r.Properties['name'][0])" } else { '' }
            $sam = if ($r.Properties['samaccountname'].Count) { "$($r.Properties['samaccountname'][0])" } else { '' }
            $mb = if ($r.Properties['managedby'].Count) { "$($r.Properties['managedby'][0])" } else { '' }
            $entry = [pscustomobject]@{ GroupName = $nm; ManagedBy = $mb }
            if ($nm) { $script:GroupMap[$nm.ToLower()] = $entry; $n++ }
            if ($sam) { $script:GroupMap[$sam.ToLower()] = $entry }
        }
        $script:GroupMapBuilt = $true
        Write-Host "OU group map: $n group(s) enumerated from $GroupsOU" -ForegroundColor DarkCyan
    }
    catch {
        Write-Warning "Could not enumerate OU '$GroupsOU': $($_.Exception.Message). Falling back to per-group AD search."
    }
}

function Resolve-ManagerByDN {
    <#  Resolve a ManagedBy DN to a manager (name + email) via ADSI, cached by DN.
        Optional $Server points the bind at a specific domain/DC (cross-domain).  #>
    param([string]$Dn, [string]$Server)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return $null }
    if ($script:MgrCache.ContainsKey($Dn)) { return $script:MgrCache[$Dn] }
    $m = $null
    try {
        $srv = if ($Server) { $Server } elseif ($AdServer) { $AdServer } elseif ($AdDomain) { $AdDomain } else { $null }
        $path = if ($srv) { "LDAP://$srv/$Dn" } else { "LDAP://$Dn" }
        $u = New-Object System.DirectoryServices.DirectoryEntry($path)
        $disp = "$($u.Properties['displayName'].Value)"
        if (-not $disp) { $disp = "$($u.Properties['cn'].Value)" }
        $mail = "$($u.Properties['mail'].Value)"
        if ($disp -or $mail) { $m = [pscustomobject]@{ Name = $disp; Email = $mail } }
    }
    catch { Write-Verbose "Manager DN not resolved ($Dn): $($_.Exception.Message)" }
    $script:MgrCache[$Dn] = $m
    return $m
}

function Search-GroupInDomain {
    <#  ADSI search for a group by cn/sAMAccountName in a given domain (empty = default).
        Returns @{ GroupName; ManagedBy; Server; DomainLabel } or $null.  #>
    param([string]$Name, [string]$Domain)
    try {
        $f = $Name -replace '([\\\*\(\)\/])', '\$1'   # escape LDAP filter chars
        if ($Domain) {
            $srv = $Domain
            $dn = 'DC=' + ($Domain -replace '\.', ',DC=')
        }
        else {
            $srv = if ($AdServer) { $AdServer } elseif ($AdDomain) { $AdDomain } else { $null }
            if ($AdDomain) { $dn = 'DC=' + ($AdDomain -replace '\.', ',DC=') }
            else { try { $dn = "$(([adsi]'LDAP://RootDSE').defaultNamingContext)" } catch { $dn = '' } }
        }
        $path = if ($srv) { "LDAP://$srv/$dn" } else { "LDAP://$dn" }
        $root = New-Object System.DirectoryServices.DirectoryEntry($path)
        $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
        $ds.Filter = "(&(objectClass=group)(|(cn=$f)(samAccountName=$f)))"
        $ds.PageSize = 10
        [void]$ds.PropertiesToLoad.Add('name')
        [void]$ds.PropertiesToLoad.Add('managedby')
        $r1 = $ds.FindOne()
        if ($r1) {
            return [pscustomobject]@{
                GroupName   = if ($r1.Properties['name'].Count) { "$($r1.Properties['name'][0])" } else { $Name }
                ManagedBy   = if ($r1.Properties['managedby'].Count) { "$($r1.Properties['managedby'][0])" } else { '' }
                Server      = $srv
                DomainLabel = if ($Domain) { $Domain } else { 'default' }
            }
        }
    }
    catch { Write-Verbose "Group search failed in domain '$Domain' for $Name : $($_.Exception.Message)" }
    return $null
}
}

function Get-CachedDomainGroup {
    <#  Resolve-DomainGroupAndManager with a cache keyed by group name, so a group
        shared by many safes triggers only ONE resolution.  #>
    param([string]$Name)
    if (-not $script:AdCache.ContainsKey($Name)) {
        $script:AdCache[$Name] = Resolve-DomainGroupAndManager -MemberName $Name
    }
    return $script:AdCache[$Name]
}

function Test-AddressMatch {
    param([string]$Address, [string]$HostValue, [string]$Strategy)
    if ([string]::IsNullOrWhiteSpace($Address) -or [string]::IsNullOrWhiteSpace($HostValue)) { return $false }
    $a = $Address.Trim().ToLower()
    $h = $HostValue.Trim().ToLower()
    switch ($Strategy) {
        'Exact' { return ($a -eq $h) }
        'Contains' { return ($a -like "*$h*") }
        'Hostname' {
            $shortA = $a.Split('.')[0]
            $shortH = $h.Split('.')[0]
            return ($shortA -eq $shortH -or $a -eq $h)
        }
    }
    return $false
}

function Test-IsDefaultGroup {
    <#  True if the safe member is a default group (exact name or matching pattern).  #>
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $short = $Name
    if ($short -match '\\') { $short = $short.Split('\')[-1] }   # strip DOMAIN\ prefix
    if ($DefaultSafeGroups -contains $Name -or $DefaultSafeGroups -contains $short) { return $true }
    foreach ($p in $DefaultSafeGroupPatterns) { if ($short -like $p) { return $true } }
    return $false
}

function Split-NameTokens {
    <#  Splits a name into lowercase tokens on '-', '_' and whitespace.  #>
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return @() }
    return @($Name -split '[-_\s]+' | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
}

function Test-SuffixMatch {
    <#  True if A and B share their last $Len characters (case-insensitive).
        Ex.: 'HAR-G-FR-UNX-C-NPR' and 'FR-G-GU-HAR-UNX-C-NPR' both end with 'C-NPR'.  #>
    param([string]$A, [string]$B, [int]$Len)
    if ($Len -le 0 -or [string]::IsNullOrWhiteSpace($A) -or [string]::IsNullOrWhiteSpace($B)) { return $false }
    $a = $A.Trim().ToLower()
    $b = $B.Trim().ToLower()
    if ($a.Length -lt $Len -or $b.Length -lt $Len) { return ($a -eq $b) }
    return ($a.Substring($a.Length - $Len) -eq $b.Substring($b.Length - $Len))
}

function Get-NameSimilarityScore {
    <#  Token-overlap (Jaccard) score between a group name and the safe name.
        Ex.: safe 'HAR-G-FR-UNX-C-NPR' vs group 'FR-G-GU-HAR-UNX-C-NPR' -> ~0.86.  #>
    param([string]$Name, [string]$Reference)
    $a = Split-NameTokens $Name
    $b = Split-NameTokens $Reference
    if ($a.Count -eq 0 -or $b.Count -eq 0) { return 0 }
    $common = @($a | Where-Object { $b -contains $_ } | Select-Object -Unique)
    $union = @($a + $b | Select-Object -Unique)
    if ($union.Count -eq 0) { return 0 }
    return [math]::Round($common.Count / $union.Count, 3)
}

function Resolve-HostIPAddress {
    <#  Resolves a hostname to its IPv4 address(es) via DNS. Returns an array (empty on failure).
        Results are cached so a repeated host is resolved only once.  #>
    param([string]$HostValue)

    if ([string]::IsNullOrWhiteSpace($HostValue)) { return @() }
    $key = $HostValue.ToLower().Trim()
    if ($script:DnsCache.ContainsKey($key)) { return $script:DnsCache[$key] }

    # If the host is already an IP, return it as-is
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($HostValue, [ref]$parsed)) { $script:DnsCache[$key] = @($HostValue); return $script:DnsCache[$key] }

    $out = @()
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($HostValue)
        $out = @($addrs |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            ForEach-Object { $_.IPAddressToString } |
            Select-Object -Unique)
    }
    catch {
        Write-Verbose "DNS resolution failed for '$HostValue': $($_.Exception.Message)"
        $out = @()
    }
    $script:DnsCache[$key] = $out
    return $out
}

function Resolve-DomainGroupAndManager {
    <#
        For a safe member name (potentially a domain group), tries to resolve it
        in AD and returns the manager (ManagedBy).
    #>
    param([string]$MemberName)

    $result = [pscustomobject]@{
        IsDomainGroup = $false
        GroupName     = $MemberName
        Manager       = $null
        ManagerEmail  = $null
        ManagerSource = $null
    }

    if ($SkipADLookup) { return $result }

    # The name may be "DOMAIN\Group", "Group@domain" or "Group"
    $name = $MemberName
    if ($name -match '\\') { $name = $name.Split('\')[-1] }
    if ($name -match '@') { $name = $name.Split('@')[0] }

    # 1) Fast path: look the group up in the pre-built OU map (no AD round-trip)
    $entry = $script:GroupMap[$name.ToLower()]
    if ($entry) {
        $result.IsDomainGroup = $true
        $result.GroupName = $entry.GroupName
        if ($entry.ManagedBy) {
            $mgr = Resolve-ManagerByDN -Dn $entry.ManagedBy
            if ($mgr) { $result.Manager = $mgr.Name; $result.ManagerEmail = $mgr.Email; $result.ManagerSource = 'OU.ManagedBy' }
        }
        return $result
    }

    # 2) Fallback: ADSI search, default domain first then each extra domain in the list.
    #    Skipped entirely when $DomainSearchFallback is $false (no domain scan).
    if (-not $DomainSearchFallback) { return $result }
    $domainsToTry = @('') + @($AdExtraDomains)   # '' = default domain
    foreach ($dom in $domainsToTry) {
        $hit = Search-GroupInDomain -Name $name -Domain $dom
        if ($hit) {
            $result.IsDomainGroup = $true
            $result.GroupName = $hit.GroupName
            if ($hit.ManagedBy) {
                $mgr = Resolve-ManagerByDN -Dn $hit.ManagedBy -Server $hit.Server
                if ($mgr) { $result.Manager = $mgr.Name; $result.ManagerEmail = $mgr.Email }
            }
            $result.ManagerSource = "AD.ManagedBy ($($hit.DomainLabel))"
            break
        }
    }

    return $result
}
#endregion

#region ----------------------------------------------------------- Main program
if (-not (Test-Path -LiteralPath $CsvPath)) { throw "CSV file not found: $CsvPath" }

# Build credentials from the CONFIGURATION section (prompt if password left empty)
if (-not $Credential) {
    if ($PvwaUsername -and $PvwaPassword) {
        $secure = ConvertTo-SecureString $PvwaPassword -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($PvwaUsername, $secure)
    }
    elseif ($PvwaUsername) {
        $Credential = Get-Credential -UserName $PvwaUsername -Message "CyberArk PVWA password ($AuthType)"
    }
    else {
        $Credential = Get-Credential -Message "CyberArk PVWA credentials ($AuthType)"
    }
}

# Session state used by Invoke-PvwaRequest for transparent re-logon on 401
$script:Credential = $Credential
$script:AuthType   = $AuthType
$script:Token      = $null
$script:MaxRelogon = 3        # max re-logon attempts per request when the session is lost

# Auto-detect the delimiter from the header when set to 'Auto' (extractSudoRoot output uses ';')
if ($CsvDelimiter -eq 'Auto') {
    $headerLine = Get-Content -LiteralPath $CsvPath -TotalCount 1
    $CsvDelimiter = if ($headerLine -match ';') { ';' } else { ',' }
}

$rows = Import-Csv -LiteralPath $CsvPath -Delimiter $CsvDelimiter
if ($rows.Count -eq 0) { throw "The CSV contains no rows." }
$cols = $rows[0].PSObject.Properties.Name

# Limit the number of processed rows (debug / test)
$totalRows = $rows.Count
if ($MaxAccounts -gt 0 -and $rows.Count -gt $MaxAccounts) {
    $rows = @($rows | Select-Object -First $MaxAccounts)
    Write-Host "LIMIT: processing the first $MaxAccounts rows out of $totalRows (MaxAccounts=$MaxAccounts)." -ForegroundColor Yellow
}

# Resolve the username/host columns: use the configured name if present,
# otherwise (or when set to 'Auto') fall back to known alternatives.
function Resolve-Column {
    param([string]$Requested, [string[]]$Fallbacks, [string[]]$Available)
    if ($Requested -and $Requested -ne 'Auto' -and ($Available -contains $Requested)) { return $Requested }
    foreach ($f in $Fallbacks) { if ($Available -contains $f) { return $f } }
    return $null
}
$UsernameColumn = Resolve-Column -Requested $UsernameColumn -Fallbacks @('username', 'UserSam', 'userName', 'user', 'Nom de l''utilisateur') -Available $cols
$HostColumn = Resolve-Column -Requested $HostColumn -Fallbacks @('host', 'Server', 'address', 'NAME_SERVER', 'Adresse') -Available $cols
if (-not $UsernameColumn -or -not $HostColumn) {
    throw "Cannot find the username/host columns in the CSV. Columns found: $($cols -join ', ')"
}
$HasCandidate = ($cols -contains $CandidateColumn)
# Destination: empty $OutputPath => enrich the input file in place (no new file)
$DestPath = if ([string]::IsNullOrWhiteSpace($OutputPath)) { $CsvPath } else { $OutputPath }
$OutDir = Split-Path -Parent $DestPath
if ($OutDir -and -not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}
Write-Host "Columns used: username='$UsernameColumn', host='$HostColumn'$(if ($HasCandidate) { ", candidate='$CandidateColumn'" })" -ForegroundColor DarkCyan
if ($DebugMode) {
    Write-Host "[DEBUG] ===== Configuration =====" -ForegroundColor Magenta
    Write-Host "[DEBUG] PVWA=$PvwaUrl | AuthType=$AuthType | User=$($Credential.UserName)" -ForegroundColor DarkGray
    Write-Host "[DEBUG] CSV=$CsvPath (delim='$CsvDelimiter') | Output=$DestPath" -ForegroundColor DarkGray
    Write-Host "[DEBUG] AddressMatch=$AddressMatch | SuffixLen=$SafeGroupSuffixLength | SkipAD=$SkipADLookup | SkipIP=$SkipIPCheck" -ForegroundColor DarkGray
    Write-Host "[DEBUG] MaxAccounts=$MaxAccounts (rows to process=$($rows.Count))" -ForegroundColor DarkGray
}

$results     = New-Object System.Collections.Generic.List[object]
$safeMembersCache = @{}
$safeMembersError = @{}
$neededSafes = New-Object 'System.Collections.Generic.HashSet[string]'
$scriptStart = Get-Date

# Build the OU group->manager map FIRST (one AD enumeration), before anything else,
# so later group resolution is just an in-memory lookup.
Build-GroupManagerMap
$tMap = Get-Date

try {
    # ============================= PHASE 1: EXTRACTION (session open) =============================
    Write-Host "Connecting to PVWA $PvwaUrl ..." -ForegroundColor Cyan
    $script:Token = Invoke-PvwaLogon -Cred $Credential -Type $AuthType
    Write-Host "Connected." -ForegroundColor Green

    # 1a) Extraction: all accounts in one shot, then save the extract
    Write-Host "Extracting all accounts from the PVWA..." -ForegroundColor Cyan
    $allAccounts = Get-PvwaAllAccounts
    try {
        $extractDir = Split-Path -Parent $AccountsExtractPath
        if ($extractDir -and -not (Test-Path -LiteralPath $extractDir)) { New-Item -ItemType Directory -Force -Path $extractDir | Out-Null }
        $allAccounts |
            Select-Object name, userName, address, platformId, safeName,
                @{ n = 'cpmStatus'; e = { $_.secretManagement.status } },
                @{ n = 'cpmManaged'; e = { $_.secretManagement.automaticManagementEnabled } } |
            Export-Csv -LiteralPath $AccountsExtractPath -NoTypeInformation -Encoding UTF8
        Write-Host "Accounts extract saved: $AccountsExtractPath" -ForegroundColor DarkCyan
    }
    catch { Write-Warning "Could not save the extract: $($_.Exception.Message)" }
    Write-Host " $($allAccounts.Count) accounts loaded." -ForegroundColor Green

    # 1b) Index accounts by user name (plain arrays: no generic List nor @() on a
    #     collection, which can fail in restricted language mode)
    $caByUser = @{}
    foreach ($a in $allAccounts) {
        $k = "$($a.userName)".ToLower().Trim()
        if (-not $k) { continue }
        if ($caByUser.ContainsKey($k)) { $caByUser[$k] = $caByUser[$k] + $a }
        else { $caByUser[$k] = @($a) }
    }

    # ============================= PHASE 2: MATCHING (memory + DNS, no API call) =================
    $tExtract = Get-Date
    $i = 0
    foreach ($row in $rows) {
        $i++
        $username = "$($row.$UsernameColumn)".Trim()
        $hostName = "$($row.$HostColumn)".Trim()
        $candidate = if ($HasCandidate) { "$($row.$CandidateColumn)".Trim() } else { $null }
        Write-Progress -Activity "Matching CyberArk" -Status "$i/$($rows.Count): $username@$hostName" -PercentComplete (($i / $rows.Count) * 100)

        # Start from the original row (keep ALL its columns), then add/refresh the
        # analysis columns. This guarantees one output row per input row (no extra rows).
        $rec = [ordered]@{}
        foreach ($p in $row.PSObject.Properties) { $rec[$p.Name] = $p.Value }
        foreach ($c in 'Onboarded', 'OnboardingAssessment', 'MatchType', 'ResolvedIP',
            'AccountName', 'AccountAddress', 'PlatformId', 'SafeName', 'AllSafeGroups',
            'ExternalDomainGroup', 'GroupSafeSimilarity', 'GroupManager', 'GroupManagerEmail', 'Notes') {
            $rec[$c] = $null
        }
        $rec['Onboarded'] = 'No'
        $results.Add($rec)

      try {
        if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($hostName)) {
            $rec.Notes = 'Row skipped (empty username or host)'; continue
        }

        $accts = $caByUser[$username.ToLower()]          # array of account objects, or $null
        $acctCount = if ($null -ne $accts) { $accts.Count } else { 0 }

        if ($DebugMode) {
            if ($acctCount -gt 0) {
                Write-Host "[DEBUG] Row $i : $username@$hostName -> $acctCount account(s):" -ForegroundColor DarkGray
                foreach ($a in $accts) {
                    Write-Host "[DEBUG]     name='$($a.name)' addr='$($a.address)' safe='$($a.safeName)' plat='$($a.platformId)'" -ForegroundColor DarkGray
                }
            }
            else {
                Write-Host "[DEBUG] Row $i : $username@$hostName -> 0 account for this user" -ForegroundColor DarkGray
            }
        }

        # Match by hostname (no @() / pipeline, to stay safe in restricted language mode)
        $match = $null
        if ($acctCount -gt 0) {
            foreach ($a in $accts) {
                if (Test-AddressMatch -Address $a.address -HostValue $hostName -Strategy $AddressMatch) {
                    $match = $a; $rec.MatchType = 'Hostname'; break
                }
            }
        }

        # IP fallback (DNS), still no CyberArk call
        if (-not $match -and -not $SkipIPCheck -and $acctCount -gt 0) {
            $ips = Resolve-HostIPAddress -HostValue $hostName
            if ($ips.Count -gt 0) {
                $rec.ResolvedIP = ($ips -join '; ')
                foreach ($ip in $ips) {
                    foreach ($a in $accts) {
                        if ("$($a.address)" -eq $ip) { $match = $a; $rec.MatchType = "IP ($ip)"; break }
                    }
                    if ($match) { break }
                }
            }
            else { $rec.ResolvedIP = 'unresolved' }
        }

        if (-not $match) {
            if ($DebugMode) { Write-Host "[DEBUG]   -> NOT ONBOARDED (no address match)" -ForegroundColor DarkYellow }
            $rec.Notes = 'Account not onboarded (no username+address match, by name or IP)'
            switch -Regex ($candidate) {
                '^(?i)YES'             { $rec.OnboardingAssessment = 'ANOMALY - CyberArk candidate not onboarded' }
                '^(?i)CHECK-INVENTORY' { $rec.OnboardingAssessment = 'TO CHECK - unknown inventory status' }
                '^(?i)NO$'             { $rec.OnboardingAssessment = 'Normal - not a candidate (no privilege / offline)' }
                default                { $rec.OnboardingAssessment = if ($HasCandidate) { 'Not a candidate (empty CA_Candidate)' } else { 'Not assessed (no CA_Candidate column)' } }
            }
            continue
        }

        $rec.Onboarded = 'Yes'
        $rec.OnboardingAssessment = if ($candidate -match '^(?i)NO$') { 'Onboarded (though not a candidate - to confirm)' } else { 'OK - onboarded' }
        $rec.AccountName = $match.name
        $rec.AccountAddress = $match.address
        $rec.PlatformId = $match.platformId
        $rec.SafeName = $match.safeName
        if ($match.safeName) { [void]$neededSafes.Add($match.safeName) }
        if ($DebugMode) { Write-Host "[DEBUG]   -> ONBOARDED ($($rec.MatchType)): account '$($match.name)' address '$($match.address)' safe '$($match.safeName)'" -ForegroundColor Green }
      }
      catch {
        $rec.Notes = "Row processing error: $($_.Exception.Message)"
        if ($DebugMode) { Write-Host "[DEBUG]   -> ERROR row $i : $($_.Exception.Message)" -ForegroundColor Red }
      }
    }
    Write-Progress -Activity "Matching CyberArk" -Completed
    $tMatch = Get-Date
    if ($DebugMode) { Write-Host "[DEBUG] Safes to query: $((@($neededSafes)) -join ', ')" -ForegroundColor Magenta }

    # ============================= PHASE 3: Members of the matched safes (session open) ===========
    Write-Host "Reading members of $($neededSafes.Count) safe(s)..." -ForegroundColor Cyan
    $sN = 0
    foreach ($safe in $neededSafes) {
        $sN++
        Write-Progress -Activity "Reading safe members" -Status "$sN/$($neededSafes.Count): $safe" -PercentComplete (($sN / [Math]::Max(1, $neededSafes.Count)) * 100)
        try {
            $m = Get-PvwaSafeMembers -SafeName $safe
            $safeMembersCache[$safe] = $m
            Write-Host "    [$safe] $(@($m).Count) member(s)" -ForegroundColor Gray
        }
        catch {
            $safeMembersCache[$safe] = $null
            $safeMembersError[$safe] = $_.Exception.Message
            Write-Warning "    [$safe] error reading members: $($_.Exception.Message)"
        }
    }
    Write-Progress -Activity "Reading safe members" -Completed
    $tMembers = Get-Date
}
finally {
    # ============================= PHASE 4: Close the session (extraction done) ===========
    if ($script:Token) { Invoke-PvwaLogoff -Token $script:Token }
    Write-Host "CyberArk session closed (extraction done)." -ForegroundColor Cyan
}

# ============================= PHASE 5: OFFLINE enrichment (external group + AD manager) =====
# Resolve each UNIQUE safe only ONCE (many accounts can share a safe), and run at
# most one AD lookup for the chosen group (cached). This is where AD is the bottleneck.
Write-Host "Resolving domain groups and managers (Active Directory)..." -ForegroundColor Cyan
$onboardedRecs = @($results | Where-Object { $_.Onboarded -eq 'Yes' })
$safeNames = @($onboardedRecs | ForEach-Object { $_.SafeName } | Select-Object -Unique)
$safeResolution = @{}
$sCount = 0

foreach ($safe in $safeNames) {
    $sCount++
    Write-Progress -Activity "AD resolution" -Status "$sCount/$($safeNames.Count): $safe" -PercentComplete (($sCount / [Math]::Max(1, $safeNames.Count)) * 100)

    $res = [ordered]@{ AllSafeGroups = $null; ExternalDomainGroup = $null; Score = $null; Manager = $null; ManagerEmail = $null; Notes = $null }
    $members = $safeMembersCache[$safe]
    if (-not $members) {
        $reason = if ($safeMembersError.ContainsKey($safe)) { $safeMembersError[$safe] } else { 'no members returned by the API' }
        $res.Notes = "Safe members unavailable: $reason"
        $safeResolution[$safe] = $res
        if ($DebugMode) { Write-Host "[DEBUG] safe '$safe': MEMBERS UNAVAILABLE ($reason)" -ForegroundColor Red }
        continue
    }
    $res.AllSafeGroups = (($members | ForEach-Object { "$($_.memberName)[$($_.memberType)]" }) -join '; ')

    # Candidates = members that are NOT default groups and NOT plain users.
    $candidates = $members | Where-Object { -not (Test-IsDefaultGroup $_.memberName) -and ("$($_.memberType)" -ne 'User') }

    # Score candidates in memory (suffix + similarity) — NO AD call yet.
    $scored = @()
    foreach ($cand in $candidates) {
        $scored += [pscustomobject]@{
            Name   = $cand.memberName
            Suffix = (Test-SuffixMatch -A $cand.memberName -B $safe -Len $SafeGroupSuffixLength)
            Score  = (Get-NameSimilarityScore -Name $cand.memberName -Reference $safe)
        }
    }

    if ($DebugMode) {
        Write-Host "[DEBUG] safe '$safe': $(@($members).Count) member(s)" -ForegroundColor Magenta
        Write-Host "[DEBUG]   members   : $($res.AllSafeGroups)" -ForegroundColor DarkGray
        Write-Host "[DEBUG]   candidates: $((@($scored) | ForEach-Object { $_.Name }) -join ', ')" -ForegroundColor DarkGray
    }

    if ($scored.Count -eq 0) {
        $res.Notes = 'No external domain group found on the safe (excluding default groups)'
        $safeResolution[$safe] = $res
        continue
    }

    # Choose the group: 1) common suffix (deterministic), else 2) best name resemblance.
    # AD is queried only for the chosen group (cached) — not for every candidate.
    $chosen = $null
    $r = $null
    $bySuffix = @($scored | Where-Object { $_.Suffix } | Sort-Object -Property Score -Descending)
    if ($bySuffix.Count -gt 0) {
        $chosen = $bySuffix[0]
        if (-not $SkipADLookup) { $r = Get-CachedDomainGroup -Name $chosen.Name }
    }
    else {
        $ordered = @($scored | Sort-Object -Property Score -Descending)
        if ($SkipADLookup) {
            $chosen = $ordered[0]
        }
        else {
            # Resolve in resemblance order, stop at the first AD-confirmed group
            foreach ($c in $ordered) {
                $rr = Get-CachedDomainGroup -Name $c.Name
                if ($rr.IsDomainGroup) { $chosen = $c; $r = $rr; break }
            }
            if (-not $chosen) { $chosen = $ordered[0]; $r = Get-CachedDomainGroup -Name $chosen.Name }
        }
    }

    $res.ExternalDomainGroup = if ($r -and $r.GroupName) { $r.GroupName } else { $chosen.Name }
    $res.Score = $chosen.Score
    if ($r) { $res.Manager = $r.Manager; $res.ManagerEmail = $r.ManagerEmail }

    $notes = @()
    if ($chosen.Suffix) { $notes += "Selected by common suffix with the safe (last $SafeGroupSuffixLength chars)" }
    elseif (-not $SkipADLookup -and $r -and -not $r.IsDomainGroup) { $notes += 'Probable group by resemblance (not confirmed in AD)' }
    if (-not $SkipADLookup -and $r -and $r.IsDomainGroup -and -not $r.Manager) { $notes += 'No manager (empty ManagedBy)' }
    $otherList = @($scored | Where-Object { $_.Name -ne $chosen.Name })
    if ($otherList.Count -gt 0) {
        $others = ($otherList | ForEach-Object { "$($_.Name) (sim=$($_.Score))" }) -join ', '
        $notes += "Other candidate groups: $others"
    }
    if ($notes.Count -gt 0) { $res.Notes = ($notes -join ' | ') }

    if ($DebugMode) { Write-Host "[DEBUG]   chosen    : $($res.ExternalDomainGroup) (suffix=$($chosen.Suffix), sim=$($chosen.Score), manager=$($res.Manager))" -ForegroundColor Green }

    $safeResolution[$safe] = $res
}

# Apply each per-safe resolution to every onboarded account in that safe
foreach ($rec in $onboardedRecs) {
    $res = $safeResolution[$rec.SafeName]
    if (-not $res) { continue }
    $rec.AllSafeGroups       = $res.AllSafeGroups
    $rec.ExternalDomainGroup = $res.ExternalDomainGroup
    $rec.GroupSafeSimilarity = $res.Score
    $rec.GroupManager        = $res.Manager
    $rec.GroupManagerEmail   = $res.ManagerEmail
    if ($res.Notes) { $rec.Notes = $res.Notes }
}
Write-Progress -Activity "AD resolution" -Completed
$tAD = Get-Date

# ============================= EXPORT & SUMMARY =====================================================
$final = $results | ForEach-Object { [pscustomobject]$_ }
$final | Export-Csv -LiteralPath $DestPath -NoTypeInformation -Encoding UTF8 -Delimiter $CsvDelimiter

$onb = ($final | Where-Object { $_.Onboarded -eq 'Yes' }).Count
$anomalies = ($final | Where-Object { $_.OnboardingAssessment -like 'ANOMALY*' }).Count
$normalMissing = ($final | Where-Object { $_.OnboardingAssessment -like 'Normal*' }).Count
$elapsed = (Get-Date) - $scriptStart
Write-Host ""
Write-Host "===== Summary =====" -ForegroundColor Yellow
Write-Host "Rows processed                : $($final.Count)"
Write-Host "Onboarded accounts            : $onb"
Write-Host "Not onboarded                 : $($final.Count - $onb)"
if ($HasCandidate) {
    Write-Host "  -> ANOMALIES (candidate not onboarded) : $anomalies" -ForegroundColor Red
    Write-Host "  -> Normal (not a candidate)            : $normalMissing" -ForegroundColor Gray
}
Write-Host "Unique safes queried          : $($safeMembersCache.Count)"
if ($GroupsOU) { Write-Host "Groups in OU map              : $($script:GroupMap.Count)" }
Write-Host "Unique group resolutions      : $($script:AdCache.Count)"
Write-Host "Manager (DN) lookups          : $($script:MgrCache.Count)"
Write-Host "DNS lookups (cache size)      : $($script:DnsCache.Count)"
Write-Host ""
Write-Host "----- Time per phase -----" -ForegroundColor Yellow
function Format-Span { param($a, $b) if ($a -and $b) { return "$([int](($b - $a).TotalSeconds))s" } else { return 'n/a' } }
Write-Host "  OU group map (AD enum)      : $(Format-Span $scriptStart $tMap)"
Write-Host "  Extraction (logon+download) : $(Format-Span $tMap $tExtract)"
Write-Host "  Matching (+DNS fallback)    : $(Format-Span $tExtract $tMatch)"
Write-Host "  Safe members (API)          : $(Format-Span $tMatch $tMembers)"
Write-Host "  AD resolution (manager)     : $(Format-Span $tMembers $tAD)"
Write-Host "Total time                    : $([int]$elapsed.TotalSeconds)s"
Write-Host "Columns added to              : $DestPath" -ForegroundColor Green
#endregion
