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
    safe members -> logoff) and on the ActiveDirectory module (RSAT) to
    resolve domain groups and their manager (ManagedBy attribute).

    The searched pair is:
        username (CSV column)  ==  userName of the CyberArk account
        host     (CSV column)  ==  address  of the CyberArk account (loose match)

.PARAMETER PvwaUrl
    PVWA base URL, e.g. https://pvwa.mydomain.local

.PARAMETER CsvPath
    Path to the source CSV (must contain at least the 'host' and 'username' columns).

.PARAMETER OutputPath
    Path to the results CSV. Default: .\CyberArk-Verification-Results.csv

.PARAMETER Credential
    Credentials for the PVWA logon. If omitted, the script prompts for them.

.PARAMETER AuthType
    PVWA authentication method: CyberArk | LDAP | RADIUS. Default: CyberArk

.PARAMETER UsernameColumn / HostColumn
    CSV column names. Defaults: 'username' and 'host'.

.PARAMETER AddressMatch
    Matching strategy between 'host' (CSV) and 'address' (CyberArk):
      Exact   : address == host
      Hostname: the first label of the address (before the first '.') == host  (default)
      Contains: address contains host

.PARAMETER DefaultSafeGroups
    List of default groups/members to exclude in order to isolate the external group.

.PARAMETER SkipADLookup
    Skips AD queries (useful for testing off a domain-joined machine).

.PARAMETER SkipIPCheck
    Disables the IP fallback: by default, when an account is not found by its
    hostname, the script resolves the 'host' to an IP via DNS and re-runs the
    search in CyberArk with that/those IP(s) (case of accounts onboarded by IP).

.PARAMETER SkipCertificateCheck
    Ignores the PVWA TLS certificate validation (labs / self-signed certs).

.EXAMPLE
    .\Verify-CyberArkAccounts.ps1 -PvwaUrl https://pvwa.corp.local -CsvPath .\accounts.csv

.NOTES
    Requires PowerShell 5.1+ . The ActiveDirectory module is only required when
    -SkipADLookup is not used.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PvwaUrl,

    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [string]$OutputPath = ".\CyberArk-Verification-Results.csv",

    [System.Management.Automation.PSCredential]$Credential,

    [ValidateSet('CyberArk', 'LDAP', 'RADIUS')]
    [string]$AuthType = 'CyberArk',

    [string]$UsernameColumn = 'username',
    [string]$HostColumn = 'host',

    [ValidateSet('Exact', 'Hostname', 'Contains')]
    [string]$AddressMatch = 'Hostname',

    [char]$CsvDelimiter = ',',

    [string[]]$DefaultSafeGroups = @(
        'Vault Admins', 'Auditors', 'Backup Users', 'DR Users', 'Master',
        'Notification Engineers', 'Operators', 'PVWAUsers', 'PVWAMonitor',
        'PVWAAppUsers', 'PVWAGWAccounts', 'PVWAGWUser', 'PSMUsers', 'PSMAppUsers',
        'PSMMaster', 'PSMP_ADB_AppUsers', 'Administrator', 'Administrators',
        'Batch', 'PasswordManager', 'ApproverGroup', 'AIMWebService',
        'ApplicationManagers', 'EPVMaintenanceUsers', 'xrayGroup'
    ),

    [switch]$SkipADLookup,
    [switch]$SkipIPCheck,
    [switch]$SkipCertificateCheck
)

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

if (-not $SkipADLookup) {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "Le module ActiveDirectory est introuvable. La résolution AD sera désactivée (utilisez -SkipADLookup pour masquer cet avertissement)."
        $SkipADLookup = $true
    }
    else {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    }
}
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

function Get-PvwaAccounts {
    <#  Paginated search of accounts matching a keyword.  #>
    param([string]$Token, [string]$Search)

    $headers = @{ Authorization = $Token }
    $results = @()
    $offset = 0
    $limit = 50

    do {
        $q = "search=$([uri]::EscapeDataString($Search))&searchType=contains&limit=$limit&offset=$offset"
        $url = "$ApiBase/Accounts?$q"
        $resp = Invoke-RestMethod -Uri $url -Method Get -Headers $headers @script:IrmExtra
        if ($resp.value) { $results += $resp.value }
        $offset += $limit
        $hasMore = ($null -ne $resp.value) -and ($resp.value.Count -eq $limit)
    } while ($hasMore)

    return $results
}

function Get-PvwaSafeMembers {
    param([string]$Token, [string]$SafeName)

    $headers = @{ Authorization = $Token }
    $url = "$ApiBase/Safes/$([uri]::EscapeDataString($SafeName))/Members?limit=1000"
    $resp = Invoke-RestMethod -Uri $url -Method Get -Headers $headers @script:IrmExtra
    return $resp.value
}
#endregion

#region ----------------------------------------------------------- Matching helpers
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

function Resolve-HostIPAddress {
    <#  Resolves a hostname to its IPv4 address(es) via DNS. Returns an array (empty on failure).  #>
    param([string]$HostValue)

    if ([string]::IsNullOrWhiteSpace($HostValue)) { return @() }

    # If the host is already an IP, return it as-is
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($HostValue, [ref]$parsed)) { return @($HostValue) }

    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($HostValue)
        $ips = $addrs |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            ForEach-Object { $_.IPAddressToString }
        return @($ips | Select-Object -Unique)
    }
    catch {
        Write-Verbose "DNS resolution failed for '$HostValue': $($_.Exception.Message)"
        return @()
    }
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

    try {
        $grp = Get-ADGroup -Identity $name -Properties ManagedBy, mail -ErrorAction Stop
    }
    catch {
        try {
            $grp = Get-ADGroup -Filter "Name -eq '$name' -or sAMAccountName -eq '$name'" -Properties ManagedBy, mail -ErrorAction Stop | Select-Object -First 1
        }
        catch { $grp = $null }
    }

    if (-not $grp) { return $result }   # not found in AD => not a domain group

    $result.IsDomainGroup = $true
    $result.GroupName = $grp.Name

    if ($grp.ManagedBy) {
        try {
            $mgr = Get-ADObject -Identity $grp.ManagedBy -Properties displayName, mail, manager -ErrorAction Stop
            $result.Manager = if ($mgr.displayName) { $mgr.displayName } else { $mgr.Name }
            $result.ManagerEmail = $mgr.mail
            $result.ManagerSource = 'Group.ManagedBy'
        }
        catch { Write-Verbose "ManagedBy not resolved for $name : $($_.Exception.Message)" }
    }

    return $result
}
#endregion

#region ----------------------------------------------------------- Main program
if (-not (Test-Path -LiteralPath $CsvPath)) { throw "CSV introuvable : $CsvPath" }
if (-not $Credential) { $Credential = Get-Credential -Message "Identifiants CyberArk PVWA ($AuthType)" }

$rows = Import-Csv -LiteralPath $CsvPath -Delimiter $CsvDelimiter
if ($rows.Count -eq 0) { throw "Le CSV ne contient aucune ligne." }
$cols = $rows[0].PSObject.Properties.Name
foreach ($c in @($UsernameColumn, $HostColumn)) {
    if ($cols -notcontains $c) { throw "Colonne '$c' absente du CSV. Colonnes trouvées : $($cols -join ', ')" }
}

Write-Host "Connexion au PVWA $PvwaUrl ..." -ForegroundColor Cyan
$token = Invoke-PvwaLogon -Cred $Credential -Type $AuthType
Write-Host "Connecté. Traitement de $($rows.Count) ligne(s)." -ForegroundColor Green

$results = New-Object System.Collections.Generic.List[object]
$safeMembersCache = @{}   # avoids re-listing the members of a same safe
$i = 0

try {
    foreach ($row in $rows) {
        $i++
        $username = "$($row.$UsernameColumn)".Trim()
        $hostName = "$($row.$HostColumn)".Trim()
        Write-Progress -Activity "Vérification CyberArk" -Status "$i/$($rows.Count) : $username@$hostName" -PercentComplete (($i / $rows.Count) * 100)

        $rec = [ordered]@{
            Inventory           = $row.inventory
            Host                = $hostName
            Username            = $username
            Onboarded           = 'No'
            MatchType           = $null
            ResolvedIP          = $null
            AccountName         = $null
            AccountAddress      = $null
            PlatformId          = $null
            SafeName            = $null
            AllSafeGroups       = $null
            ExternalDomainGroup = $null
            GroupManager        = $null
            GroupManagerEmail   = $null
            Notes               = $null
        }

        if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($hostName)) {
            $rec.Notes = 'Ligne ignorée (username ou host vide)'
            $results.Add([pscustomobject]$rec); continue
        }

        # --- 1) Search for the account in CyberArk ---
        try {
            $found = Get-PvwaAccounts -Token $token -Search "$username $hostName"
        }
        catch {
            $rec.Notes = "Erreur recherche compte : $($_.Exception.Message)"
            $results.Add([pscustomobject]$rec); continue
        }

        $match = $found | Where-Object {
            $_.userName -and ($_.userName.ToLower() -eq $username.ToLower()) -and
            (Test-AddressMatch -Address $_.address -HostValue $hostName -Strategy $AddressMatch)
        } | Select-Object -First 1

        if ($match) { $rec.MatchType = 'Hostname' }

        # --- 1b) IP fallback: if not found by hostname, resolve the host to an IP ---
        if (-not $match -and -not $SkipIPCheck) {
            $ips = Resolve-HostIPAddress -HostValue $hostName
            if ($ips.Count -gt 0) {
                $rec.ResolvedIP = ($ips -join '; ')
                foreach ($ip in $ips) {
                    # First look among the already-returned accounts, then via a dedicated search by IP
                    $match = $found | Where-Object {
                        $_.userName -and ($_.userName.ToLower() -eq $username.ToLower()) -and ($_.address -eq $ip)
                    } | Select-Object -First 1

                    if (-not $match) {
                        try { $foundByIp = Get-PvwaAccounts -Token $token -Search "$username $ip" } catch { $foundByIp = @() }
                        $match = $foundByIp | Where-Object {
                            $_.userName -and ($_.userName.ToLower() -eq $username.ToLower()) -and ($_.address -eq $ip)
                        } | Select-Object -First 1
                    }

                    if ($match) { $rec.MatchType = "IP ($ip)"; break }
                }
            }
            else {
                $rec.ResolvedIP = 'non résolu'
            }
        }

        if (-not $match) {
            $rec.Notes = 'Compte non embarqué (aucune correspondance username+address, ni par nom ni par IP)'
            $results.Add([pscustomobject]$rec); continue
        }

        $rec.Onboarded = 'Yes'
        $rec.AccountName = $match.name
        $rec.AccountAddress = $match.address
        $rec.PlatformId = $match.platformId
        $rec.SafeName = $match.safeName

        # --- 2) Safe members / groups ---
        $safe = $match.safeName
        if (-not $safeMembersCache.ContainsKey($safe)) {
            try { $safeMembersCache[$safe] = Get-PvwaSafeMembers -Token $token -SafeName $safe }
            catch { $safeMembersCache[$safe] = $null; $rec.Notes = "Erreur lecture membres safe : $($_.Exception.Message)" }
        }
        $members = $safeMembersCache[$safe]
        if (-not $members) {
            if (-not $rec.Notes) { $rec.Notes = 'Aucun membre retourné pour le safe' }
            $results.Add([pscustomobject]$rec); continue
        }

        $rec.AllSafeGroups = (($members | ForEach-Object { $_.memberName }) -join '; ')

        # --- 3) Candidates = non-default groups ---
        $candidates = $members | Where-Object {
            $_.memberType -eq 'Group' -and ($DefaultSafeGroups -notcontains $_.memberName)
        }

        # --- 4) AD resolution: keep only the groups actually present in the domain ---
        $domainGroups = @()
        foreach ($cand in $candidates) {
            $r = Resolve-DomainGroupAndManager -MemberName $cand.memberName
            if ($SkipADLookup) {
                # Without AD we cannot certify the domain: keep the candidate as-is
                $domainGroups += [pscustomobject]@{ GroupName = $cand.memberName; Manager = $null; ManagerEmail = $null }
            }
            elseif ($r.IsDomainGroup) {
                $domainGroups += [pscustomobject]@{ GroupName = $r.GroupName; Manager = $r.Manager; ManagerEmail = $r.ManagerEmail }
            }
        }

        if ($domainGroups.Count -eq 0) {
            $rec.Notes = if ($SkipADLookup) { 'Aucun groupe non-défaut (AD non interrogé)' } else { 'Aucun groupe de domaine externe trouvé sur le safe' }
        }
        else {
            $rec.ExternalDomainGroup = ($domainGroups.GroupName -join '; ')
            $withMgr = $domainGroups | Where-Object { $_.Manager } | Select-Object -First 1
            if ($withMgr) {
                $rec.GroupManager = $withMgr.Manager
                $rec.GroupManagerEmail = $withMgr.ManagerEmail
            }
            elseif (-not $SkipADLookup) {
                $rec.Notes = 'Groupe de domaine trouvé mais aucun manager (ManagedBy vide)'
            }
            if ($domainGroups.Count -gt 1) {
                $rec.Notes = (@($rec.Notes, "Plusieurs groupes de domaine ($($domainGroups.Count)) — vérifier") | Where-Object { $_ }) -join ' | '
            }
        }

        $results.Add([pscustomobject]$rec)
    }
}
finally {
    Write-Progress -Activity "Vérification CyberArk" -Completed
    Invoke-PvwaLogoff -Token $token
    Write-Host "Déconnecté du PVWA." -ForegroundColor Cyan
}

$results | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8 -Delimiter $CsvDelimiter

$onb = ($results | Where-Object { $_.Onboarded -eq 'Yes' }).Count
Write-Host ""
Write-Host "===== Synthèse =====" -ForegroundColor Yellow
Write-Host "Lignes traitées      : $($results.Count)"
Write-Host "Comptes embarqués    : $onb"
Write-Host "Non embarqués        : $($results.Count - $onb)"
Write-Host "Résultats écrits dans : $OutputPath" -ForegroundColor Green
#endregion
