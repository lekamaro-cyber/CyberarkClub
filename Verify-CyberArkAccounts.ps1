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

    NO COMMAND-LINE ARGUMENTS: every setting (PVWA URL, credentials, file paths,
    options...) is hard-coded in the CONFIGURATION section right below. Just edit
    that section and run the script (e.g. from PowerShell ISE / VS Code / right-click
    "Run with PowerShell").

    The input CSV can be the output of extractSudoRootV0.7.ps1
    (Audit_Privileges_Unix_YYYY-MM.csv): the script reads its CA_Candidate column
    to decide whether a non-onboarded account is a real anomaly (CA_Candidate =
    YES/YES-SSH) or expected (NO = no privilege / offline host).

.NOTES
    Requires PowerShell 5.1+ . The ActiveDirectory module is only required when
    $SkipADLookup is left to $false.
#>

# =====================================================================================
# ============================  CONFIGURATION (À ADAPTER)  =============================
# =====================================================================================
# Aucun argument en ligne de commande : tout se règle ici. Lancez simplement le script.

# --- PVWA / CyberArk ---
$PvwaUrl  = 'https://oneconnection.intra.corp'   # <-- ADAPTER : URL du PVWA
$AuthType = 'LDAP'                               # 'CyberArk' | 'LDAP' | 'RADIUS'

# --- Identifiants PVWA ---
# Laissez $PvwaPassword vide ('') pour une saisie sécurisée à l'exécution (recommandé).
# Vous pouvez renseigner le mot de passe en dur, mais il sera alors stocké en CLAIR.
$PvwaUsername = ''                               # ex. 'svc_cyberark_admin' (vide = saisie complète)
$PvwaPassword = ''                               # vide = demande à l'exécution

# --- Fichiers ---
# CSV d'entrée : couples compte/serveur. Peut être la sortie de extractSudoRootV0.7.ps1.
$CsvPath    = "$PSScriptRoot\Input\Audit_Privileges_Unix.csv"
$OutputPath = "$PSScriptRoot\Output\CyberArk-Verification-Results_$(Get-Date -Format 'yyyy-MM').csv"

# --- Colonnes du CSV d'entrée (laisser 'Auto' pour détection automatique) ---
$UsernameColumn  = 'Auto'          # ex. 'UserSam' / 'username' / 'userName'
$HostColumn      = 'Auto'          # ex. 'Server' / 'host' / 'address'
$CandidateColumn = 'CA_Candidate'  # colonne de candidature CyberArk (extractSudoRoot)
$CsvDelimiter    = 'Auto'          # 'Auto' (détecte , ou ;), sinon ',' ou ';'

# --- Correspondance host <-> address CyberArk ---
$AddressMatch = 'Hostname'         # 'Hostname' (nom court) | 'Exact' | 'Contains'

# --- Options ---
$SkipADLookup        = $false      # $true = ne pas interroger l'Active Directory
$SkipIPCheck         = $false      # $true = ne pas tenter le repli par IP (DNS)
$SkipCertificateCheck = $false     # $true = ignorer la validation TLS du PVWA

# --- Groupes par défaut du safe à exclure pour isoler le groupe de domaine externe ---
$DefaultSafeGroups = @(
    'Vault Admins', 'Auditors', 'Backup Users', 'DR Users', 'Master',
    'Notification Engineers', 'Operators', 'PVWAUsers', 'PVWAMonitor',
    'PVWAAppUsers', 'PVWAGWAccounts', 'PVWAGWUser', 'PSMUsers', 'PSMAppUsers',
    'PSMMaster', 'PSMP_ADB_AppUsers', 'Administrator', 'Administrators',
    'Batch', 'PasswordManager', 'ApproverGroup', 'AIMWebService',
    'ApplicationManagers', 'EPVMaintenanceUsers', 'xrayGroup'
)
# =====================================================================================
# ==========================  FIN DE LA CONFIGURATION  ================================
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

if (-not $SkipADLookup) {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "Le module ActiveDirectory est introuvable. La résolution AD sera désactivée (mettez `$SkipADLookup = `$true pour masquer cet avertissement)."
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

# Build credentials from the CONFIGURATION section (prompt if password left empty)
if (-not $Credential) {
    if ($PvwaUsername -and $PvwaPassword) {
        $secure = ConvertTo-SecureString $PvwaPassword -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($PvwaUsername, $secure)
    }
    elseif ($PvwaUsername) {
        $Credential = Get-Credential -UserName $PvwaUsername -Message "Mot de passe CyberArk PVWA ($AuthType)"
    }
    else {
        $Credential = Get-Credential -Message "Identifiants CyberArk PVWA ($AuthType)"
    }
}

# Auto-detect the delimiter from the header when set to 'Auto' (extractSudoRoot output uses ';')
if ($CsvDelimiter -eq 'Auto') {
    $headerLine = Get-Content -LiteralPath $CsvPath -TotalCount 1
    $CsvDelimiter = if ($headerLine -match ';') { ';' } else { ',' }
}

$rows = Import-Csv -LiteralPath $CsvPath -Delimiter $CsvDelimiter
if ($rows.Count -eq 0) { throw "Le CSV ne contient aucune ligne." }
$cols = $rows[0].PSObject.Properties.Name

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
    throw "Impossible de trouver les colonnes username/host dans le CSV. Colonnes trouvées : $($cols -join ', ')"
}
$HasCandidate = ($cols -contains $CandidateColumn)
$OutDir = Split-Path -Parent $OutputPath
if ($OutDir -and -not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}
Write-Host "Colonnes utilisées : username='$UsernameColumn', host='$HostColumn'$(if ($HasCandidate) { ", candidat='$CandidateColumn'" })" -ForegroundColor DarkCyan

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
        $candidate = if ($HasCandidate) { "$($row.$CandidateColumn)".Trim() } else { $null }
        Write-Progress -Activity "Vérification CyberArk" -Status "$i/$($rows.Count) : $username@$hostName" -PercentComplete (($i / $rows.Count) * 100)

        $rec = [ordered]@{
            Inventory            = $row.inventory
            Host                 = $hostName
            Username             = $username
            CA_Candidate         = $candidate
            Onboarded            = 'No'
            OnboardingAssessment = $null
            MatchType            = $null
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
            # Qualify the "not onboarded" result using CA_Candidate (extractSudoRoot)
            switch -Regex ($candidate) {
                '^(?i)YES'             { $rec.OnboardingAssessment = 'ANOMALIE - candidat CyberArk non embarqué' }
                '^(?i)CHECK-INVENTORY' { $rec.OnboardingAssessment = 'À vérifier - statut inventaire inconnu' }
                '^(?i)NO$'             { $rec.OnboardingAssessment = 'Normal - non candidat (pas de privilège / hors ligne)' }
                default                { $rec.OnboardingAssessment = if ($HasCandidate) { 'Non candidat (valeur CA_Candidate vide)' } else { 'Non évalué (colonne CA_Candidate absente)' } }
            }
            $results.Add([pscustomobject]$rec); continue
        }

        $rec.Onboarded = 'Yes'
        $rec.OnboardingAssessment = if ($candidate -match '^(?i)NO$') { 'Embarqué (alors que non candidat - à confirmer)' } else { 'OK - embarqué' }
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
$anomalies = ($results | Where-Object { $_.OnboardingAssessment -like 'ANOMALIE*' }).Count
$normalMissing = ($results | Where-Object { $_.OnboardingAssessment -like 'Normal*' }).Count
Write-Host ""
Write-Host "===== Synthèse =====" -ForegroundColor Yellow
Write-Host "Lignes traitées               : $($results.Count)"
Write-Host "Comptes embarqués             : $onb"
Write-Host "Non embarqués                 : $($results.Count - $onb)"
if ($HasCandidate) {
    Write-Host "  -> ANOMALIES (candidat non embarqué) : $anomalies" -ForegroundColor Red
    Write-Host "  -> Normal (non candidat)             : $normalMissing" -ForegroundColor Gray
}
Write-Host "Résultats écrits dans         : $OutputPath" -ForegroundColor Green
#endregion
