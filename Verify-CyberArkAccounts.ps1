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

# --- Source des comptes CyberArk ---
# Le script télécharge TOUJOURS tous les comptes en une seule fois (extraction),
# les sauvegarde dans le fichier ci-dessous, puis ferme la session avant le
# traitement (matching + AD), qui se fait hors-ligne.
$AccountsExtractPath = "$PSScriptRoot\Input\cyberark_accounts.csv"

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
# Noms exacts :
$DefaultSafeGroups = @(
    'Vault Admins', 'Auditors', 'Backup Users', 'DR Users', 'Master',
    'Notification Engineers', 'Operators', 'PVWAUsers', 'PVWAMonitor',
    'PVWAAppUsers', 'PVWAGWAccounts', 'PVWAGWUser', 'PSMUsers', 'PSMAppUsers',
    'PSMMaster', 'PSMP_ADB_AppUsers', 'Administrator', 'Administrators',
    'Batch', 'PasswordManager', 'ApproverGroup', 'AIMWebService',
    'ApplicationManagers', 'EPVMaintenanceUsers', 'xrayGroup',
    'PAM_CyberArk_Manager'
)
# Motifs (wildcards) pour les groupes par défaut "métier" propres à votre org,
# ex. FR_GUA_PAM_Auth_Admins / _Auditors / _Safe_Managers, PAM_CyberArk_Manager...
$DefaultSafeGroupPatterns = @(
    '*_PAM_Auth_*',      # FR_GUA_PAM_Auth_Admins / _Auditors / _Safe_Managers
    'PAM_CyberArk_*',    # PAM_CyberArk_Manager
    '*_Auth_Admins',
    '*_Auth_Auditors',
    '*_Auth_Safe_Managers',
    '*_Safe_Managers'
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

function Get-PvwaAllAccounts {
    <#  Downloads ALL accounts once (paged). One bulk extraction instead of
        one search per CSV row, so the session can be closed quickly afterwards.  #>
    param([string]$Token)

    $headers = @{ Authorization = $Token }
    $all = @()
    $offset = 0
    $limit = 1000

    do {
        $url = "$ApiBase/Accounts?limit=$limit&offset=$offset"
        $resp = Invoke-RestMethod -Uri $url -Method Get -Headers $headers @script:IrmExtra
        if ($resp.value) { $all += $resp.value }
        $offset += $limit
        $hasMore = ($null -ne $resp.value) -and ($resp.value.Count -eq $limit)
        Write-Host "    ... $($all.Count) comptes chargés" -ForegroundColor Gray
    } while ($hasMore)

    return $all
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

$results     = New-Object System.Collections.Generic.List[object]
$safeMembersCache = @{}
$neededSafes = New-Object 'System.Collections.Generic.HashSet[string]'
$token = $null

try {
    # ============================= PHASE 1 : EXTRACTION (session ouverte) =============================
    Write-Host "Connexion au PVWA $PvwaUrl ..." -ForegroundColor Cyan
    $token = Invoke-PvwaLogon -Cred $Credential -Type $AuthType
    Write-Host "Connecté." -ForegroundColor Green

    # 1a) Extraction : tous les comptes en une seule fois, puis sauvegarde de l'extrait
    Write-Host "Extraction de tous les comptes depuis le PVWA..." -ForegroundColor Cyan
    $allAccounts = Get-PvwaAllAccounts -Token $token
    try {
        $extractDir = Split-Path -Parent $AccountsExtractPath
        if ($extractDir -and -not (Test-Path -LiteralPath $extractDir)) { New-Item -ItemType Directory -Force -Path $extractDir | Out-Null }
        $allAccounts |
            Select-Object name, userName, address, platformId, safeName,
                @{ n = 'cpmStatus'; e = { $_.secretManagement.status } },
                @{ n = 'cpmManaged'; e = { $_.secretManagement.automaticManagementEnabled } } |
            Export-Csv -LiteralPath $AccountsExtractPath -NoTypeInformation -Encoding UTF8
        Write-Host "Extrait des comptes sauvegardé : $AccountsExtractPath" -ForegroundColor DarkCyan
    }
    catch { Write-Warning "Impossible de sauvegarder l'extrait : $($_.Exception.Message)" }
    Write-Host " $($allAccounts.Count) comptes chargés." -ForegroundColor Green

    # 1b) Index des comptes par nom d'utilisateur (matching ensuite 100% en mémoire)
    $caByUser = @{}
    foreach ($a in $allAccounts) {
        if (-not $a.userName) { continue }
        $k = $a.userName.ToLower().Trim()
        if (-not $caByUser.ContainsKey($k)) { $caByUser[$k] = New-Object System.Collections.Generic.List[object] }
        $caByUser[$k].Add($a)
    }

    # ============================= PHASE 2 : MATCHING (mémoire + DNS, sans appel API) =================
    $i = 0
    foreach ($row in $rows) {
        $i++
        $username = "$($row.$UsernameColumn)".Trim()
        $hostName = "$($row.$HostColumn)".Trim()
        $candidate = if ($HasCandidate) { "$($row.$CandidateColumn)".Trim() } else { $null }
        Write-Progress -Activity "Matching CyberArk" -Status "$i/$($rows.Count) : $username@$hostName" -PercentComplete (($i / $rows.Count) * 100)

        $rec = [ordered]@{
            Inventory            = $row.inventory
            Host                 = $hostName
            Username             = $username
            CA_Candidate         = $candidate
            Onboarded            = 'No'
            OnboardingAssessment = $null
            MatchType            = $null
            ResolvedIP           = $null
            AccountName          = $null
            AccountAddress       = $null
            PlatformId           = $null
            SafeName             = $null
            AllSafeGroups        = $null
            ExternalDomainGroup  = $null
            GroupSafeSimilarity  = $null
            GroupManager         = $null
            GroupManagerEmail    = $null
            Notes                = $null
        }
        $results.Add($rec)

        if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($hostName)) {
            $rec.Notes = 'Ligne ignorée (username ou host vide)'; continue
        }

        $accts = $caByUser[$username.ToLower()]
        $match = $null
        if ($accts) {
            $match = $accts | Where-Object { Test-AddressMatch -Address $_.address -HostValue $hostName -Strategy $AddressMatch } | Select-Object -First 1
            if ($match) { $rec.MatchType = 'Hostname' }
        }

        # IP fallback (DNS), still no CyberArk call
        if (-not $match -and -not $SkipIPCheck) {
            $ips = Resolve-HostIPAddress -HostValue $hostName
            if ($ips.Count -gt 0) {
                $rec.ResolvedIP = ($ips -join '; ')
                if ($accts) {
                    foreach ($ip in $ips) {
                        $match = $accts | Where-Object { $_.address -eq $ip } | Select-Object -First 1
                        if ($match) { $rec.MatchType = "IP ($ip)"; break }
                    }
                }
            }
            else { $rec.ResolvedIP = 'non résolu' }
        }

        if (-not $match) {
            $rec.Notes = 'Compte non embarqué (aucune correspondance username+address, ni par nom ni par IP)'
            switch -Regex ($candidate) {
                '^(?i)YES'             { $rec.OnboardingAssessment = 'ANOMALIE - candidat CyberArk non embarqué' }
                '^(?i)CHECK-INVENTORY' { $rec.OnboardingAssessment = 'À vérifier - statut inventaire inconnu' }
                '^(?i)NO$'             { $rec.OnboardingAssessment = 'Normal - non candidat (pas de privilège / hors ligne)' }
                default                { $rec.OnboardingAssessment = if ($HasCandidate) { 'Non candidat (valeur CA_Candidate vide)' } else { 'Non évalué (colonne CA_Candidate absente)' } }
            }
            continue
        }

        $rec.Onboarded = 'Yes'
        $rec.OnboardingAssessment = if ($candidate -match '^(?i)NO$') { 'Embarqué (alors que non candidat - à confirmer)' } else { 'OK - embarqué' }
        $rec.AccountName = $match.name
        $rec.AccountAddress = $match.address
        $rec.PlatformId = $match.platformId
        $rec.SafeName = $match.safeName
        if ($match.safeName) { [void]$neededSafes.Add($match.safeName) }
    }
    Write-Progress -Activity "Matching CyberArk" -Completed

    # ============================= PHASE 3 : Membres des safes concernés (session ouverte) ===========
    Write-Host "Lecture des membres de $($neededSafes.Count) safe(s) concerné(s)..." -ForegroundColor Cyan
    $sN = 0
    foreach ($safe in $neededSafes) {
        $sN++
        Write-Progress -Activity "Lecture des membres des safes" -Status "$sN/$($neededSafes.Count) : $safe" -PercentComplete (($sN / [Math]::Max(1, $neededSafes.Count)) * 100)
        try { $safeMembersCache[$safe] = Get-PvwaSafeMembers -Token $token -SafeName $safe }
        catch { $safeMembersCache[$safe] = $null }
    }
    Write-Progress -Activity "Lecture des membres des safes" -Completed
}
finally {
    # ============================= PHASE 4 : Fermeture de la session (extraction terminée) ===========
    if ($token) { Invoke-PvwaLogoff -Token $token }
    Write-Host "Session CyberArk fermée (extraction terminée)." -ForegroundColor Cyan
}

# ============================= PHASE 5 : Enrichissement HORS-LIGNE (groupe externe + manager AD) =====
Write-Host "Résolution des groupes de domaine et managers (Active Directory)..." -ForegroundColor Cyan
$onboardedRecs = $results | Where-Object { $_.Onboarded -eq 'Yes' }
$j = 0
foreach ($rec in $onboardedRecs) {
    $j++
    Write-Progress -Activity "Résolution AD" -Status "$j/$($onboardedRecs.Count) : $($rec.SafeName)" -PercentComplete (($j / [Math]::Max(1, $onboardedRecs.Count)) * 100)
    $members = $safeMembersCache[$rec.SafeName]
    if (-not $members) {
        if (-not $rec.Notes) { $rec.Notes = 'Aucun membre retourné pour le safe' }
        continue
    }
    $rec.AllSafeGroups = (($members | ForEach-Object { $_.memberName }) -join '; ')

    # Candidates = members that are groups and are NOT default groups (exact name or pattern)
    $candidates = $members | Where-Object { $_.memberType -eq 'Group' -and -not (Test-IsDefaultGroup $_.memberName) }

    # Score each candidate by name resemblance to the safe name, resolve in AD
    $domainGroups = @()
    foreach ($cand in $candidates) {
        $score = Get-NameSimilarityScore -Name $cand.memberName -Reference $rec.SafeName
        $r = Resolve-DomainGroupAndManager -MemberName $cand.memberName
        $domainGroups += [pscustomobject]@{
            GroupName    = if ($r.GroupName) { $r.GroupName } else { $cand.memberName }
            Manager      = $r.Manager
            ManagerEmail = $r.ManagerEmail
            InAD         = $r.IsDomainGroup
            Score        = $score
        }
    }

    # Keep AD-confirmed domain groups; if none confirmed but candidates exist,
    # fall back to all candidates (so the safe-name resemblance can still pick one).
    $confirmed = @($domainGroups | Where-Object { $_.InAD })
    $pool = if ($SkipADLookup) { $domainGroups }
    elseif ($confirmed.Count -gt 0) { $confirmed }
    else { $domainGroups }   # AD ON but nothing confirmed -> probable group via resemblance

    # The external domain group is the one whose name most resembles the safe name
    $pool = @($pool | Sort-Object -Property Score -Descending)

    if ($pool.Count -eq 0) {
        $rec.Notes = 'Aucun groupe de domaine externe trouvé sur le safe (hors groupes par défaut)'
    }
    else {
        $best = $pool[0]
        $rec.ExternalDomainGroup = $best.GroupName
        $rec.GroupSafeSimilarity = $best.Score
        $rec.GroupManager = $best.Manager
        $rec.GroupManagerEmail = $best.ManagerEmail

        $notes = @()
        if (-not $SkipADLookup -and -not $best.InAD) { $notes += 'Groupe probable par ressemblance (non confirmé dans l''AD)' }
        if (-not $best.Manager -and -not $SkipADLookup -and $best.InAD) { $notes += 'Aucun manager (ManagedBy vide)' }
        if ($pool.Count -gt 1) {
            $others = ($pool | Select-Object -Skip 1 | ForEach-Object { "$($_.GroupName) (sim=$($_.Score))" }) -join ', '
            $notes += "Autres groupes candidats : $others"
        }
        if ($notes.Count -gt 0) { $rec.Notes = ($notes -join ' | ') }
    }
}
Write-Progress -Activity "Résolution AD" -Completed

# ============================= EXPORT & SYNTHÈSE =====================================================
$final = $results | ForEach-Object { [pscustomobject]$_ }
$final | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8 -Delimiter $CsvDelimiter

$onb = ($final | Where-Object { $_.Onboarded -eq 'Yes' }).Count
$anomalies = ($final | Where-Object { $_.OnboardingAssessment -like 'ANOMALIE*' }).Count
$normalMissing = ($final | Where-Object { $_.OnboardingAssessment -like 'Normal*' }).Count
Write-Host ""
Write-Host "===== Synthèse =====" -ForegroundColor Yellow
Write-Host "Lignes traitées               : $($final.Count)"
Write-Host "Comptes embarqués             : $onb"
Write-Host "Non embarqués                 : $($final.Count - $onb)"
if ($HasCandidate) {
    Write-Host "  -> ANOMALIES (candidat non embarqué) : $anomalies" -ForegroundColor Red
    Write-Host "  -> Normal (non candidat)             : $normalMissing" -ForegroundColor Gray
}
Write-Host "Résultats écrits dans         : $OutputPath" -ForegroundColor Green
#endregion
