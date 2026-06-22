<#
.SYNOPSIS
    Vérifie qu'une liste de couples (compte / serveur) issue d'un CSV est bien
    embarquée (onboarded) dans CyberArk, puis récupère pour chaque compte :
      - son Safe
      - la liste de tous les groupes/membres (permissions) du Safe
      - le groupe de domaine "externe" (hors groupes par défaut)
      - le manager de ce groupe de domaine, lu dans l'Active Directory.

.DESCRIPTION
    S'appuie sur l'API REST du PVWA CyberArk (logon -> recherche de comptes ->
    membres du safe -> logoff) et sur le module ActiveDirectory (RSAT) pour la
    résolution des groupes de domaine et de leur manager (attribut ManagedBy).

    Le couple recherché est :
        username (colonne CSV)  ==  userName du compte CyberArk
        host     (colonne CSV)  ==  address  du compte CyberArk (match souple)

.PARAMETER PvwaUrl
    URL de base du PVWA, ex : https://pvwa.mondomaine.local

.PARAMETER CsvPath
    Chemin du CSV source (doit contenir au minimum les colonnes 'host' et 'username').

.PARAMETER OutputPath
    Chemin du CSV de résultats. Défaut : .\CyberArk-Verification-Results.csv

.PARAMETER Credential
    Identifiants pour le logon PVWA. Si absent, le script les demande.

.PARAMETER AuthType
    Méthode d'authentification PVWA : CyberArk | LDAP | RADIUS. Défaut : CyberArk

.PARAMETER UsernameColumn / HostColumn
    Noms des colonnes du CSV. Défauts : 'username' et 'host'.

.PARAMETER AddressMatch
    Stratégie de correspondance entre 'host' (CSV) et 'address' (CyberArk) :
      Exact   : address == host
      Hostname: le 1er label de l'address (avant le 1er '.') == host  (défaut)
      Contains: address contient host

.PARAMETER DefaultSafeGroups
    Liste des groupes/membres par défaut à exclure pour isoler le groupe externe.

.PARAMETER SkipADLookup
    N'effectue pas les requêtes AD (utile pour tester hors d'un poste joint au domaine).

.PARAMETER SkipIPCheck
    Désactive le repli (fallback) par IP : par défaut, lorsqu'un compte n'est pas
    trouvé par son nom d'hôte, le script résout le 'host' en IP via DNS et relance
    la recherche dans CyberArk avec cette/ces IP (cas des comptes embarqués par IP).

.PARAMETER SkipCertificateCheck
    Ignore la validation du certificat TLS du PVWA (labos / certs auto-signés).

.EXAMPLE
    .\Verify-CyberArkAccounts.ps1 -PvwaUrl https://pvwa.corp.local -CsvPath .\comptes.csv

.NOTES
    Nécessite PowerShell 5.1+ . Le module ActiveDirectory n'est requis que si
    -SkipADLookup n'est pas utilisé.
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

#region ----------------------------------------------------------- Pré-requis & TLS
$ErrorActionPreference = 'Stop'

# Force TLS 1.2 (PVWA refuse souvent les protocoles plus anciens)
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

#region ----------------------------------------------------------- Fonctions CyberArk
function Invoke-PvwaLogon {
    param([pscredential]$Cred, [string]$Type)

    $url = "$ApiBase/auth/$Type/Logon"
    $body = @{
        username          = $Cred.UserName
        password          = $Cred.GetNetworkCredential().Password
        concurrentSession = $true
    } | ConvertTo-Json

    Write-Verbose "Logon sur $url (AuthType=$Type)"
    $token = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType 'application/json' @script:IrmExtra
    # Le token renvoyé est une chaîne (parfois entre guillemets) à mettre dans Authorization
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
    <#  Recherche paginée des comptes correspondant à un mot-clé.  #>
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

#region ----------------------------------------------------------- Helpers de correspondance
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
    <#  Résout un nom d'hôte en adresse(s) IPv4 via DNS. Renvoie un tableau (vide si échec).  #>
    param([string]$HostValue)

    if ([string]::IsNullOrWhiteSpace($HostValue)) { return @() }

    # Si le host est déjà une IP, on la renvoie telle quelle
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
        Write-Verbose "Résolution DNS impossible pour '$HostValue' : $($_.Exception.Message)"
        return @()
    }
}

function Resolve-DomainGroupAndManager {
    <#
        Pour un nom de membre de safe (potentiellement un groupe de domaine),
        tente de le résoudre dans l'AD et renvoie le manager (ManagedBy).
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

    # Le nom peut être "DOMAIN\Groupe", "Groupe@domaine" ou "Groupe"
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

    if (-not $grp) { return $result }   # introuvable dans l'AD => pas un groupe de domaine

    $result.IsDomainGroup = $true
    $result.GroupName = $grp.Name

    if ($grp.ManagedBy) {
        try {
            $mgr = Get-ADObject -Identity $grp.ManagedBy -Properties displayName, mail, manager -ErrorAction Stop
            $result.Manager = if ($mgr.displayName) { $mgr.displayName } else { $mgr.Name }
            $result.ManagerEmail = $mgr.mail
            $result.ManagerSource = 'Group.ManagedBy'
        }
        catch { Write-Verbose "ManagedBy non résolu pour $name : $($_.Exception.Message)" }
    }

    return $result
}
#endregion

#region ----------------------------------------------------------- Programme principal
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
$safeMembersCache = @{}   # évite de re-listter les membres d'un même safe
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

        # --- 1) Recherche du compte dans CyberArk ---
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

        # --- 1bis) Repli par IP : si non trouvé par nom d'hôte, on résout le host en IP ---
        if (-not $match -and -not $SkipIPCheck) {
            $ips = Resolve-HostIPAddress -HostValue $hostName
            if ($ips.Count -gt 0) {
                $rec.ResolvedIP = ($ips -join '; ')
                foreach ($ip in $ips) {
                    # On recherche d'abord parmi les comptes déjà remontés, puis via une requête dédiée par IP
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

        # --- 2) Membres / groupes du safe ---
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

        # --- 3) Candidats = groupes non par défaut ---
        $candidates = $members | Where-Object {
            $_.memberType -eq 'Group' -and ($DefaultSafeGroups -notcontains $_.memberName)
        }

        # --- 4) Résolution AD : on garde les groupes réellement présents dans le domaine ---
        $domainGroups = @()
        foreach ($cand in $candidates) {
            $r = Resolve-DomainGroupAndManager -MemberName $cand.memberName
            if ($SkipADLookup) {
                # Sans AD on ne peut pas certifier le domaine : on retient le candidat tel quel
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
