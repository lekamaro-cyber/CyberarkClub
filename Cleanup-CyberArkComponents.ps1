<#
.SYNOPSIS
    Purge des "component users" laissés dans un Vault CyberArk repliqué depuis la
    production, pour isoler un nouvel environnement. Nettoie aussi les traces PTA.

.DESCRIPTION
    Lorsqu'un Vault est restaure/repliqué depuis la prod, tous les utilisateurs
    techniques des composants (CPM, PSM, PSM/SSH, Credential Provider / AAM, PTA)
    sont presents dans le coffre. Pour isoler le nouvel environnement, ces comptes
    "anciens" doivent etre supprimes afin que les composants fraichement installes
    se reenregistrent proprement.

    Ce script s'appuie uniquement sur l'API REST du PVWA (PAS Web Services) et
    n'a AUCUNE dependance externe (pas de psPAS, pas de module CyberArk). Il
    fonctionne en Windows PowerShell 5.1 et en PowerShell 7+.

    SECURITE : par defaut le script tourne en mode SIMULATION (dry-run). Aucune
    suppression n'est effectuee tant que le commutateur -Execute n'est pas fourni.
    Les utilisateurs internes du Vault (Administrator, Master, Backup, DR, etc.)
    sont proteges et ne seront jamais supprimes.

.PARAMETER PVWAUrl
    URL de base du PVWA, ex : https://pvwa.isole.local  (le suffixe /PasswordVault
    est ajoute automatiquement s'il manque).

.PARAMETER Credential
    Identifiants de connexion (PSCredential). Si absent, le script les demande.

.PARAMETER AuthType
    Methode d'authentification REST : Cyberark (defaut), LDAP, RADIUS, Windows.

.PARAMETER Component
    Composants dont les comptes doivent etre purges. Valeurs : CPM, PSM, PSMP,
    CP, PTA, PVWA, All. Defaut : CPM, PSM, PSMP, CP, PTA (le PVWA est exclu par
    defaut car deja traite).

.PARAMETER ExcludeUser
    Noms (ou motifs avec *) d'utilisateurs a conserver explicitement, ex les
    comptes des composants NEUFS deja installes.

.PARAMETER IncludeUser
    Noms d'utilisateurs supplementaires a forcer dans la cible de suppression.

.PARAMETER SkipUserCleanup
    Ne traite PAS les component users (utile pour ne faire que le menage des safes).

.PARAMETER CleanSafes
    Active le menage des safes : supprime tous les safes NON natifs (les safes
    systeme/composants CyberArk sont proteges). OPERATION TRES DESTRUCTRICE :
    la suppression d'un safe efface tous les comptes/enregistrements qu'il contient.

.PARAMETER ExcludeSafe
    Noms (ou motifs avec *) de safes a conserver en plus de la liste native.

.PARAMETER ExactNativeMatchOnly
    Avec -CleanSafes : protege UNIQUEMENT les safes dont le nom figure exactement
    dans la liste native (desactive la protection par prefixe PSM*/PVWA*/...).
    A utiliser avec prudence.

.PARAMETER ReportPath
    Chemin d'un fichier CSV ou exporter le rapport des elements cibles/supprimes.

.PARAMETER Execute
    Effectue reellement les suppressions. Sans ce commutateur => simulation.

.PARAMETER SkipCertificateCheck
    Ignore la validation du certificat TLS (utile sur un PVWA en certificat
    auto-signe dans un lab isole).

.PARAMETER LogFile
    Chemin d'un fichier journal optionnel.

.EXAMPLE
    # 1) Simulation : voir ce qui serait supprime
    .\Cleanup-CyberArkComponents.ps1 -PVWAUrl https://pvwa.isole.local -SkipCertificateCheck

.EXAMPLE
    # 2) Suppression reelle des CPM/PSM/PSMP/CP/PTA, en gardant le nouveau PSM
    .\Cleanup-CyberArkComponents.ps1 -PVWAUrl https://pvwa.isole.local `
        -Component CPM,PSM,PSMP,CP,PTA -ExcludeUser 'PSMApp_NEWHOST','PSMGw_NEWHOST' `
        -SkipCertificateCheck -Execute

.EXAMPLE
    # 3) Ne purger que les traces PTA
    .\Cleanup-CyberArkComponents.ps1 -PVWAUrl https://pvwa.isole.local -Component PTA -Execute

.EXAMPLE
    # 4) Simulation du menage des safes non natifs + export CSV
    .\Cleanup-CyberArkComponents.ps1 -PVWAUrl https://pvwa.isole.local -SkipUserCleanup `
        -CleanSafes -SkipCertificateCheck -ReportPath .\rapport-safes.csv

.EXAMPLE
    # 5) Menage complet : users composants + safes non natifs (en conservant 2 safes metier)
    .\Cleanup-CyberArkComponents.ps1 -PVWAUrl https://pvwa.isole.local `
        -Component CPM,PSM,PSMP,CP,PTA -CleanSafes -ExcludeSafe 'SAFE_METIER_*','LegacyApp' `
        -SkipCertificateCheck -ReportPath .\rapport.csv -Execute
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$PVWAUrl,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateSet('Cyberark', 'LDAP', 'RADIUS', 'Windows')]
    [string]$AuthType = 'Cyberark',

    [Parameter()]
    [ValidateSet('CPM', 'PSM', 'PSMP', 'CP', 'PTA', 'PVWA', 'All')]
    [string[]]$Component = @('CPM', 'PSM', 'PSMP', 'CP', 'PTA'),

    [Parameter()]
    [string[]]$ExcludeUser = @(),

    [Parameter()]
    [string[]]$IncludeUser = @(),

    [Parameter()]
    [switch]$SkipUserCleanup,

    [Parameter()]
    [switch]$CleanSafes,

    [Parameter()]
    [string[]]$ExcludeSafe = @(),

    [Parameter()]
    [switch]$ExactNativeMatchOnly,

    [Parameter()]
    [string]$ReportPath,

    [Parameter()]
    [switch]$Execute,

    [Parameter()]
    [switch]$SkipCertificateCheck,

    [Parameter()]
    [string]$LogFile
)

#region ---------- Utilitaires ----------

$ErrorActionPreference = 'Stop'

# Utilisateurs internes du Vault a NE JAMAIS supprimer.
$script:ProtectedUsers = @(
    'Master', 'Administrator', 'Auditor', 'Backup', 'Batch', 'DR',
    'NotificationEngine', 'Operator', 'PVWAGWUser'
) # PVWAGWUser/Operator ajoutes par prudence ; retires de la cible via -Component.

# Cartographie composant -> (userTypes attendus, motifs de nom).
# La selection se fait d'abord sur userType, avec repli sur le motif de nom.
$script:ComponentMap = @{
    CPM  = @{ Types = @('CPM'); Patterns = @('PasswordManager*') }
    PSM  = @{ Types = @('PSM'); Patterns = @('PSMApp_*', 'PSMGw_*', 'PSMAppUsers', 'PSMGWUser', 'PSM_*') }
    PSMP = @{ Types = @('PSMP', 'PSMPApp'); Patterns = @('PSMPApp_*', 'PSMPGw_*', 'PSMP_*') }
    CP   = @{ Types = @('AIMApp', 'AppPrv', 'AppProvider'); Patterns = @('Prov_*', 'AppProvider*', 'AIMWebService*') }
    PTA  = @{ Types = @('PTA'); Patterns = @('PTA*', 'PTAUser*', 'PTAAppUser*') }
    PVWA = @{ Types = @('PVWA'); Patterns = @('PVWAAppUser*', 'PVWAUsers', 'PVWAGWAccounts', 'PVWAGWUser') }
}

# Safes systeme/composants natifs de CyberArk -> a NE JAMAIS supprimer.
$script:NativeSafes = @(
    'System', 'VaultInternal', 'Notification Engine', 'Pictures',
    'PVWAConfig', 'PVWAReports', 'PVWAPublicData', 'PVWAPrivateUserPrefs',
    'PVWAUserPrefs', 'PVWATaskDefinitions', 'PVWATicketingSystem',
    'PasswordManager', 'PasswordManager_Pending', 'PasswordManager_workspace',
    'PasswordManager_ADInternal', 'PasswordManager_Info', 'PasswordManagerShared',
    'PSM', 'PSMSessions', 'PSMRecordings', 'PSMLiveSessions',
    'PSMUnmanagedSessionAccounts', 'PSMNotifications',
    'PSMPConf', 'PSMPLiveSessions', 'PSMPADBridgeConf', 'PSMPADBUserProfile',
    'PSMPADBridgeCustom', 'PSMPUnmanagedSessionAccounts',
    'AccountsFeed', 'AccountsFeedADAccounts', 'AccountsFeedDiscoveryLogs',
    'TelemetryConfig', 'ConjurSync', 'Reports', 'DR'
)

# Prefixes reserves aux safes geres par les composants (protection supplementaire,
# desactivable via -ExactNativeMatchOnly).
$script:NativeSafePrefixes = @(
    'PSMP', 'PSM', 'PVWA', 'PasswordManager', 'AccountsFeed', 'VaultInternal', 'ConjurSync'
)

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK', 'DRYRUN')]
        [string]$Level = 'INFO'
    )
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$stamp] [$Level] $Message"
    $color = switch ($Level) {
        'ERROR'  { 'Red' }
        'WARN'   { 'Yellow' }
        'OK'     { 'Green' }
        'DRYRUN' { 'Cyan' }
        default  { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
    if ($LogFile) { Add-Content -Path $LogFile -Value $line }
}

# Construit les parametres communs d'Invoke-RestMethod (gestion TLS / certificat).
function Get-RestBaseParams {
    $p = @{}
    if ($SkipCertificateCheck) {
        if ($PSVersionTable.PSEdition -eq 'Core') {
            # PowerShell 7+
            $p['SkipCertificateCheck'] = $true
        }
        else {
            # Windows PowerShell 5.1 : politique de certificat permissive + TLS1.2
            if (-not ('TrustAllCertsPolicy' -as [type])) {
                Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
            }
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
    }
    return $p
}

function Invoke-PVWA {
    param(
        [string]$Method,
        [string]$Uri,
        [hashtable]$Headers,
        $Body
    )
    $params = Get-RestBaseParams
    $params['Method'] = $Method
    $params['Uri'] = $Uri
    $params['ContentType'] = 'application/json'
    if ($Headers) { $params['Headers'] = $Headers }
    if ($null -ne $Body) { $params['Body'] = ($Body | ConvertTo-Json -Depth 5) }
    return Invoke-RestMethod @params
}

#endregion

#region ---------- Connexion ----------

# Normalisation de l'URL de base.
$PVWAUrl = $PVWAUrl.TrimEnd('/')
if ($PVWAUrl -notmatch '/PasswordVault$') { $PVWAUrl = "$PVWAUrl/PasswordVault" }
$apiBase = "$PVWAUrl/api"

if (-not $Credential) {
    $Credential = Get-Credential -Message "Identifiants pour l'API CyberArk ($AuthType)"
}

Write-Log "Cible PVWA : $apiBase"
Write-Log ("Mode : {0}" -f $(if ($Execute) { 'EXECUTION (suppressions reelles)' } else { 'SIMULATION (dry-run)' })) `
    -Level $(if ($Execute) { 'WARN' } else { 'DRYRUN' })

$token = $null
try {
    $logonUri = "$apiBase/auth/$AuthType/Logon"
    $logonBody = @{
        username          = $Credential.UserName
        password          = $Credential.GetNetworkCredential().Password
        concurrentSession = $true
    }
    Write-Log "Authentification sur $logonUri ..."
    $token = Invoke-PVWA -Method Post -Uri $logonUri -Body $logonBody
    $token = $token.Trim('"')
    Write-Log "Authentification reussie." -Level OK
}
catch {
    Write-Log "Echec de l'authentification : $($_.Exception.Message)" -Level ERROR
    throw
}

$authHeader = @{ Authorization = $token }

# Collecte pour le rapport CSV (users + safes).
$script:report = @()

function Test-WildcardMatch {
    param([string]$Value, [string[]]$Patterns)
    foreach ($p in $Patterns) { if ($Value -like $p) { return $true } }
    return $false
}

#endregion

#region ---------- Recuperation des component users ----------

function Get-ComponentUsers {
    $all = @()
    $offset = 0
    $pageSize = 1000
    do {
        $uri = "$apiBase/Users?ExtendedDetails=true&pageSize=$pageSize&pageOffset=$offset&filter=componentUser%20eq%20true"
        $resp = Invoke-PVWA -Method Get -Uri $uri -Headers $authHeader
        if ($resp.Users) { $all += $resp.Users }
        $count = @($resp.Users).Count
        $offset += $pageSize
    } while ($count -eq $pageSize)
    return $all
}

$selected = if ($Component -contains 'All') { $script:ComponentMap.Keys } else { $Component }
$componentUsers = @()
if (-not $SkipUserCleanup) {
    Write-Log "Recuperation des utilisateurs techniques (componentUser=true) ..."
    $componentUsers = @(Get-ComponentUsers)
    Write-Log ("{0} utilisateur(s) technique(s) trouve(s) dans le coffre." -f $componentUsers.Count)
}
else {
    Write-Log "Menage des component users ignore (-SkipUserCleanup)."
}

#endregion

#region ---------- Selection des cibles (users) ----------

$targets = @()
foreach ($u in $componentUsers) {
    $uname = $u.username
    $utype = $u.userType

    # Protection : utilisateurs internes.
    if ($script:ProtectedUsers -contains $uname) { continue }

    # Exclusions explicites (noms ou motifs).
    if (Test-WildcardMatch -Value $uname -Patterns $ExcludeUser) {
        Write-Log "Conserve (exclu) : $uname [$utype]"
        continue
    }

    $matchedComponent = $null
    foreach ($comp in $selected) {
        $map = $script:ComponentMap[$comp]
        $byType = $map.Types -contains $utype
        $byName = Test-WildcardMatch -Value $uname -Patterns $map.Patterns
        if ($byType -or $byName) { $matchedComponent = $comp; break }
    }

    # Inclusions forcees.
    if (-not $matchedComponent -and (Test-WildcardMatch -Value $uname -Patterns $IncludeUser)) {
        $matchedComponent = 'FORCE'
    }

    if ($matchedComponent) {
        $targets += [pscustomobject]@{
            Id        = $u.id
            Username  = $uname
            UserType  = $utype
            Component = $matchedComponent
        }
    }
}

if ($targets.Count -eq 0) {
    Write-Log "Aucun compte a supprimer pour les composants selectionnes : $($selected -join ', ')." -Level OK
}
else {
    Write-Log ("{0} compte(s) cible(s) pour suppression :" -f $targets.Count) -Level WARN
    $targets | Sort-Object Component, Username |
        Format-Table -AutoSize Component, Username, UserType, Id | Out-String | Write-Host
}

#endregion

#region ---------- Suppression (users) ----------

$deleted = 0
$failed = 0
foreach ($t in ($targets | Sort-Object Component, Username)) {
    $delUri = "$apiBase/Users/$($t.Id)"
    $status = 'WouldDelete'
    if (-not $Execute) {
        Write-Log "[SIMULATION] Supprimerait : $($t.Username) (id=$($t.Id), type=$($t.UserType), composant=$($t.Component))" -Level DRYRUN
    }
    elseif ($PSCmdlet.ShouldProcess("$($t.Username) (id=$($t.Id))", 'Supprimer le component user')) {
        try {
            Invoke-PVWA -Method Delete -Uri $delUri -Headers $authHeader | Out-Null
            Write-Log "Supprime : $($t.Username) (id=$($t.Id))" -Level OK
            $deleted++; $status = 'Deleted'
        }
        catch {
            Write-Log "Echec suppression $($t.Username) (id=$($t.Id)) : $($_.Exception.Message)" -Level ERROR
            $failed++; $status = 'Failed'
        }
    }
    else { $status = 'Skipped' }
    $script:report += [pscustomobject]@{
        Kind = 'User'; Name = $t.Username; Identifier = $t.Id
        Category = $t.Component; Detail = $t.UserType; Status = $status
    }
}

#endregion

#region ---------- Menage des safes (optionnel) ----------

$safeDeleted = 0
$safeFailed = 0
$safeTargets = @()
if ($CleanSafes) {
    function Get-AllSafes {
        $all = @()
        $offset = 0
        $limit = 1000
        do {
            $uri = "$apiBase/Safes?limit=$limit&offset=$offset"
            $resp = Invoke-PVWA -Method Get -Uri $uri -Headers $authHeader
            if ($resp.value) { $all += $resp.value }
            $count = @($resp.value).Count
            $offset += $limit
        } while ($count -eq $limit)
        return $all
    }

    Write-Log "------------------------------------------------------------"
    Write-Log "Recuperation des safes ..."
    $allSafes = @(Get-AllSafes)
    Write-Log ("{0} safe(s) trouve(s) dans le coffre." -f $allSafes.Count)

    foreach ($s in $allSafes) {
        $sname = $s.safeName
        $surl = $s.safeUrlId
        if (-not $surl) { $surl = $sname }

        if ($script:NativeSafes -contains $sname) { continue }
        if (-not $ExactNativeMatchOnly) {
            $isNativePrefix = $false
            foreach ($pfx in $script:NativeSafePrefixes) {
                if ($sname -like "$pfx*") { $isNativePrefix = $true; break }
            }
            if ($isNativePrefix) { continue }
        }
        if (Test-WildcardMatch -Value $sname -Patterns $ExcludeSafe) {
            Write-Log "Conserve (exclu) : safe '$sname'"
            continue
        }
        $safeTargets += [pscustomobject]@{ Name = $sname; UrlId = $surl }
    }

    if ($safeTargets.Count -eq 0) {
        Write-Log "Aucun safe non-natif a supprimer." -Level OK
    }
    else {
        Write-Log ("{0} safe(s) NON natif(s) cible(s) pour suppression :" -f $safeTargets.Count) -Level WARN
        $safeTargets | Sort-Object Name | Format-Table -AutoSize Name, UrlId | Out-String | Write-Host
        Write-Log "ATTENTION : supprimer un safe efface DEFINITIVEMENT tous ses comptes/enregistrements." -Level WARN
    }

    foreach ($st in ($safeTargets | Sort-Object Name)) {
        $delUri = "$apiBase/Safes/$([uri]::EscapeDataString($st.UrlId))"
        $status = 'WouldDelete'
        if (-not $Execute) {
            Write-Log "[SIMULATION] Supprimerait le safe : '$($st.Name)'" -Level DRYRUN
        }
        elseif ($PSCmdlet.ShouldProcess("safe '$($st.Name)'", 'Supprimer le safe (DESTRUCTIF)')) {
            try {
                Invoke-PVWA -Method Delete -Uri $delUri -Headers $authHeader | Out-Null
                Write-Log "Safe supprime : '$($st.Name)'" -Level OK
                $safeDeleted++; $status = 'Deleted'
            }
            catch {
                Write-Log "Echec suppression safe '$($st.Name)' : $($_.Exception.Message)" -Level ERROR
                $safeFailed++; $status = 'Failed'
            }
        }
        else { $status = 'Skipped' }
        $script:report += [pscustomobject]@{
            Kind = 'Safe'; Name = $st.Name; Identifier = $st.UrlId
            Category = 'Safe'; Detail = ''; Status = $status
        }
    }
}

#endregion

#region ---------- Deconnexion + rapport ----------

try {
    Invoke-PVWA -Method Post -Uri "$apiBase/auth/Logoff" -Headers $authHeader | Out-Null
    Write-Log "Deconnexion effectuee." -Level OK
}
catch {
    Write-Log "Avertissement : echec du logoff : $($_.Exception.Message)" -Level WARN
}

Write-Log "------------------------------------------------------------"
if ($Execute) {
    Write-Log ("Users  -> supprimes : {0} | echecs : {1} | cibles : {2}" -f $deleted, $failed, $targets.Count) `
        -Level $(if ($failed) { 'WARN' } else { 'OK' })
    if ($CleanSafes) {
        Write-Log ("Safes  -> supprimes : {0} | echecs : {1} | cibles : {2}" -f $safeDeleted, $safeFailed, $safeTargets.Count) `
            -Level $(if ($safeFailed) { 'WARN' } else { 'OK' })
    }
}
else {
    Write-Log ("Simulation terminee. Users cibles : {0}{1}. Relancez avec -Execute pour appliquer." -f `
            $targets.Count, $(if ($CleanSafes) { " | Safes cibles : $($safeTargets.Count)" } else { '' })) -Level DRYRUN
}

if ($ReportPath) {
    try {
        $script:report | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
        Write-Log "Rapport CSV exporte : $ReportPath" -Level OK
    }
    catch {
        Write-Log "Echec export CSV : $($_.Exception.Message)" -Level WARN
    }
}

if ($selected -contains 'PTA') {
    Write-Log "------------------------------------------------------------"
    Write-Log "NOTE PTA : ce script supprime le(s) utilisateur(s) PTA du coffre via l'API." -Level WARN
    Write-Log "Les traces residuelles cote PTA NON accessibles par l'API REST Vault doivent" -Level WARN
    Write-Log "etre traitees sur l'appliance / la console PTA :" -Level WARN
    Write-Log "  - Reset de l'integration Vault dans la config PTA (vault.ini / Vault user)" -Level WARN
    Write-Log "  - Suppression des anciens capteurs/sources Syslog dans la console PTA" -Level WARN
    Write-Log "  - Purge des entrees PTA obsoletes dans System Health / Component Monitoring" -Level WARN
    Write-Log "    (ces entrees s'effacent aussi d'elles-memes apres expiration des heartbeats)" -Level WARN
}
#endregion
