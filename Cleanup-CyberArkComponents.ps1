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

Write-Log "Recuperation des utilisateurs techniques (componentUser=true) ..."
$componentUsers = @(Get-ComponentUsers)
Write-Log ("{0} utilisateur(s) technique(s) trouve(s) dans le coffre." -f $componentUsers.Count)

#endregion

#region ---------- Selection des cibles ----------

# Composants demandes.
$selected = if ($Component -contains 'All') { $script:ComponentMap.Keys } else { $Component }

function Test-WildcardMatch {
    param([string]$Value, [string[]]$Patterns)
    foreach ($p in $Patterns) { if ($Value -like $p) { return $true } }
    return $false
}

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

#region ---------- Suppression ----------

$deleted = 0
$failed = 0
foreach ($t in ($targets | Sort-Object Component, Username)) {
    $delUri = "$apiBase/Users/$($t.Id)"
    if (-not $Execute) {
        Write-Log "[SIMULATION] Supprimerait : $($t.Username) (id=$($t.Id), type=$($t.UserType), composant=$($t.Component))" -Level DRYRUN
        continue
    }
    if ($PSCmdlet.ShouldProcess("$($t.Username) (id=$($t.Id))", 'Supprimer le component user')) {
        try {
            Invoke-PVWA -Method Delete -Uri $delUri -Headers $authHeader | Out-Null
            Write-Log "Supprime : $($t.Username) (id=$($t.Id))" -Level OK
            $deleted++
        }
        catch {
            Write-Log "Echec suppression $($t.Username) (id=$($t.Id)) : $($_.Exception.Message)" -Level ERROR
            $failed++
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
    Write-Log ("Termine. Supprimes : {0} | Echecs : {1} | Total cible : {2}" -f $deleted, $failed, $targets.Count) `
        -Level $(if ($failed) { 'WARN' } else { 'OK' })
}
else {
    Write-Log ("Simulation terminee. {0} compte(s) seraient supprimes. Relancez avec -Execute pour appliquer." -f $targets.Count) `
        -Level DRYRUN
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
