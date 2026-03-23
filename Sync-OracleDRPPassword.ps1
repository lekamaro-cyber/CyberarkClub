<#
.SYNOPSIS
    Synchronise le mot de passe d'un compte Oracle DRP depuis son equivalent PRD dans CyberArk.

.DESCRIPTION
    Ce script :
    1. Se connecte au PVWA CyberArk (API REST)
    2. Recherche le compte PRD (Production) pour un utilisateur/base donnee
    3. Recupere le mot de passe du compte PRD
    4. Recherche le compte DRP equivalent (meme utilisateur, meme base)
    5. Met a jour le mot de passe du compte DRP avec celui du PRD
    6. Lance une verification immediate sur le compte DRP

.PARAMETER PVWAUrl
    URL du serveur PVWA CyberArk (ex: https://pvwa.entreprise.com/PasswordVault)

.PARAMETER AuthType
    Type d authentification : CyberArk, LDAP ou RADIUS. Par defaut : LDAP

.PARAMETER OracleUser
    Nom du compte Oracle a synchroniser (ex: APP_OWNER)

.PARAMETER DatabaseName
    Nom de la base de donnees Oracle (ex: MYDB)

.PARAMETER PRDSafe
    Nom du safe contenant le compte PRD

.PARAMETER DRPSafe
    Nom du safe contenant le compte DRP

.PARAMETER PRDPlatformId
    Platform ID pour les comptes PRD (ex: Oracle-PRD). Par defaut : Oracle

.PARAMETER DRPPlatformId
    Platform ID pour les comptes DRP (ex: Oracle-DRP). Par defaut : Oracle

.PARAMETER Credential
    Objet PSCredential pour l authentification PVWA. Si omis, le script le demande interactivement.

.PARAMETER LogFile
    Chemin du fichier de log. Par defaut : .\Sync-OracleDRP_<date>.log

.EXAMPLE
    .\Sync-OracleDRPPassword.ps1 -PVWAUrl "https://pvwa.corp.local/PasswordVault" `
        -OracleUser "APP_OWNER" -DatabaseName "FINDB" `
        -PRDSafe "Oracle-PRD-Accounts" -DRPSafe "Oracle-DRP-Accounts"

.EXAMPLE
    # Traitement en lot depuis un CSV (colonnes: OracleUser, DatabaseName)
    Import-Csv .\comptes.csv | ForEach-Object {
        .\Sync-OracleDRPPassword.ps1 -PVWAUrl $pvwa `
            -OracleUser $_.OracleUser -DatabaseName $_.DatabaseName `
            -PRDSafe "SAF-PRD" -DRPSafe "SAF-DRP" -Credential $cred
    }
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PVWAUrl,

    [ValidateSet("CyberArk", "LDAP", "RADIUS")]
    [string]$AuthType = "LDAP",

    [Parameter(Mandatory)]
    [string]$OracleUser,

    [Parameter(Mandatory)]
    [string]$DatabaseName,

    [Parameter(Mandatory)]
    [string]$PRDSafe,

    [Parameter(Mandatory)]
    [string]$DRPSafe,

    [string]$PRDPlatformId = "Oracle",

    [string]$DRPPlatformId = "Oracle",

    [PSCredential]$Credential,

    [string]$LogFile = ".\Sync-OracleDRP_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Ignore les certificats auto-signes (environnements lab) ---
if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) { return true; }
}
"@
}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ============================================================
#  Fonctions utilitaires
# ============================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    Write-Host $line -ForegroundColor $(switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "OK"    { "Green" }
        default { "White" }
    })
    $line | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

function Invoke-PVWARestMethod {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [object]$Body
    )
    $params = @{
        Uri         = $Uri
        Method      = $Method
        ContentType = "application/json"
        Headers     = $Headers
    }
    if ($Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 10)
    }
    try {
        Invoke-RestMethod @params
    }
    catch {
        $status = $_.Exception.Response.StatusCode.value__
        $detail = $_.ErrorDetails.Message
        Write-Log "Appel API echoue [$Method $Uri] - HTTP $status : $detail" "ERROR"
        throw
    }
}

# ============================================================
#  1. Authentification au PVWA
# ============================================================

$baseUrl = $PVWAUrl.TrimEnd('/')

if (-not $Credential) {
    $Credential = Get-Credential -Message "Entrez vos identifiants PVWA CyberArk"
}

Write-Log "Connexion au PVWA ($baseUrl) avec le type d'auth : $AuthType"

$authBody = @{
    username = $Credential.UserName
    password = $Credential.GetNetworkCredential().Password
}

$authUrl = "$baseUrl/api/auth/$AuthType/Logon"
$token = Invoke-PVWARestMethod -Uri $authUrl -Method POST -Body $authBody

if (-not $token) {
    Write-Log "Echec d'authentification au PVWA." "ERROR"
    exit 1
}

# Le token est retourne sous forme de chaine entre guillemets
$token = $token.Trim('"')
$authHeaders = @{ Authorization = $token }
Write-Log "Authentification reussie." "OK"

# ============================================================
#  2. Recherche du compte PRD
# ============================================================

Write-Log "Recherche du compte PRD : User=$OracleUser, DB=$DatabaseName, Safe=$PRDSafe"

$searchFilter = "safename eq $PRDSafe"
$searchQuery = "$OracleUser $DatabaseName"
$prdSearchUrl = "$baseUrl/api/accounts?search=$searchQuery&filter=$searchFilter"

$prdResults = Invoke-PVWARestMethod -Uri $prdSearchUrl -Headers $authHeaders

if ($prdResults.count -eq 0) {
    Write-Log "Aucun compte PRD trouve pour $OracleUser@$DatabaseName dans le safe $PRDSafe" "ERROR"
    exit 1
}

# Filtrage precis sur le username et le nom de base
$prdAccount = $prdResults.value | Where-Object {
    $_.userName -ieq $OracleUser -and
    ($_.platformAccountProperties.Database -ieq $DatabaseName -or
     $_.address -ieq $DatabaseName)
} | Select-Object -First 1

if (-not $prdAccount) {
    Write-Log "Compte PRD introuvable apres filtrage fin (user=$OracleUser, db=$DatabaseName)" "ERROR"
    Write-Log "Comptes retournes : $($prdResults.value | ForEach-Object { $_.name } | Out-String)" "WARN"
    exit 1
}

$prdAccountId   = $prdAccount.id
$prdAccountName = $prdAccount.name
Write-Log "Compte PRD trouve : $prdAccountName (ID: $prdAccountId)" "OK"

# ============================================================
#  3. Recuperation du mot de passe PRD
# ============================================================

Write-Log "Recuperation du mot de passe du compte PRD..."

$retrieveUrl = "$baseUrl/api/accounts/$prdAccountId/Password/Retrieve"
$retrieveBody = @{ reason = "Synchronisation DRP - copie mot de passe PRD vers DRP" }

$prdPassword = Invoke-PVWARestMethod -Uri $retrieveUrl -Method POST -Headers $authHeaders -Body $retrieveBody

if (-not $prdPassword) {
    Write-Log "Impossible de recuperer le mot de passe PRD." "ERROR"
    exit 1
}

Write-Log "Mot de passe PRD recupere avec succes." "OK"

# ============================================================
#  4. Recherche du compte DRP
# ============================================================

Write-Log "Recherche du compte DRP : User=$OracleUser, DB=$DatabaseName, Safe=$DRPSafe"

$drpSearchFilter = "safename eq $DRPSafe"
$drpSearchUrl = "$baseUrl/api/accounts?search=$searchQuery&filter=$drpSearchFilter"

$drpResults = Invoke-PVWARestMethod -Uri $drpSearchUrl -Headers $authHeaders

if ($drpResults.count -eq 0) {
    Write-Log "Aucun compte DRP trouve pour $OracleUser@$DatabaseName dans le safe $DRPSafe" "ERROR"
    exit 1
}

$drpAccount = $drpResults.value | Where-Object {
    $_.userName -ieq $OracleUser -and
    ($_.platformAccountProperties.Database -ieq $DatabaseName -or
     $_.address -ieq $DatabaseName)
} | Select-Object -First 1

if (-not $drpAccount) {
    Write-Log "Compte DRP introuvable apres filtrage fin (user=$OracleUser, db=$DatabaseName)" "ERROR"
    exit 1
}

$drpAccountId   = $drpAccount.id
$drpAccountName = $drpAccount.name
Write-Log "Compte DRP trouve : $drpAccountName (ID: $drpAccountId)" "OK"

# ============================================================
#  5. Mise a jour du mot de passe DRP avec celui du PRD
# ============================================================

Write-Log "Mise a jour du mot de passe DRP avec le mot de passe PRD..."

$changeUrl = "$baseUrl/api/accounts/$drpAccountId/Password/Update"
$changeBody = @{
    NewCredentials = $prdPassword
}

Invoke-PVWARestMethod -Uri $changeUrl -Method POST -Headers $authHeaders -Body $changeBody
Write-Log "Mot de passe du compte DRP mis a jour avec succes." "OK"

# ============================================================
#  6. Lancement de la verification sur le compte DRP
# ============================================================

Write-Log "Lancement de la verification du compte DRP..."

$verifyUrl = "$baseUrl/api/accounts/$drpAccountId/Verify"

Invoke-PVWARestMethod -Uri $verifyUrl -Method POST -Headers $authHeaders
Write-Log "Verification lancee sur le compte DRP : $drpAccountName" "OK"

# ============================================================
#  7. Deconnexion
# ============================================================

Write-Log "Deconnexion du PVWA..."
try {
    Invoke-PVWARestMethod -Uri "$baseUrl/api/auth/Logoff" -Method POST -Headers $authHeaders
    Write-Log "Deconnexion reussie." "OK"
}
catch {
    Write-Log "Erreur lors de la deconnexion (non critique) : $_" "WARN"
}

# ============================================================
#  Resume
# ============================================================

Write-Log "=== RESUME ===" "OK"
Write-Log "Compte PRD source  : $prdAccountName (Safe: $PRDSafe)" "OK"
Write-Log "Compte DRP cible   : $drpAccountName (Safe: $DRPSafe)" "OK"
Write-Log "Utilisateur Oracle : $OracleUser" "OK"
Write-Log "Base de donnees    : $DatabaseName" "OK"
Write-Log "Mot de passe copie : OUI" "OK"
Write-Log "Verification       : LANCEE" "OK"
Write-Log "Log complet        : $LogFile" "OK"
