<#
.SYNOPSIS
    Synchronise le mot de passe d'un compte Oracle DRP depuis son equivalent PRD dans CyberArk.

.DESCRIPTION
    Ce script :
    1. Se connecte au PVWA CyberArk (API REST)
    2. Recherche le compte PRD par utilisateur + base + adresse PRD
    3. Recupere le mot de passe du compte PRD
    4. Recherche le compte DRP par utilisateur + base + adresse DRP
    5. Met a jour le mot de passe du compte DRP avec celui du PRD
    6. Lance une verification immediate sur le compte DRP

    Le user Oracle et la base de donnees sont identiques entre PRD et DRP.
    Seule l'adresse (serveur) change.

.PARAMETER PVWAUrl
    URL du serveur PVWA CyberArk (ex: https://pvwa.entreprise.com/PasswordVault)

.PARAMETER AuthType
    Type d authentification : CyberArk, LDAP ou RADIUS. Par defaut : LDAP

.PARAMETER OracleUser
    Nom du compte Oracle a synchroniser (ex: APP_OWNER)

.PARAMETER DatabaseName
    Nom de la base de donnees Oracle (ex: MYDB)

.PARAMETER PRDAddress
    Adresse (serveur) du compte PRD (ex: oraprd01.corp.local)

.PARAMETER DRPAddress
    Adresse (serveur) du compte DRP (ex: oradrp01.corp.local)

.PARAMETER Safe
    Nom du safe CyberArk (optionnel, pour affiner la recherche)

.PARAMETER CsvFile
    Chemin vers un fichier CSV pour traitement en lot.
    Colonnes attendues : User,Database,AdressePRD,AdresseDRP

.PARAMETER Credential
    Objet PSCredential pour l authentification PVWA. Si omis, le script le demande interactivement.

.PARAMETER LogFile
    Chemin du fichier de log. Par defaut : .\Sync-OracleDRP_<date>.log

.EXAMPLE
    .\Sync-OracleDRPPassword.ps1 -PVWAUrl "https://pvwa.corp.local/PasswordVault" `
        -OracleUser "APP_OWNER" -DatabaseName "FINDB" `
        -PRDAddress "oraprd01.corp.local" -DRPAddress "oradrp01.corp.local"

.EXAMPLE
    # Traitement en lot depuis un CSV
    .\Sync-OracleDRPPassword.ps1 -PVWAUrl "https://pvwa.corp.local/PasswordVault" `
        -CsvFile ".\comptes.csv"
#>

[CmdletBinding(DefaultParameterSetName = "Single")]
param(
    [Parameter(Mandatory)]
    [string]$PVWAUrl,

    [ValidateSet("CyberArk", "LDAP", "RADIUS")]
    [string]$AuthType = "LDAP",

    [Parameter(Mandatory, ParameterSetName = "Single")]
    [string]$OracleUser,

    [Parameter(Mandatory, ParameterSetName = "Single")]
    [string]$DatabaseName,

    [Parameter(Mandatory, ParameterSetName = "Single")]
    [string]$PRDAddress,

    [Parameter(Mandatory, ParameterSetName = "Single")]
    [string]$DRPAddress,

    [Parameter(Mandatory, ParameterSetName = "Batch")]
    [string]$CsvFile,

    [string]$Safe,

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
        $status = "N/A"
        $detail = $_.Exception.Message
        if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) {
            try { $status = $_.Exception.Response.StatusCode.value__ } catch {}
        }
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $detail = $_.ErrorDetails.Message
        }
        Write-Log "Appel API echoue [$Method $Uri] - HTTP $status : $detail" "ERROR"
        throw
    }
}

function Find-CyberArkAccount {
    param(
        [string]$BaseUrl,
        [hashtable]$AuthHeaders,
        [string]$User,
        [string]$Database,
        [string]$Address,
        [string]$SafeName
    )

    $searchQuery = "$User $Database"
    $searchUrl = "$BaseUrl/api/accounts?search=$searchQuery"

    if ($SafeName) {
        $searchUrl += "&filter=safename eq $SafeName"
    }

    $results = Invoke-PVWARestMethod -Uri $searchUrl -Headers $AuthHeaders

    # Gerer les differents formats de reponse PVWA
    $accounts = $null
    if ($results -and $results.PSObject.Properties['value']) {
        $accounts = $results.value
    } elseif ($results -is [array]) {
        $accounts = $results
    }

    if (-not $accounts -or @($accounts).Count -eq 0) { return $null }

    # Filtrage precis : meme user + meme base + meme adresse
    $matched = @($accounts | Where-Object {
        $_.userName -ieq $User -and
        $_.address -ieq $Address -and
        ($_.platformAccountProperties.Database -ieq $Database -or
         $_.name -imatch $Database)
    })

    if ($matched.Count -gt 1) {
        Write-Log "ANOMALIE : $($matched.Count) comptes trouves pour $User@$Database [$Address] - attendu 1 seul !" "ERROR"
        Write-Log "Comptes en doublon :" "ERROR"
        foreach ($dup in $matched) {
            Write-Log "  - $($dup.name) (ID: $($dup.id), Safe: $($dup.safeName))" "ERROR"
        }
        throw "Doublon detecte : $($matched.Count) comptes pour le triplet ($User, $Database, $Address). Corrigez dans CyberArk avant de relancer."
    }

    if ($matched.Count -eq 0) { return $null }

    return $matched[0]
}

function Sync-SingleAccount {
    param(
        [string]$BaseUrl,
        [hashtable]$AuthHeaders,
        [string]$User,
        [string]$Database,
        [string]$AddressPRD,
        [string]$AddressDRP,
        [string]$SafeName
    )

    Write-Log "------------------------------------------------------"
    Write-Log "Traitement : User=$User | DB=$Database | PRD=$AddressPRD | DRP=$AddressDRP"

    # --- Recherche du compte PRD ---
    Write-Log "Recherche du compte PRD ($User@$Database sur $AddressPRD)..."
    $prdAccount = Find-CyberArkAccount -BaseUrl $BaseUrl -AuthHeaders $AuthHeaders `
        -User $User -Database $Database -Address $AddressPRD -SafeName $SafeName

    if (-not $prdAccount) {
        Write-Log "Compte PRD introuvable : $User@$Database [$AddressPRD]" "ERROR"
        return $false
    }
    Write-Log "Compte PRD trouve : $($prdAccount.name) (ID: $($prdAccount.id))" "OK"

    # --- Recuperation du mot de passe PRD ---
    Write-Log "Recuperation du mot de passe PRD..."
    $retrieveUrl = "$BaseUrl/api/accounts/$($prdAccount.id)/Password/Retrieve"
    $retrieveBody = @{ reason = "Sync DRP - copie mdp PRD vers DRP pour $User@$Database" }
    $prdPassword = Invoke-PVWARestMethod -Uri $retrieveUrl -Method POST -Headers $AuthHeaders -Body $retrieveBody

    if (-not $prdPassword) {
        Write-Log "Impossible de recuperer le mot de passe PRD." "ERROR"
        return $false
    }
    Write-Log "Mot de passe PRD recupere." "OK"

    # --- Recherche du compte DRP ---
    Write-Log "Recherche du compte DRP ($User@$Database sur $AddressDRP)..."
    $drpAccount = Find-CyberArkAccount -BaseUrl $BaseUrl -AuthHeaders $AuthHeaders `
        -User $User -Database $Database -Address $AddressDRP -SafeName $SafeName

    if (-not $drpAccount) {
        Write-Log "Compte DRP introuvable : $User@$Database [$AddressDRP]" "ERROR"
        return $false
    }
    Write-Log "Compte DRP trouve : $($drpAccount.name) (ID: $($drpAccount.id))" "OK"

    # --- Mise a jour du mot de passe DRP ---
    Write-Log "Mise a jour du mot de passe DRP avec celui du PRD..."
    $changeUrl = "$BaseUrl/api/accounts/$($drpAccount.id)/Password/Update"
    $changeBody = @{ NewCredentials = $prdPassword }
    Invoke-PVWARestMethod -Uri $changeUrl -Method POST -Headers $AuthHeaders -Body $changeBody
    Write-Log "Mot de passe DRP mis a jour." "OK"

    # --- Verification immediate ---
    Write-Log "Lancement de la verification sur le compte DRP..."
    $verifyUrl = "$BaseUrl/api/accounts/$($drpAccount.id)/Verify"
    Invoke-PVWARestMethod -Uri $verifyUrl -Method POST -Headers $AuthHeaders
    Write-Log "Verification lancee sur $($drpAccount.name)." "OK"

    return $true
}

# ============================================================
#  MAIN
# ============================================================

$baseUrl = $PVWAUrl.TrimEnd('/')

# --- Authentification ---
if (-not $Credential) {
    $Credential = Get-Credential -Message "Entrez vos identifiants PVWA CyberArk"
}

Write-Log "Connexion au PVWA ($baseUrl) - Auth: $AuthType"

$authBody = @{
    username = $Credential.UserName
    password = $Credential.GetNetworkCredential().Password
}
$token = Invoke-PVWARestMethod -Uri "$baseUrl/api/auth/$AuthType/Logon" -Method POST -Body $authBody

if (-not $token) {
    Write-Log "Echec d'authentification au PVWA." "ERROR"
    exit 1
}

$token = $token.Trim('"').Trim().Replace("`r","").Replace("`n","")
$authHeaders = @{ Authorization = $token }
Write-Log "Authentification reussie." "OK"

# --- Construction de la liste des comptes a traiter ---
$accounts = @()

if ($PSCmdlet.ParameterSetName -eq "Batch") {
    if (-not (Test-Path $CsvFile)) {
        Write-Log "Fichier CSV introuvable : $CsvFile" "ERROR"
        exit 1
    }
    $accounts = @(Import-Csv -Path $CsvFile -Delimiter ",")
    Write-Log "CSV charge : $($accounts.Count) comptes a traiter depuis $CsvFile"
}
else {
    $accounts = @([PSCustomObject]@{
        User        = $OracleUser
        Database    = $DatabaseName
        AdressePRD  = $PRDAddress
        AdresseDRP  = $DRPAddress
    })
}

# --- Traitement ---
$totalSuccess = 0
$totalFail    = 0

foreach ($entry in $accounts) {
    try {
        $result = Sync-SingleAccount -BaseUrl $baseUrl -AuthHeaders $authHeaders `
            -User $entry.User -Database $entry.Database `
            -AddressPRD $entry.AdressePRD -AddressDRP $entry.AdresseDRP `
            -SafeName $Safe

        if ($result) { $totalSuccess++ } else { $totalFail++ }
    }
    catch {
        Write-Log "Erreur sur $($entry.User)@$($entry.Database) : $_" "ERROR"
        $totalFail++
    }
}

# --- Deconnexion ---
Write-Log "Deconnexion du PVWA..."
try {
    Invoke-PVWARestMethod -Uri "$baseUrl/api/auth/Logoff" -Method POST -Headers $authHeaders
    Write-Log "Deconnexion reussie." "OK"
}
catch {
    Write-Log "Erreur lors de la deconnexion (non critique) : $_" "WARN"
}

# --- Resume ---
Write-Log "======================================================" "OK"
Write-Log "=== RESUME FINAL ===" "OK"
Write-Log "Total traites  : $($totalSuccess + $totalFail)" "OK"
Write-Log "Succes         : $totalSuccess" "OK"
Write-Log "Echecs         : $totalFail" $(if ($totalFail -gt 0) { "WARN" } else { "OK" })
Write-Log "Log complet    : $LogFile" "OK"
Write-Log "======================================================" "OK"

if ($totalFail -gt 0) { exit 1 }
