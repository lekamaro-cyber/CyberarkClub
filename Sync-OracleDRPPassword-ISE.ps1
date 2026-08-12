<#
.SYNOPSIS
    ISE version - Synchronizes Oracle DRP passwords from PRD via CSV.

.DESCRIPTION
    Simplified version for PowerShell ISE execution (F5).
    Configure the variables below then run the script.
    Processes all accounts from the CSV file.

    Expected CSV columns: User,DatabasePRD,DatabaseDRP,AdressePRD,AdresseDRP
#>

# ============================================================
#  CONFIGURATION - Edit these values before running
# ============================================================

$PVWAUrl   = "https://oneconnection.intra.corp"
$AuthType  = "LDAP"                          # CyberArk, LDAP, or RADIUS
$CsvFile   = "D:\Cyberark\Majide\PAM Script\SyncOraPRD-DRP\comptes_template.csv"
$Safe      = ""                              # Optional: safe name to filter
$LogFile   = ".\Sync-OracleDRP_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$SkipPRDComplianceCheck = $false             # Set to $true to skip PRD validation (not recommended)

# ============================================================
#  END CONFIGURATION - Do not modify below this line
# ============================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Ignore self-signed certificates (lab environments) ---
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
#  Utility functions
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
        Write-Log "API call failed [$Method $Uri] - HTTP $status : $detail" "ERROR"
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

    # Simple search like psPAS: search="User Address" then local filtering
    $searchQuery = "$User $Address $Database"
    $searchUrl = "$BaseUrl/PasswordVault/api/accounts?search=$searchQuery"
    if ($SafeName) {
        $searchUrl += "&filter=safename eq $SafeName"
    }
    Write-Log "  [DEBUG] API call URL: $searchUrl" "INFO"

    $results = Invoke-PVWARestMethod -Uri $searchUrl -Headers $AuthHeaders

    # Handle different PVWA response formats
    $accounts = $null
    if ($results -and $results.PSObject.Properties['value']) {
        $accounts = $results.value
    } elseif ($results -is [array]) {
        $accounts = $results
    }

    if (-not $accounts -or @($accounts).Count -eq 0) {
        Write-Log "  [DEBUG] No accounts returned by API for search=$searchQuery" "WARN"
        return $null
    }

    # Debug: display returned accounts
    foreach ($acct in @($accounts)) {
        $dbVal = ""
        if ($acct.platformAccountProperties) {
            $props = ($acct.platformAccountProperties.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ", "
            $dbVal = " | props: $props"
        }
        Write-Log "  [DEBUG] Account: $($acct.name) | user=$($acct.userName) | addr=$($acct.address)$dbVal" "INFO"
    }

    # Precise local filtering: same username (like psPAS Where-Object)
    $matched = @($accounts | Where-Object { $_.userName -like "$User*" })

    if ($matched.Count -gt 1) {
        Write-Log "ANOMALY: $($matched.Count) accounts found for $User@$Database [$Address] - expected exactly 1!" "ERROR"
        foreach ($dup in $matched) {
            Write-Log "  - $($dup.name) (ID: $($dup.id), Safe: $($dup.safeName))" "ERROR"
        }
        throw "Duplicate detected: $($matched.Count) accounts for triplet ($User, $Database, $Address). Fix in CyberArk before retrying."
    }

    if ($matched.Count -eq 0) {
        Write-Log "  [DEBUG] After filtering Database=$Database: no match among $(@($accounts).Count) accounts" "WARN"
        return $null
    }

    return $matched[0]
}

function Test-PRDAccountCompliance {
    param(
        [object]$Account,
        [string]$User,
        [string]$Database,
        [string]$Address
    )

    $accountLabel = "$User@$Database [$Address]"
    $compliant = $true

    # Check 1: Account status
    if ($Account.PSObject.Properties['status'] -and $Account.status) {
        Write-Log "PRD account status: $($Account.status)" "INFO"
    }

    # Check 2: Secret management state (password verification status)
    if ($Account.PSObject.Properties['secretManagement']) {
        $sm = $Account.secretManagement

        # Check if automatic management is enabled
        if ($sm.PSObject.Properties['automaticManagementEnabled'] -and -not $sm.automaticManagementEnabled) {
            Write-Log "PRD compliance FAILED: Automatic password management is DISABLED for $accountLabel" "ERROR"
            $compliant = $false
        }

        # Check last verification status
        if ($sm.PSObject.Properties['status']) {
            $pwdStatus = $sm.status
            Write-Log "PRD password management status: $pwdStatus" "INFO"
            if ($pwdStatus -iin @("PasswordNeverVerified", "Failure", "PasswordChangeInProcess")) {
                Write-Log "PRD compliance FAILED: Password status is '$pwdStatus' for $accountLabel" "ERROR"
                $compliant = $false
            }
        }

        # Check last verified time (warn if older than 90 days)
        if ($sm.PSObject.Properties['lastVerifiedTime'] -and $sm.lastVerifiedTime) {
            $lastVerified = [DateTimeOffset]::FromUnixTimeSeconds($sm.lastVerifiedTime).DateTime
            $daysSinceVerify = (Get-Date) - $lastVerified
            Write-Log "PRD last verified: $($lastVerified.ToString('yyyy-MM-dd HH:mm:ss')) ($([int]$daysSinceVerify.TotalDays) days ago)" "INFO"
            if ($daysSinceVerify.TotalDays -gt 90) {
                Write-Log "PRD compliance WARNING: Last verification was $([int]$daysSinceVerify.TotalDays) days ago for $accountLabel" "WARN"
            }
        }

        # Check last modified time
        if ($sm.PSObject.Properties['lastModifiedTime'] -and $sm.lastModifiedTime) {
            $lastModified = [DateTimeOffset]::FromUnixTimeSeconds($sm.lastModifiedTime).DateTime
            Write-Log "PRD password last modified: $($lastModified.ToString('yyyy-MM-dd HH:mm:ss'))" "INFO"
        }
    }
    else {
        Write-Log "PRD compliance WARNING: No secretManagement data available for $accountLabel - cannot verify password state" "WARN"
    }

    # Check 3: Platform ID
    if ($Account.PSObject.Properties['platformId'] -and $Account.platformId) {
        Write-Log "PRD platform: $($Account.platformId)" "INFO"
    }

    return $compliant
}

function Sync-SingleAccount {
    param(
        [string]$BaseUrl,
        [hashtable]$AuthHeaders,
        [string]$User,
        [string]$DatabasePRD,
        [string]$DatabaseDRP,
        [string]$AddressPRD,
        [string]$AddressDRP,
        [string]$SafeName,
        [bool]$CheckCompliance = $true
    )

    Write-Log "------------------------------------------------------"
    Write-Log "Processing: User=$User | DB_PRD=$DatabasePRD | DB_DRP=$DatabaseDRP | PRD=$AddressPRD | DRP=$AddressDRP"

    # --- Find PRD account ---
    Write-Log "Searching for PRD account ($User@$DatabasePRD on $AddressPRD)..."
    $prdAccount = Find-CyberArkAccount -BaseUrl $BaseUrl -AuthHeaders $AuthHeaders `
        -User $User -Database $DatabasePRD -Address $AddressPRD -SafeName $SafeName

    if (-not $prdAccount) {
        Write-Log "PRD account not found: $User@$DatabasePRD [$AddressPRD]" "ERROR"
        return $false
    }
    Write-Log "PRD account found: $($prdAccount.name) (ID: $($prdAccount.id))" "OK"

    # --- PRD compliance check ---
    if ($CheckCompliance) {
        Write-Log "Validating PRD account compliance..."
        $isCompliant = Test-PRDAccountCompliance -Account $prdAccount `
            -User $User -Database $DatabasePRD -Address $AddressPRD

        if (-not $isCompliant) {
            Write-Log "PRD account is NOT compliant. Skipping sync for $User@$DatabasePRD." "ERROR"
            Write-Log "Set `$SkipPRDComplianceCheck = `$true to bypass this validation (not recommended)." "WARN"
            return $false
        }
        Write-Log "PRD account compliance: OK" "OK"
    }
    else {
        Write-Log "PRD compliance check skipped (SkipPRDComplianceCheck=true)" "WARN"
    }

    # --- Retrieve PRD password ---
    Write-Log "Retrieving PRD password..."
    $retrieveUrl = "$BaseUrl/PasswordVault/api/accounts/$($prdAccount.id)/Password/Retrieve"
    $retrieveBody = @{ reason = "DRP sync - copy PRD password to DRP for $User@$DatabasePRD" }
    $prdPassword = Invoke-PVWARestMethod -Uri $retrieveUrl -Method POST -Headers $AuthHeaders -Body $retrieveBody

    if (-not $prdPassword) {
        Write-Log "Failed to retrieve PRD password." "ERROR"
        return $false
    }
    Write-Log "PRD password retrieved." "OK"

    # --- Find DRP account ---
    Write-Log "Searching for DRP account ($User@$DatabaseDRP on $AddressDRP)..."
    $drpAccount = Find-CyberArkAccount -BaseUrl $BaseUrl -AuthHeaders $AuthHeaders `
        -User $User -Database $DatabaseDRP -Address $AddressDRP -SafeName $SafeName

    if (-not $drpAccount) {
        Write-Log "DRP account not found: $User@$DatabaseDRP [$AddressDRP]" "ERROR"
        return $false
    }
    Write-Log "DRP account found: $($drpAccount.name) (ID: $($drpAccount.id))" "OK"

    # --- Update DRP password in vault only (no CPM interaction) ---
    Write-Log "Updating DRP password in vault only (no CPM)..."
    $changeUrl = "$BaseUrl/PasswordVault/api/accounts/$($drpAccount.id)"
    $changeBody = @{ secret = $prdPassword }
    Invoke-PVWARestMethod -Uri $changeUrl -Method PATCH -Headers $AuthHeaders -Body $changeBody
    Write-Log "DRP password updated in vault (CPM not triggered)." "OK"

    return $true
}

# ============================================================
#  MAIN
# ============================================================

$baseUrl = $PVWAUrl.TrimEnd('/')

# --- CSV check ---
if (-not (Test-Path $CsvFile)) {
    Write-Log "CSV file not found: $CsvFile" "ERROR"
    return
}

# --- Authentication ---
$Credential = Get-Credential -Message "Enter your CyberArk PVWA credentials ($AuthType)"

Write-Log "Connecting to PVWA ($baseUrl) - Auth: $AuthType"

$authBody = @{
    username = $Credential.UserName
    password = $Credential.GetNetworkCredential().Password
}
$token = Invoke-PVWARestMethod -Uri "$baseUrl/PasswordVault/api/auth/$AuthType/Logon" -Method POST -Body $authBody

if (-not $token) {
    Write-Log "PVWA authentication failed." "ERROR"
    return
}

$token = $token.Trim('"').Trim().Replace("`r","").Replace("`n","")
$authHeaders = @{ Authorization = $token }
Write-Log "Authentication successful." "OK"

# --- Load CSV ---
$accounts = @(Import-Csv -Path $CsvFile -Delimiter ",")
Write-Log "CSV loaded: $($accounts.Count) accounts to process from $CsvFile"

# --- Processing ---
$totalSuccess = 0
$totalFail    = 0

foreach ($entry in $accounts) {
    try {
        $result = Sync-SingleAccount -BaseUrl $baseUrl -AuthHeaders $authHeaders `
            -User $entry.User -DatabasePRD $entry.DatabasePRD -DatabaseDRP $entry.DatabaseDRP `
            -AddressPRD $entry.AdressePRD -AddressDRP $entry.AdresseDRP `
            -SafeName $Safe -CheckCompliance (-not $SkipPRDComplianceCheck)

        if ($result) { $totalSuccess++ } else { $totalFail++ }
    }
    catch {
        Write-Log "Error processing $($entry.User)@$($entry.DatabasePRD)->$($entry.DatabaseDRP): $_" "ERROR"
        $totalFail++
    }
}

# --- Logoff ---
Write-Log "Disconnecting from PVWA..."
try {
    Invoke-PVWARestMethod -Uri "$baseUrl/PasswordVault/api/auth/Logoff" -Method POST -Headers $authHeaders
    Write-Log "Disconnected successfully." "OK"
}
catch {
    Write-Log "Logoff error (non-critical): $_" "WARN"
}

# --- Summary ---
Write-Log "======================================================" "OK"
Write-Log "=== FINAL SUMMARY === (v2.0)" "OK"
Write-Log "Total processed : $($totalSuccess + $totalFail)" "OK"
Write-Log "Succeeded       : $totalSuccess" "OK"
Write-Log "Failed          : $totalFail" $(if ($totalFail -gt 0) { "WARN" } else { "OK" })
Write-Log "Log file        : $LogFile" "OK"
Write-Log "======================================================" "OK"
