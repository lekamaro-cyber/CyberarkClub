# --- TLS CONFIGURATION ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- FILE PATH CONFIGURATION ---
$Files = @{
    PrivHost        = "$PSScriptRoot\Input\all_priv_host"
    RootMembers     = "$PSScriptRoot\Input\all_root_members"
    Passwd          = "$PSScriptRoot\Input\all_pass"
    PrivMembers     = "$PSScriptRoot\Input\all_priv_members"
    Inventory       = "$PSScriptRoot\Input\request.csv"
    CyberArkAccounts   = "$PSScriptRoot\Input\cyberark_accounts.csv"
    CyberArkCompliance = "$PSScriptRoot\Input\cyberark_compliance.csv"
}

$OutCsv = "$PSScriptRoot\output\Audit_Privileges_Unix_$(Get-Date -Format 'yyyy-MM').csv"

# --- PVWA CONFIGURATION ---
$PVWAUrl   = "https://pvwa.yourcompany.com"   # <-- ADAPTER: URL du PVWA
$AuthMethod = "CyberArk"                       # CyberArk, LDAP, or RADIUS

# --- PVWA FUNCTIONS ---
function Connect-PVWA {
    param([string]$BaseUrl, [string]$AuthType)

    Write-Host "`n==============================" -ForegroundColor Cyan
    Write-Host "  CONNEXION AU PVWA" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan

    $cred = Get-Credential -Message "Entrez vos identifiants PVWA ($AuthType)"
    if (-not $cred) {
        Write-Host "[ERROR] Aucun identifiant fourni. Abandon." -ForegroundColor Red
        return $null
    }

    $body = @{
        username = $cred.UserName
        password = $cred.GetNetworkCredential().Password
    } | ConvertTo-Json

    $logonUrl = "$BaseUrl/PasswordVault/api/auth/$AuthType/Logon"
    try {
        $token = Invoke-RestMethod -Uri $logonUrl -Method POST -Body $body -ContentType "application/json"
        Write-Host "  Connexion reussie." -ForegroundColor Green
        return $token
    } catch {
        Write-Host "[ERROR] Echec de connexion au PVWA: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Disconnect-PVWA {
    param([string]$BaseUrl, [string]$Token)
    try {
        Invoke-RestMethod -Uri "$BaseUrl/PasswordVault/api/auth/Logoff" -Method POST `
            -Headers @{ Authorization = $Token } -ContentType "application/json" | Out-Null
        Write-Host "  Deconnexion PVWA OK." -ForegroundColor Green
    } catch {
        Write-Host "  [WARNING] Echec deconnexion PVWA: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Get-PVWAAccounts {
    param([string]$BaseUrl, [string]$Token)

    Write-Host "  Recuperation des comptes depuis le PVWA..." -ForegroundColor Cyan
    $headers = @{ Authorization = $Token }
    $allAccounts = @()
    $offset = 0
    $limit = 1000

    do {
        $uri = "$BaseUrl/PasswordVault/api/Accounts?limit=$limit&offset=$offset"
        try {
            $response = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers -ContentType "application/json"
            $allAccounts += $response.value
            $offset += $limit
            Write-Host "    ... $($allAccounts.Count) comptes charges" -ForegroundColor Gray
        } catch {
            Write-Host "  [ERROR] Erreur API Accounts: $($_.Exception.Message)" -ForegroundColor Red
            break
        }
    } while ($response.value.Count -eq $limit)

    Write-Host "  Total: $($allAccounts.Count) comptes Unix recuperes." -ForegroundColor Cyan
    return $allAccounts
}

function Export-PVWAAccountsToCsv {
    param($Accounts, [string]$OutputPath)

    $csvData = $Accounts | ForEach-Object {
        [PSCustomObject]@{
            "Coffre-fort"                = $_.safeName
            "ID de la plateforme"        = $_.platformId
            "Adresse"                    = $_.address
            "Nom de l'utilisateur"       = $_.userName
            "Derniere modification par"  = $_.secretManagement.lastModifiedTime
            "CPMManaged"                 = $_.secretManagement.automaticManagementEnabled
            "CPMStatus"                  = $_.secretManagement.status
        }
    }
    $csvData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Delimiter ","
    Write-Host "  Export sauvegarde: $OutputPath" -ForegroundColor Green
}

# --- 0. INPUT FILE FRESHNESS CHECK ---
$now = Get-Date
$currentMonth = $now.Month
$currentYear = $now.Year
$oldFiles = @()

foreach ($entry in $Files.GetEnumerator()) {
    if (Test-Path $entry.Value) {
        $fileInfo = Get-Item $entry.Value
        $fileMonth = $fileInfo.LastWriteTime.Month
        $fileYear = $fileInfo.LastWriteTime.Year
        if ($fileMonth -ne $currentMonth -or $fileYear -ne $currentYear) {
            $oldFiles += [PSCustomObject]@{
                Name         = $entry.Key
                FileName     = Split-Path $entry.Value -Leaf
                LastModified = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                FileMonth    = $fileInfo.LastWriteTime.ToString("MMMM yyyy")
            }
        }
    } else {
        Write-Host "[WARNING] File not found: $($entry.Key) -> $($entry.Value)" -ForegroundColor Red
    }
}

if ($oldFiles.Count -gt 0) {
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "  WARNING: FILES NOT FROM CURRENT MONTH" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "Current month: $($now.ToString('MMMM yyyy'))" -ForegroundColor Yellow
    Write-Host "The following files were NOT modified this month:`n" -ForegroundColor Yellow

    foreach ($f in $oldFiles) {
        Write-Host "  - $($f.Name) ($($f.FileName)): last modified $($f.LastModified) ($($f.FileMonth))" -ForegroundColor Yellow
    }

    Write-Host "`nThese files may be outdated." -ForegroundColor Yellow
    Write-Host "Do you want to continue the audit anyway? (Y/N) " -ForegroundColor Cyan -NoNewline
    $response = Read-Host
    if ($response -notin @("Y", "y", "Yes", "yes")) {
        Write-Host "Audit cancelled by user." -ForegroundColor Red
        exit
    }
    Write-Host ""
}

Write-Host "All input files are valid. Starting audit...`n" -ForegroundColor Green

# --- INITIALIZATION ---
$results = @{}
$statusMap = @{}

# --- 1. LOAD INVENTORY (request.csv) ---
if (Test-Path $Files.Inventory) {
    # Auto-detect delimiter (French CSV often uses ";")
    $firstLine = Get-Content $Files.Inventory -TotalCount 1
    $csvDelimiter = if ($firstLine -match ";") { ";" } else { "," }
    Write-Host "  Chargement inventaire (delimiter='$csvDelimiter')..." -ForegroundColor Cyan

    Import-Csv $Files.Inventory -Delimiter $csvDelimiter | ForEach-Object {
        if ($_.NAME_SERVER) { $statusMap[$_.NAME_SERVER.ToLower().Trim()] = $_.NAME_STATUS }
    }
    Write-Host "  $($statusMap.Count) serveurs charges depuis request.csv" -ForegroundColor Cyan
}

# --- CORE FUNCTION: ADD AND MERGE AUDIT DATA ---
function Add-AuditEntry($user, $server, $source, $noPass = "NO") {
    if (!$user -or !$server) { return }

    $key = ("$user|$server").ToLower().Trim()
    $srvKey = $server.ToLower().Trim()
    $invStatus = if ($statusMap.ContainsKey($srvKey)) { $statusMap[$srvKey] } else { "Unknown" }

    if ($results.ContainsKey($key)) {
        # Merge sources (avoid duplicate sources)
        if ($results[$key].Source -notmatch [regex]::Escape($source)) {
            $results[$key].Source += ";$source"
        }
        # If a line indicates NOPASSWD, enable it for this account
        if ($noPass -eq "YES") { $results[$key].NoPasswd = "YES" }
    } else {
        $results[$key] = [PSCustomObject]@{
            UserSam         = $user.Trim() # PRESERVE CASE
            Server          = $server.Trim()
            InventoryStatus = $invStatus
            Source          = $source
            NoPasswd        = $noPass
            AccountStatus   = "Active" # Default
            FoundInCyberArk = ""
            CA_Compliant    = ""
        }
    }
}

# --- 2. PROCESS ALL_PRIV_HOST (Sudoers) ---
Write-Host "###############"
Write-Host "ALL_PRIV_HOST"
Write-Host "###############"
if (Test-Path $Files.PrivHost) {
    Get-Content $Files.PrivHost | ForEach-Object {
        $line = $_.Trim()
        if ($line -match "ALL=") {
            $isNoPass = if ($line -match "NOPASSWD") { "YES" } else { "NO" }
            $idBlock = ($line -split "ALL=")[0].Trim()
            if ($idBlock -match '(.+)-([^-]+)$') {
                Write-Host "ALL_PRIV_HOST: $($matches[2])"
                Add-AuditEntry `
                    -user $matches[2] `
                    -server $matches[1] `
                    -source "Sudoers" `
                    -noPass $isNoPass
            }
        }
    }
    Write-Host "  $($results.Count) comptes apres Sudoers" -ForegroundColor Cyan
}

# --- 3. PROCESS ALL_PRIV_MEMBERS (Wheel/Sudo Groups) ---
Write-Host "`n###############"
Write-Host "ALL_PRIV_MEMBERS"
Write-Host "###############"
if (Test-Path $Files.PrivMembers) {
    Get-Content $Files.PrivMembers | ForEach-Object {
        if ($_ -match '^([^:]+)-([^:]+):[^:]*:(.*)$') {
            $srv = $matches[1]
            $grp = $matches[2]
            $matches[3].Split(",") | ForEach-Object {
                if ($_.Trim()) {
                    Write-Host "ALL_PRIV_MEMBERS: Found $($_.Trim())"
                    Add-AuditEntry `
                        -user $_.Trim() `
                        -server $srv `
                        -source "Group:$grp"
                }
            }
        }
    }
    Write-Host "  $($results.Count) comptes apres Groups" -ForegroundColor Cyan
}

# --- 4. PROCESS ALL_PASS (Shadow/Passwd — enrich status only) ---
Write-Host "`n###############"
Write-Host "ALL_PASS"
Write-Host "###############"
if (Test-Path $Files.Passwd) {
    Get-Content $Files.Passwd | ForEach-Object {
        $line = $_.Trim()
        $parts = $line -split "\s+\|\s+"
        if ($parts.Count -ge 5) {
            $user = $parts[0].Trim()
            $server = $parts[4].Trim()
            $isLocked = if ($line -match "Password locked") { "Locked" } else { "Active" }
            $key = ("$user|$server").ToLower().Trim()
            if ($results.ContainsKey($key)) {
                # Account already known from privilege sources — update status
                $results[$key].AccountStatus = $isLocked
            } else {
                # Account not in privilege sources — add only if Active
                if ($isLocked -eq "Active") {
                    Write-Host "ALL_PASS: Found $user"
                    Add-AuditEntry `
                        -user $user `
                        -server $server `
                        -source "Shadow"
                }
            }
        }
    }
    Write-Host "  $($results.Count) comptes apres all_pass" -ForegroundColor Cyan
}

# --- 5. PROCESS ALL_ROOT_MEMBERS (UID 0) ---
Write-Host "`n###############"
Write-Host "ALL_ROOT"
Write-Host "###############"
if (Test-Path $Files.RootMembers) {
    Get-Content $Files.RootMembers | ForEach-Object {
        if ($_ -match '^([^:]+)-([^:]+).*\(([^)]+)\)$') {
            Write-Host "ALL_ROOT: Found $($matches[1])"
            Add-AuditEntry `
                -user $matches[1] `
                -server $matches[2] `
                -source "Root_Equivalent"
        }
    }
    Write-Host "  $($results.Count) comptes apres Root" -ForegroundColor Cyan
}

# --- 5b. SUMMARY ---
Write-Host "`n###################################"
Write-Host "SUMMARY"
Write-Host "###################################"
Write-Host "  Total comptes privilegies: $($results.Count)" -ForegroundColor Cyan

# --- 6. CYBERARK CROSS-REFERENCE (via PVWA API) ---
Write-Host ""
Write-Host "######################"
Write-Host "CYBERARK CROSS-CHECK"
Write-Host "######################"

# 6a. Connect to PVWA and download accounts
$pvwaToken = Connect-PVWA -BaseUrl $PVWAUrl -AuthType $AuthMethod

$cyberArkIndex = @{}
$cyberArkCompliance = @{}

if ($pvwaToken) {
    # Fetch all Unix accounts from PVWA
    $pvwaAccounts = Get-PVWAAccounts -BaseUrl $PVWAUrl -Token $pvwaToken

    if ($pvwaAccounts.Count -gt 0) {
        # Save a local copy for traceability
        Export-PVWAAccountsToCsv -Accounts $pvwaAccounts -OutputPath $Files.CyberArkAccounts

        # 6b. Build indexes from API data
        foreach ($acct in $pvwaAccounts) {
            $caUser   = $acct.userName
            $caServer = $acct.address
            if ($caUser -and $caServer) {
                $caKey = ("$caUser|$caServer").ToLower().Trim()

                # Accounts index (FoundInCyberArk)
                $cyberArkIndex[$caKey] = $true

                # Compliance index (CA_Compliant based on CPM)
                # Compliant = CPM enabled AND last operation successful
                $cpmEnabled = $acct.secretManagement.automaticManagementEnabled
                $cpmStatus  = $acct.secretManagement.status
                if ($cpmEnabled -eq $true -and $cpmStatus -match "^success$") {
                    $cyberArkCompliance[$caKey] = "Compliant"
                } else {
                    $cyberArkCompliance[$caKey] = "Non-Compliant"
                }
            }
        }
        Write-Host "  Index construit: $($cyberArkIndex.Count) comptes, $($cyberArkCompliance.Count) entrees compliance." -ForegroundColor Cyan
    }

    # Disconnect from PVWA
    Disconnect-PVWA -BaseUrl $PVWAUrl -Token $pvwaToken

} else {
    # Fallback: try to use local CSV files if PVWA connection failed
    Write-Host "  Connexion PVWA echouee. Tentative de lecture des CSV locaux..." -ForegroundColor Yellow

    if (Test-Path $Files.CyberArkAccounts) {
        # Inventory report columns (French): "Nom de l'utilisateur", "Adresse"
        # "Derniere modification par" = "PasswordManager" means CPM-managed
        Import-Csv $Files.CyberArkAccounts -Delimiter "," | ForEach-Object {
            $caUser   = $_."Nom de l'utilisateur"
            $caServer = $_."Adresse"
            if (-not $caUser) { $caUser = $_.UserName }
            if (-not $caServer) { $caServer = $_.Address }
            if ($caUser -and $caServer) {
                $caKey = ("$($caUser.Trim())|$($caServer.Trim())").ToLower()
                $cyberArkIndex[$caKey] = $true
            }
        }
        Write-Host "  Charge $($cyberArkIndex.Count) comptes depuis le CSV local (inventaire)." -ForegroundColor Cyan
    } else {
        Write-Host "  [WARNING] Fichier inventaire introuvable: $($Files.CyberArkAccounts)" -ForegroundColor Red
    }

    if (Test-Path $Files.CyberArkCompliance) {
        # Compliance report columns (French):
        #   "Nom de l'utilisateur du systeme cible", "Adresse du systeme",
        #   "Statut de la conformite"
        Import-Csv $Files.CyberArkCompliance -Delimiter "," | ForEach-Object {
            $ccUser   = $_."Nom de l'utilisateur du systeme cible"
            $ccServer = $_."Adresse du systeme"
            $ccStatus = $_."Statut de la conformite"
            if (-not $ccUser) { $ccUser = $_."Nom de l'utilisateur du système cible" }
            if (-not $ccServer) { $ccServer = $_."Adresse du système" }
            if ($ccUser -and $ccServer) {
                $ccKey = ("$($ccUser.Trim())|$($ccServer.Trim())").ToLower()
                if ($ccStatus -match "conforme" -and $ccStatus -notmatch "Non") {
                    $cyberArkCompliance[$ccKey] = "Compliant"
                } else {
                    $cyberArkCompliance[$ccKey] = "Non-Compliant"
                }
            }
        }
        Write-Host "  Charge $($cyberArkCompliance.Count) entrees depuis le CSV local (compliance)." -ForegroundColor Cyan
    } else {
        Write-Host "  [WARNING] Fichier compliance introuvable: $($Files.CyberArkCompliance)" -ForegroundColor Red
    }
}

# 6c. Update results with CyberArk data
$caFoundCount = 0
$caCompliantCount = 0
$caNotFoundCount = 0
foreach ($entry in $results.GetEnumerator()) {
    $lookupKey = $entry.Key

    # FoundInCyberArk
    if ($cyberArkIndex.ContainsKey($lookupKey)) {
        $entry.Value.FoundInCyberArk = "YES"
        $caFoundCount++
    } elseif ($cyberArkIndex.Count -gt 0) {
        $entry.Value.FoundInCyberArk = "NO"
        $caNotFoundCount++
    }

    # CA_Compliant (based on CPM management)
    if ($cyberArkCompliance.ContainsKey($lookupKey)) {
        if ($cyberArkCompliance[$lookupKey] -eq "Compliant") {
            $entry.Value.CA_Compliant = "YES"
            $caCompliantCount++
        } else {
            $entry.Value.CA_Compliant = "NO"
        }
    } elseif ($entry.Value.FoundInCyberArk -eq "YES") {
        # In CyberArk but not in compliance report = non-compliant
        $entry.Value.CA_Compliant = "NO"
    } elseif ($cyberArkIndex.Count -gt 0) {
        # Not in CyberArk at all = not compliant
        $entry.Value.CA_Compliant = "NO"
    }
}

Write-Host ""
Write-Host "Resume CyberArk:" -ForegroundColor Cyan
Write-Host "  Trouve dans CyberArk: $caFoundCount | Absent: $caNotFoundCount" -ForegroundColor Cyan
Write-Host "  CPM Compliant: $caCompliantCount | Non-compliant: $($results.Count - $caCompliantCount)" -ForegroundColor Cyan

# --- FINAL EXPORT ---
$finalData = $results.Values | Sort-Object UserSam, Server
$finalData | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Host "`nAudit termine. Fichier de sortie: $OutCsv" -ForegroundColor Cyan
