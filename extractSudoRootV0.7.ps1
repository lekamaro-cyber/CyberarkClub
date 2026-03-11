# --- FILE PATH CONFIGURATION ---
$Files = @{
    PrivHost     = "$PSScriptRoot\Input\all_priv_host"
    RootMembers  = "$PSScriptRoot\Input\all_root_members"
    Passwd       = "$PSScriptRoot\Input\all_pass"
    PrivMembers  = "$PSScriptRoot\Input\all_priv_members"
    Inventory    = "$PSScriptRoot\request.csv"
}

$OutCsv = "$PSScriptRoot\output\Audit_Privileges_Unix_$(Get-Date -Format 'yyyy-MM').csv"

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
    Import-Csv $Files.Inventory -Delimiter "," | ForEach-Object {
        if ($_.NAME_SERVER) { $statusMap[$_.NAME_SERVER.ToLower().Trim()] = $_.NAME_STATUS }
    }
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
Write-Host "##############"
Write-Host "ALL_PRIV_HOST"
Write-Host "##############"
if (Test-Path $Files.PrivHost) {
    Get-Content $Files.PrivHost | ForEach-Object {
        $line = $_.Trim()
        if ($line -match 'ALL=') {
            $isNoPass = if ($line -match "NOPASSWD") { "YES" } else { "NO" }
            # Extract the block before ALL=
            $idBlock = ($line -split 'ALL=')[0].Trim()
            # Find the last hyphen to separate Server and User
            if ($idBlock -match '(.+)-([^\-]+)$') {
                Write-Host "ALL_PRIV_HOST:  $($matches[2])"
                Add-AuditEntry -user $matches[2] -server $matches[1] -source "Sudoers" -noPass $isNoPass
            }
        }
    }
}

# --- 3. PROCESS ALL_PRIV_MEMBERS (Wheel/Sudo Groups) ---
Write-Host "################"
Write-Host "ALL_PRIV_MEMBERS"
Write-Host "################"
if (Test-Path $Files.PrivMembers) {
    Get-Content $Files.PrivMembers | ForEach-Object {
        # Format: SERVER-group:x:ID:members
        if ($_ -match '^([^\:]+)-([^\:]+):([^\:]+):([^\:]+):(.*)') {
            $srv = $matches[1]; $grp = $matches[2]
            $matches[5] -split ',' | ForEach-Object {
                if ($_.Trim()) {
                    Write-Host "ALL_PRIV_MEMBERS: Found  $($_.Trim())"
                    Add-AuditEntry -user $_.Trim() -server $srv -source "Group:$grp"
                }
            }
        }
    }
}

# --- 4. PROCESS ALL_PASS (Shadow/Passwd) ---
# Build a password status index first, then update existing entries and add new ones
Write-Host "########"
Write-Host "ALL_PASS"
Write-Host "########"
$passwdMap = @{}
if (Test-Path $Files.Passwd) {
    Get-Content $Files.Passwd | ForEach-Object {
        $line = $_.Trim()
        # Format: USERNAME XX DATE ... (Password set/locked), SERVERNAME
        if ($line -match '^(\S+)\s+.+,\s*(\S+)\s*$') {
            $pUser = $matches[1].Trim()
            $pServer = $matches[2].Trim()
            $isLocked = if ($line -match "Password locked") { "Locked" } else { "Active" }
            $pKey = ("$pUser|$pServer").ToLower().Trim()
            $passwdMap[$pKey] = $isLocked
        }
    }

    # Update AccountStatus for all accounts already in $results
    foreach ($entry in $results.GetEnumerator()) {
        if ($passwdMap.ContainsKey($entry.Key)) {
            $entry.Value.AccountStatus = $passwdMap[$entry.Key]
        }
    }

    # Also add shadow-only active accounts
    foreach ($pEntry in $passwdMap.GetEnumerator()) {
        if (-not $results.ContainsKey($pEntry.Key)) {
            if ($pEntry.Value -eq "Active") {
                $parts = $pEntry.Key -split '\|'
                Write-Host "ALL_PASS: Found  $($parts[0])"
                Add-AuditEntry -user $parts[0] -server $parts[1] -source "Shadow"
                $results[$pEntry.Key].AccountStatus = $pEntry.Value
            }
        }
    }
}

# --- 4b. PASSWORD STATUS REPORT FOR PRIVILEGED GROUP MEMBERS ---
Write-Host ""
Write-Host "###################################"
Write-Host "PASSWORD STATUS FOR GROUP MEMBERS"
Write-Host "###################################"
$groupMembers = $results.Values | Where-Object { $_.Source -match "Group:" }
$activeGroupCount = 0
$lockedGroupCount = 0
$unknownGroupCount = 0
foreach ($member in $groupMembers) {
    $mKey = ("$($member.UserSam)|$($member.Server)").ToLower().Trim()
    if ($passwdMap.ContainsKey($mKey)) {
        $member.AccountStatus = $passwdMap[$mKey]
        if ($passwdMap[$mKey] -eq "Active") {
            $activeGroupCount++
            Write-Host "  [ACTIVE]  $($member.UserSam) on $($member.Server) (Source: $($member.Source))" -ForegroundColor Green
        } else {
            $lockedGroupCount++
            Write-Host "  [LOCKED]  $($member.UserSam) on $($member.Server) (Source: $($member.Source))" -ForegroundColor DarkGray
        }
    } else {
        $unknownGroupCount++
        $member.AccountStatus = "Unknown"
        Write-Host "  [UNKNOWN] $($member.UserSam) on $($member.Server) (Source: $($member.Source)) - not found in passwd file" -ForegroundColor Yellow
    }
}
Write-Host "`nGroup members summary: $activeGroupCount Active, $lockedGroupCount Locked, $unknownGroupCount Unknown" -ForegroundColor Cyan

# --- 5. PROCESS ALL_ROOT_MEMBERS (UID 0) ---
Write-Host "########"
Write-Host "ALL_ROOT"
Write-Host "########"
if (Test-Path $Files.RootMembers) {
    Get-Content $Files.RootMembers | ForEach-Object {
        if ($_ -match '^([^\:]+):([^\:]+):0:.*:([^\:]+)$') {
            Write-Host "ALL_ROOT: Found  $($matches[1])"
            Add-AuditEntry -user $matches[1] -server $matches[3] -source "Root_Equivalent"
        }
    }
}

# --- FINAL EXPORT ---
$finalData = $results.Values | Sort-Object UserSam, Server
$finalData | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Host "Audit complete. NOPASSWD column added. Output file: $OutCsv" -ForegroundColor Cyan
