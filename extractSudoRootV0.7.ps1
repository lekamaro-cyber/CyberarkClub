# --- CONFIGURATION DES CHEMINS ---
$Files = @{
    PrivHost     = "D:\Cyberark\Majide\PAM Script\KPI\UnixAcctsCyberark\all_priv_host.txt"
    RootMembers  = "D:\Cyberark\Majide\PAM Script\KPI\UnixAcctsCyberark\all_root_members.txt"
    Passwd       = "D:\Cyberark\Majide\PAM Script\KPI\UnixAcctsCyberark\all_pass.txt"
    PrivMembers  = "D:\Cyberark\Majide\PAM Script\KPI\UnixAcctsCyberark\all_priv_members.txt"
    Inventory    = "D:\Cyberark\Majide\PAM Script\KPI\request.csv"
}

$OutCsv = ".\Audit_Privileges_Unix.csv"

# --- 0. VERIFICATION DE LA FRAICHEUR DES FICHIERS INPUT ---
$maxAgeDays = 30  # Seuil d'alerte en jours
$now = Get-Date
$oldFiles = @()

foreach ($entry in $Files.GetEnumerator()) {
    if (Test-Path $entry.Value) {
        $fileInfo = Get-Item $entry.Value
        $ageDays = ($now - $fileInfo.LastWriteTime).Days
        if ($ageDays -gt $maxAgeDays) {
            $oldFiles += [PSCustomObject]@{
                Nom           = $entry.Key
                Fichier       = Split-Path $entry.Value -Leaf
                DerniereModif = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                AgeDays       = $ageDays
            }
        }
    } else {
        Write-Host "[ATTENTION] Fichier introuvable : $($entry.Key) -> $($entry.Value)" -ForegroundColor Red
    }
}

if ($oldFiles.Count -gt 0) {
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "  ATTENTION : FICHIERS POTENTIELLEMENT OBSOLETES" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "Les fichiers suivants ont ete modifies il y a plus de $maxAgeDays jours :`n" -ForegroundColor Yellow

    foreach ($f in $oldFiles) {
        Write-Host "  - $($f.Nom) ($($f.Fichier)) : modifie le $($f.DerniereModif) (il y a $($f.AgeDays) jours)" -ForegroundColor Yellow
    }

    Write-Host "`nIl est possible que ces fichiers ne soient plus a jour." -ForegroundColor Yellow
    Write-Host "Voulez-vous continuer l'audit malgre tout ? (O/N) " -ForegroundColor Cyan -NoNewline
    $response = Read-Host
    if ($response -notin @("O", "o", "Y", "y", "Oui", "oui", "Yes", "yes")) {
        Write-Host "Audit annule par l'utilisateur." -ForegroundColor Red
        exit
    }
    Write-Host ""
}

Write-Host "Tous les fichiers sont valides. Lancement de l'audit...`n" -ForegroundColor Green

# --- INITIALISATION ---
$results = @{}
$statusMap = @{}

# --- 1. CHARGEMENT DE L'INVENTAIRE (request.csv) ---
if (Test-Path $Files.Inventory) {
    Import-Csv $Files.Inventory -Delimiter "," | ForEach-Object {
        if ($_.NAME_SERVER) { $statusMap[$_.NAME_SERVER.ToLower().Trim()] = $_.NAME_STATUS }
    }
}

# --- FONCTION COEUR : AJOUT ET FUSION DES DONNEES ---
function Add-AuditEntry($user, $server, $source, $noPass = "NO") {
    if (!$user -or !$server) { return }

    $key = ("$user|$server").ToLower().Trim()
    $srvKey = $server.ToLower().Trim()
    $invStatus = if ($statusMap.ContainsKey($srvKey)) { $statusMap[$srvKey] } else { "Inconnu" }

    if ($results.ContainsKey($key)) {
        # Fusion des sources (eviter les doublons de source)
        if ($results[$key].Source -notmatch [regex]::Escape($source)) {
            $results[$key].Source += ";$source"
        }
        # Si une ligne indique NOPASSWD, on l'active pour ce compte
        if ($noPass -eq "YES") { $results[$key].NoPasswd = "YES" }
    } else {
        $results[$key] = [PSCustomObject]@{
            UserSam         = $user.Trim() # PRESERVE LA CASSE
            Server          = $server.Trim()
            InventoryStatus = $invStatus
            Source          = $source
            NoPasswd        = $noPass
            AccountStatus   = "Active" # Par defaut
            FoundInCyberArk = ""
            CA_Compliant    = ""
        }
    }
}

# --- 2. MOULINETTE ALL_PRIV_HOST (Sudoers) ---
Write-Host "##############"
Write-Host "ALL_PRIV_HOST"
Write-Host "##############"
if (Test-Path $Files.PrivHost) {
    Get-Content $Files.PrivHost | ForEach-Object {
        $line = $_.Trim()
        if ($line -match 'ALL=') {
            $isNoPass = if ($line -match "NOPASSWD") { "YES" } else { "NO" }
            # Extraction du bloc avant ALL=
            $idBlock = ($line -split 'ALL=')[0].Trim()
            # On cherche le dernier tiret pour separer Serveur et User
            if ($idBlock -match '(.+)-([^\-]+)$') {
                Write-Host "ALL_PRIV_HOST:  $($matches[2])"
                Add-AuditEntry -user $matches[2] -server $matches[1] -source "Sudoers" -noPass $isNoPass
            }
        }
    }
}

# --- 3. MOULINETTE ALL_PRIV_MEMBERS (Wheel/Sudo Groups) ---
Write-Host "################"
Write-Host "ALL_PRIV_MEMBERS"
Write-Host "################"
if (Test-Path $Files.PrivMembers) {
    Get-Content $Files.PrivMembers | ForEach-Object {
        # Format: SERVEUR-groupe:x:ID:membres
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

# --- 4. MOULINETTE ALL_PASS (Shadow/Passwd) ---
Write-Host "########"
Write-Host "ALL_PASS"
Write-Host "########"
if (Test-Path $Files.Passwd) {
    Get-Content $Files.Passwd | ForEach-Object {
        $line = $_.Trim()
        $parts = $line -split '\s+\.\s+'
        if ($parts.Count -ge 5) {
            $user = $parts[0].Trim()
            $server = $parts[4].Trim()
            $isLocked = if ($line -match "Password locked") { "Locked" } else { "Active" }

            # Si le compte existe deja, on met a jour son statut, sinon on l'ajoute comme "Shadow"
            $key = ("$user|$server").ToLower().Trim()
            if ($results.ContainsKey($key)) {
                $results[$key].AccountStatus = $isLocked
            } else {
                # On ne rajoute ici que si vous voulez TOUS les comptes, meme non privilegies
                # Sinon, on ignore pour ne garder que l'audit du privilege
                if ($isLocked -eq "Actif") {
                    Write-Host "ALL_PASS: Found  $user"
                    Add-AuditEntry -user $user -server $server -source "Shadow"
                }
            }
        }
    }
}

# --- 5. MOULINETTE ALL_ROOT_MEMBERS (UID 0) ---
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

# --- EXPORT FINAL ---
$finalData = $results.Values | Sort-Object UserSam, Server
$finalData | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Host "Audit termine. Colonne NOPASSWD ajoutee. Fichier : $OutCsv" -ForegroundColor Cyan
