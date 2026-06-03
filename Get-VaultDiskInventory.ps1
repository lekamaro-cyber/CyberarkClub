<#
.SYNOPSIS
    Inventaire des disques/partitions/volumes d'un noeud Vault CyberArk +
    lecture du registre WSFC (HKLM:\Cluster) si present. Sans dependance :
    pas de module FailoverClusters, pas de module Storage requis.

.DESCRIPTION
    Concu pour les Vault durcis ou le module FailoverClusters n'est pas
    installe (et ou Get-Disk n'est parfois pas disponible non plus). Tout
    se fait via CIM/WMI standards (Win32_DiskDrive, Win32_DiskPartition,
    Win32_LogicalDisk, Win32_LogicalDiskToPartition, Win32_Volume) plus
    une lecture directe de HKLM:\Cluster si la hive existe.

    A executer LOCALEMENT sur chaque noeud (PSRemoting suppose coupe par
    le hardening Vault). Lecture seule, aucune modification.

    Si tu utilises CyberArk Cluster Vault Manager (CVM, le cluster
    proprietaire CyberArk), il n'y a pas de hive HKLM:\Cluster : le script
    le signale et liste alors les fichiers de configuration CyberArk
    plausibles (sous Server\Conf) qui referencent la grappe/quorum, pour
    que tu identifies le volume du quorum dedans.

.PARAMETER ReportPath
    Chemin de sortie JSON (optionnel).
#>

[CmdletBinding()]
param(
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'
function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function SigHex($v) {
    if ($null -eq $v -or "$v" -eq '') { return '' }
    try { return ('0x{0:X8}' -f [uint32]$v) } catch { return "$v" }
}

#region Disques / partitions / volumes via CIM (toujours disponible)

Section "Disques physiques (Win32_DiskDrive)"
$drives = Get-CimInstance Win32_DiskDrive | Sort-Object Index
$drives | Format-Table -AutoSize Index, Model, InterfaceType, MediaType,
    @{n = 'SignatureHex'; e = { SigHex $_.Signature } },
    @{n = 'SizeGB';       e = { [math]::Round($_.Size / 1GB, 2) } },
    Partitions, SerialNumber, Status | Out-Host

Section "Partitions (Win32_DiskPartition)"
$parts = Get-CimInstance Win32_DiskPartition | Sort-Object DiskIndex, Index
$parts | Format-Table -AutoSize DiskIndex, Index, Name, Type,
    BootPartition, PrimaryPartition,
    @{n = 'SizeGB';   e = { [math]::Round($_.Size / 1GB, 2) } },
    @{n = 'OffsetMB'; e = { [math]::Round($_.StartingOffset / 1MB, 2) } } | Out-Host

Section "Volumes et lettres (Win32_Volume)"
$volumes = Get-CimInstance Win32_Volume |
    Sort-Object DriveLetter, Name
$volumes | Format-Table -AutoSize DriveLetter, Label, FileSystem,
    @{n = 'CapacityGB'; e = { [math]::Round($_.Capacity / 1GB, 2) } },
    @{n = 'FreeGB';     e = { [math]::Round($_.FreeSpace / 1GB, 2) } },
    Name | Out-Host

Section "Mapping Disque -> Partition -> Lettre (Win32_LogicalDiskToPartition)"
$mapping = foreach ($a in (Get-CimInstance Win32_LogicalDiskToPartition)) {
    # Antecedent = partition, Dependent = lettre logique
    $partName = ($a.Antecedent.DeviceID)  # ex: "Disk #1, Partition #0"
    $driveLtr = ($a.Dependent.DeviceID)   # ex: "G:"
    [pscustomobject]@{ Partition = $partName; DriveLetter = $driveLtr }
}
$mapping | Format-Table -AutoSize | Out-Host

#endregion

#region WSFC sans module : lecture directe du registre

Section "Cluster Microsoft (registre HKLM:\Cluster)"
if (Test-Path 'HKLM:\Cluster') {
    $q = Get-ItemProperty 'HKLM:\Cluster\Quorum' -ErrorAction SilentlyContinue
    Write-Host "Quorum :" -ForegroundColor Yellow
    if ($q) {
        [pscustomobject]@{
            QuorumType     = $q.QuorumType
            QuorumResource = $q.Resource
            QuorumPath     = $q.Path
        } | Format-List | Out-Host
    }
    else { Write-Host "(clef HKLM:\Cluster\Quorum absente)" }

    if (Test-Path 'HKLM:\Cluster\Resources') {
        $resources = foreach ($r in Get-ChildItem 'HKLM:\Cluster\Resources') {
            $head = Get-ItemProperty $r.PSPath -ErrorAction SilentlyContinue
            $params = Get-ItemProperty (Join-Path $r.PSPath 'Parameters') -ErrorAction SilentlyContinue
            [pscustomobject]@{
                ResourceId       = $r.PSChildName
                Name             = $head.Name
                Type             = $head.Type
                State            = $head.State
                DiskSignature    = $params.DiskSignature
                DiskSignatureHex = SigHex $params.DiskSignature
                DiskIdGuid       = $params.DiskIdGuid
                IsQuorum         = ($q -and $q.Resource -eq $r.PSChildName)
            }
        }

        Write-Host "Ressources Physical Disk avec signature/GUID :" -ForegroundColor Yellow
        $resources |
            Where-Object { $_.DiskSignature -or $_.DiskIdGuid } |
            Sort-Object IsQuorum -Descending |
            Format-Table -AutoSize ResourceId, Name, Type, State, IsQuorum, DiskSignatureHex, DiskIdGuid |
            Out-Host

        Section "Correspondance Cluster <-> Disques OS"
        $matches = foreach ($r in ($resources | Where-Object { $_.DiskSignature -or $_.DiskIdGuid })) {
            $hits = @()
            foreach ($d in $drives) {
                if ($r.DiskSignatureHex -and (SigHex $d.Signature) -eq $r.DiskSignatureHex) {
                    $hits += "Disk$($d.Index)"
                }
            }
            # Volumes derriere ces disques (via mapping de Win32_LogicalDiskToPartition)
            $vols = foreach ($h in $hits) {
                $diskNum = [int]($h -replace 'Disk', '')
                $lettersOnDisk = $mapping |
                    Where-Object { $_.Partition -like "Disk #$diskNum,*" } |
                    ForEach-Object { $_.DriveLetter }
                $volRows = $volumes | Where-Object {
                    ($_.DriveLetter -and ($lettersOnDisk -contains $_.DriveLetter)) -or
                    ($null -eq $_.DriveLetter -and $_.Name -like "*\Harddisk$diskNum*")
                }
                foreach ($v in $volRows) {
                    $mnt = if ($v.DriveLetter) { "$($v.DriveLetter) " }
                           elseif ($v.Name) { $v.Name } else { '(no mount)' }
                    $lbl = if ($v.Label) { "'$($v.Label)' " } else { '' }
                    $sz  = if ($v.Capacity) { "$([math]::Round($v.Capacity/1GB,2))GB" } else { '' }
                    "$mnt$lbl$sz"
                }
            }
            [pscustomobject]@{
                ClusterResource = $r.Name
                IsQuorum        = $r.IsQuorum
                State           = $r.State
                SignatureHex    = $r.DiskSignatureHex
                DiskIdGuid      = $r.DiskIdGuid
                MatchedDisks    = ($hits -join ', ')
                Volumes         = ($vols -join ' | ')
            }
        }
        $matches | Sort-Object IsQuorum -Descending |
            Format-Table -Wrap ClusterResource, IsQuorum, State, SignatureHex, MatchedDisks, Volumes |
            Out-Host

        Section "Anomalies"
        $anomalies = 0
        # Signatures dupliquees cote OS
        $dupSig = $drives | Where-Object { $_.Signature } |
            Group-Object Signature | Where-Object { $_.Count -gt 1 }
        foreach ($g in $dupSig) {
            $anomalies++
            Write-Warning ("Signature {0} portee par {1} disques OS : {2}" -f `
                (SigHex $g.Name), $g.Count, (($g.Group | ForEach-Object { "Disk$($_.Index)" }) -join ', '))
        }
        # Ressources sans correspondance OS
        foreach ($m in $matches) {
            if (-not $m.MatchedDisks) {
                $anomalies++
                $tag = if ($m.IsQuorum) { ' [QUORUM]' } else { '' }
                Write-Warning ("Ressource cluster '$($m.ClusterResource)'$tag (sig=$($m.SignatureHex), guid=$($m.DiskIdGuid)) sans disque OS correspondant -> trace residuelle / quorum non libere.")
            }
        }
        if (-not $anomalies) { Write-Host "Aucune anomalie detectee." -ForegroundColor Green }
    }
}
else {
    Write-Host "(pas de hive HKLM:\Cluster sur ce noeud -> pas de Microsoft Failover Cluster ici)" -ForegroundColor DarkYellow
    Write-Host "Si tu utilises CyberArk Cluster Vault Manager (CVM), c'est NORMAL : la grappe est geree par CyberArk." -ForegroundColor DarkYellow
}

#endregion

#region Indices CyberArk Cluster Vault Manager (CVM)

Section "Fichiers de conf CyberArk susceptibles de referencer la grappe / quorum (CVM)"
$confCandidates = @(
    'C:\Program Files (x86)\PrivateArk\Server\Conf',
    'C:\Program Files\PrivateArk\Server\Conf'
)
$cvmHits = @()
foreach ($c in $confCandidates) {
    if (Test-Path $c) {
        $cvmHits += Get-ChildItem $c -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'cluster|cvm|quorum|vault\.ini|dbparm\.ini' } |
            Select-Object FullName, Length, LastWriteTime
    }
}
if ($cvmHits) {
    $cvmHits | Format-Table -AutoSize | Out-Host
    Write-Host "=> Ouvre ces fichiers et cherche les directives referencant le disque/lettre/signature du quorum CVM." -ForegroundColor DarkYellow
    Write-Host "   Les valeurs (lettre de lecteur ou chemin) que tu y trouveras sont a recouper avec la table 'Volumes' plus haut." -ForegroundColor DarkYellow
}
else {
    Write-Host "(aucun chemin Server\Conf trouve - chemin d'install non standard)"
}

#endregion

#region Export

if ($ReportPath) {
    $payload = [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('s')
        Node        = $env:COMPUTERNAME
        Drives      = $drives | Select-Object Index, Model, InterfaceType, MediaType, SerialNumber,
                       Signature, @{n='SignatureHex';e={SigHex $_.Signature}}, Size, Partitions, Status
        Partitions  = $parts
        Volumes     = $volumes
        Mapping     = $mapping
        Cluster     = if (Test-Path 'HKLM:\Cluster') {
            [pscustomobject]@{
                Quorum    = (Get-ItemProperty 'HKLM:\Cluster\Quorum' -ErrorAction SilentlyContinue)
                Resources = if ($resources) { $resources } else { @() }
                Matches   = if ($matches) { $matches } else { @() }
            }
        } else { $null }
        CvmConfHits = $cvmHits
    }
    $payload | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportPath -Encoding UTF8
    Write-Host "Rapport JSON : $ReportPath" -ForegroundColor Green
}

#endregion
