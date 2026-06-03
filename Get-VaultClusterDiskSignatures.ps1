<#
.SYNOPSIS
    Collecte les signatures de disques (cluster + OS) sur un cluster Vault
    CyberArk (WSFC) pour diagnostiquer un quorum/witness mal libere par
    Cluster Manager.

.DESCRIPTION
    Script de diagnostic en LECTURE SEULE. Aucune modification n'est faite.
    Il interroge chaque noeud du cluster pour recuperer :
      - les disques OS (Get-Disk) : numero, signature MBR, GUID GPT, UniqueId,
        SerialNumber, BusType, PartitionStyle, IsClustered, IsOffline ;
      - les ressources Cluster de type "Physical Disk" et leurs parametres
        DiskSignature / DiskIdGuid / DiskArbitrationVersion ;
      - la configuration de quorum (witness) ;
      - les Cluster Shared Volumes ;
      - optionnellement la cle de registre HKLM:\Cluster\Resources sur chaque
        noeud (utile quand une ressource a ete supprimee dans Cluster Manager
        mais que la trace persiste dans la base cluster d'un noeud).

    Puis il croise les signatures cluster avec les disques OS de chaque noeud
    et signale les anomalies classiques :
      - signature dupliquee (clone de LUN non re-signature) ;
      - ressource cluster sans disque OS correspondant (trace fantome) ;
      - witness identifie clairement.

    Pre-requis : execution sur un noeud du cluster (ou poste avec RSAT
    FailoverClusters), WinRM ouvert vers les autres noeuds pour la collecte
    distante. Module FailoverClusters present (fourni par Windows). Aucune
    autre dependance.

.PARAMETER ComputerName
    Noeuds a interroger. Par defaut : tous les noeuds du cluster detecte.

.PARAMETER Cluster
    Nom du cluster (optionnel, sinon cluster local).

.PARAMETER Credential
    Identifiants pour Invoke-Command sur les noeuds distants.

.PARAMETER IncludeRegistry
    Lit aussi HKLM:\Cluster\Resources sur chaque noeud (DiskSignature /
    DiskIdGuid historiques cote base cluster locale).

.PARAMETER ReportPath
    Chemin d'export. Extension .json => un seul fichier JSON. Sinon un
    prefixe pour 3 CSV (-clusterdisks.csv, -osdisks.csv, -matches.csv).

.EXAMPLE
    .\Get-VaultClusterDiskSignatures.ps1

.EXAMPLE
    .\Get-VaultClusterDiskSignatures.ps1 -IncludeRegistry -ReportPath .\cluster-disks.json

.EXAMPLE
    .\Get-VaultClusterDiskSignatures.ps1 -Cluster VAULTCL01 -ComputerName VLT01,VLT02 -Credential (Get-Credential)
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [string]$Cluster,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$IncludeRegistry,
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'

function Write-Section { param([string]$Title) Write-Host "`n=== $Title ===" -ForegroundColor Cyan }
function Format-SigHex {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return '' }
    try { return ('0x{0:X8}' -f [uint32]$Value) } catch { return "$Value" }
}

#region Cluster + nodes

$useCluster = $false
$clusterObj = $null
try {
    $clusterObj = if ($Cluster) { Get-Cluster -Name $Cluster } else { Get-Cluster }
    $useCluster = $true
}
catch {
    Write-Warning "Pas de cluster joignable : $($_.Exception.Message). Mode disques OS uniquement."
}

if (-not $ComputerName) {
    if ($useCluster) { $ComputerName = (Get-ClusterNode -Cluster $clusterObj.Name).Name }
    else { $ComputerName = @($env:COMPUTERNAME) }
}

if ($useCluster) {
    Write-Section "Cluster"
    $clusterObj | Format-List Name, Domain, SharedVolumesRoot | Out-Host

    Write-Section "Quorum (witness)"
    $quorum = Get-ClusterQuorum -Cluster $clusterObj.Name
    $quorum | Format-List Cluster, QuorumResource, QuorumType | Out-Host

    Write-Section "Noeuds"
    Get-ClusterNode -Cluster $clusterObj.Name |
        Format-Table Name, State, NodeWeight, Id -AutoSize | Out-Host
}

#endregion

#region Ressources Physical Disk + parametres

$clusterDisksDetail = @()
if ($useCluster) {
    Write-Section "Ressources cluster 'Physical Disk'"
    $clusterDisks = Get-ClusterResource -Cluster $clusterObj.Name |
        Where-Object { $_.ResourceType -eq 'Physical Disk' }

    foreach ($r in $clusterDisks) {
        $p = $r | Get-ClusterParameter
        $clusterDisksDetail += [pscustomobject]@{
            ResourceName           = $r.Name
            OwnerNode              = "$($r.OwnerNode)"
            State                  = "$($r.State)"
            IsWitness              = ($quorum -and $quorum.QuorumResource -and $quorum.QuorumResource.Name -eq $r.Name)
            DiskSignature          = ($p | Where-Object Name -eq 'DiskSignature').Value
            DiskSignatureHex       = (Format-SigHex (($p | Where-Object Name -eq 'DiskSignature').Value))
            DiskIdGuid             = ($p | Where-Object Name -eq 'DiskIdGuid').Value
            DiskArbitrationVersion = ($p | Where-Object Name -eq 'DiskArbitrationVersion').Value
        }
    }

    $clusterDisksDetail |
        Format-Table -AutoSize ResourceName, OwnerNode, State, IsWitness, DiskSignatureHex, DiskIdGuid |
        Out-Host

    Write-Section "Cluster Shared Volumes"
    try {
        Get-ClusterSharedVolume -Cluster $clusterObj.Name |
            Format-Table Name, OwnerNode, State -AutoSize | Out-Host
    }
    catch { Write-Host "(aucun CSV ou non applicable)" }
}

#endregion

#region Disques OS par noeud

$allDisks = @()
$diskSb = {
    Get-Disk | Select-Object Number, FriendlyName, SerialNumber, BusType,
        PartitionStyle, Signature, Guid, UniqueId, Size,
        OperationalStatus, IsClustered, IsOffline, IsReadOnly
}

foreach ($node in $ComputerName) {
    Write-Section "Disques OS sur $node"
    try {
        if ($node -ieq $env:COMPUTERNAME) {
            $nd = & $diskSb
        }
        else {
            $invokeParams = @{ ComputerName = $node; ScriptBlock = $diskSb }
            if ($Credential) { $invokeParams['Credential'] = $Credential }
            $nd = Invoke-Command @invokeParams
        }
    }
    catch {
        Write-Warning "Echec collecte disques sur $node : $($_.Exception.Message)"
        continue
    }

    foreach ($d in $nd) {
        Add-Member -InputObject $d -NotePropertyName Node -NotePropertyValue $node -Force
        $allDisks += $d
    }

    $nd | Sort-Object Number | Format-Table -AutoSize `
        Number, FriendlyName, BusType, PartitionStyle,
        @{n = 'SignatureHex'; e = { Format-SigHex $_.Signature } },
        Guid, IsClustered, IsOffline, OperationalStatus,
        @{n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB, 2) } } | Out-Host
}

#endregion

#region Correspondance cluster <-> OS + anomalies

$matchTable = @()
if ($useCluster -and $clusterDisksDetail) {
    Write-Section "Correspondance Cluster <-> OS"

    foreach ($cd in $clusterDisksDetail) {
        $sigHex = $cd.DiskSignatureHex
        $matched = @()
        foreach ($disk in $allDisks) {
            $osSigHex = Format-SigHex $disk.Signature
            $hit = $false
            if ($sigHex -and $osSigHex -and $sigHex -eq $osSigHex) { $hit = $true }
            elseif ($cd.DiskIdGuid -and $disk.Guid) {
                try { if ([guid]$cd.DiskIdGuid -eq [guid]$disk.Guid) { $hit = $true } } catch {}
            }
            if ($hit) { $matched += "$($disk.Node):Disk$($disk.Number)" }
        }
        $matchTable += [pscustomobject]@{
            ResourceName     = $cd.ResourceName
            IsWitness        = $cd.IsWitness
            OwnerNode        = $cd.OwnerNode
            State            = $cd.State
            DiskSignatureHex = $sigHex
            DiskIdGuid       = $cd.DiskIdGuid
            MatchedOSDisks   = ($matched -join ', ')
        }
    }
    $matchTable | Format-Table -AutoSize | Out-Host

    Write-Section "Anomalies"
    $anomalies = 0

    # Signatures dupliquees cote OS (clone de LUN typique).
    $dupSig = $allDisks | Where-Object { $_.Signature } |
        Group-Object Signature | Where-Object { $_.Count -gt 1 }
    foreach ($g in $dupSig) {
        $anomalies++
        $where = ($g.Group | ForEach-Object { "$($_.Node):Disk$($_.Number)" }) -join ', '
        Write-Warning ("Signature {0} dupliquee : {1}" -f (Format-SigHex $g.Name), $where)
    }

    # Ressources cluster sans disque OS correspondant.
    foreach ($m in $matchTable) {
        if (-not $m.MatchedOSDisks) {
            $anomalies++
            $tag = if ($m.IsWitness) { ' [WITNESS]' } else { '' }
            Write-Warning ("Ressource cluster '$($m.ResourceName)'$tag (sig=$($m.DiskSignatureHex), guid=$($m.DiskIdGuid)) : aucun disque OS correspondant -> trace residuelle / quorum non libere ?")
        }
    }

    # Disques OS clusterises mais pas references par une ressource cluster (cote OS isClustered=$true sans match).
    $clusterSigs = $clusterDisksDetail | ForEach-Object { Format-SigHex $_.DiskSignature }
    foreach ($d in ($allDisks | Where-Object { $_.IsClustered })) {
        $osSigHex = Format-SigHex $d.Signature
        if ($osSigHex -and ($clusterSigs -notcontains $osSigHex)) {
            $anomalies++
            Write-Warning ("Disque OS clusterise sans ressource correspondante : $($d.Node):Disk$($d.Number) sig=$osSigHex")
        }
    }

    if (-not $anomalies) { Write-Host "Aucune anomalie detectee." -ForegroundColor Green }
}

#endregion

#region Registre cluster (optionnel)

$registryDump = @{}
if ($IncludeRegistry) {
    Write-Section "Registre HKLM:\Cluster\Resources (par noeud)"
    $regSb = {
        $path = 'HKLM:\Cluster\Resources'
        if (-not (Test-Path $path)) { return @() }
        Get-ChildItem $path | ForEach-Object {
            $pp = Join-Path $_.PSPath 'Parameters'
            if (Test-Path $pp) {
                $params = Get-ItemProperty $pp -ErrorAction SilentlyContinue
                $name = (Get-ItemProperty $_.PSPath -Name Name -ErrorAction SilentlyContinue).Name
                $type = (Get-ItemProperty $_.PSPath -Name Type -ErrorAction SilentlyContinue).Type
                [pscustomobject]@{
                    ResourceId    = $_.PSChildName
                    Name          = $name
                    Type          = $type
                    DiskSignature = $params.DiskSignature
                    DiskIdGuid    = $params.DiskIdGuid
                }
            }
        }
    }

    foreach ($node in $ComputerName) {
        try {
            $r = if ($node -ieq $env:COMPUTERNAME) { & $regSb } else {
                $p = @{ ComputerName = $node; ScriptBlock = $regSb }
                if ($Credential) { $p['Credential'] = $Credential }
                Invoke-Command @p
            }
        }
        catch {
            Write-Warning "Echec lecture registre sur $node : $($_.Exception.Message)"
            continue
        }
        Write-Host "-- $node --"
        $r | Where-Object { $_.DiskSignature -or $_.DiskIdGuid } |
            Format-Table -AutoSize ResourceId, Name, Type,
                @{n = 'DiskSignatureHex'; e = { Format-SigHex $_.DiskSignature } },
                DiskIdGuid | Out-Host
        $registryDump[$node] = $r
    }
}

#endregion

#region Export

if ($ReportPath) {
    $payload = [pscustomobject]@{
        GeneratedAt    = (Get-Date).ToString('s')
        Cluster        = if ($useCluster) { $clusterObj.Name } else { $null }
        Quorum         = if ($useCluster) { $quorum } else { $null }
        ClusterDisks   = $clusterDisksDetail
        OSDisks        = $allDisks
        Matches        = $matchTable
        RegistryByNode = $registryDump
    }

    if ($ReportPath -like '*.json') {
        $payload | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportPath -Encoding UTF8
        Write-Host "Rapport JSON : $ReportPath" -ForegroundColor Green
    }
    else {
        $base = [IO.Path]::Combine(
            [IO.Path]::GetDirectoryName($ReportPath),
            [IO.Path]::GetFileNameWithoutExtension($ReportPath)
        )
        $clusterDisksDetail | Export-Csv "$base-clusterdisks.csv" -NoTypeInformation -Encoding UTF8
        $allDisks           | Export-Csv "$base-osdisks.csv"      -NoTypeInformation -Encoding UTF8
        $matchTable         | Export-Csv "$base-matches.csv"      -NoTypeInformation -Encoding UTF8
        Write-Host "Rapports CSV : $base-clusterdisks.csv, $base-osdisks.csv, $base-matches.csv" -ForegroundColor Green
    }
}

#endregion
