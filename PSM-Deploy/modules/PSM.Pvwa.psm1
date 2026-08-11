<#
.SYNOPSIS
    Recuperation de secrets et operations Vault via l'API REST du PVWA.

.DESCRIPTION
    Remplace l'approche CCP/AIM : l'admin qui realise l'installation s'authentifie
    lui-meme sur le PVWA (il a acces a tous les comptes CyberArk), et le script
    recupere a la volee les mots de passe dont il a besoin via l'API REST.

    API REST stable de PSM/PVWA 12.6 -> 14.0 :
      POST {Pvwa}/PasswordVault/API/Auth/{method}/Logon        -> jeton de session
      GET  {Pvwa}/PasswordVault/API/Accounts?search=..&filter=safeName eq ..
      POST {Pvwa}/PasswordVault/API/Accounts/{id}/Password/Retrieve
      POST {Pvwa}/PasswordVault/API/Auth/Logoff

    Aucun secret n'est ecrit sur disque ; les mots de passe recuperes sont
    enregistres aupres de Register-PSMSecret pour etre masques dans les logs.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Set-PvwaTlsBypass {
    <#
        LAB UNIQUEMENT : accepte les certificats auto-signes du PVWA de test.
        A NE PAS activer en production (mettre SkipCertificateCheck = $false).
    #>
    [CmdletBinding()]
    param()
    # PowerShell 5.1 ne sait pas convertir une methode statique (PSMethod) en
    # delegue RemoteCertificateValidationCallback ("Cannot convert ... PSMethod").
    # L'affectation du delegue est donc faite DANS le C# lui-meme.
    if (-not ([System.Management.Automation.PSTypeName]'PSMTlsBypass').Type) {
        Add-Type -TypeDefinition @"
using System.Net;
public static class PSMTlsBypass {
    public static void Enable()  { ServicePointManager.ServerCertificateValidationCallback = delegate { return true; }; }
    public static void Disable() { ServicePointManager.ServerCertificateValidationCallback = null; }
}
"@
    }
    [PSMTlsBypass]::Enable()
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Write-Verbose "PVWA : validation du certificat TLS desactivee (mode lab)."
}

function Connect-PvwaSession {
    <#
        Authentifie l'admin sur le PVWA et renvoie un objet session
        (URL de base + jeton + en-tetes prets a l'emploi).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $PvwaUrl,
        [Parameter(Mandatory)] [pscredential] $Credential,
        [ValidateSet('CyberArk', 'LDAP', 'Windows', 'RADIUS')] [string] $AuthMethod = 'CyberArk',
        [switch] $ConcurrentSession,
        [switch] $SkipCertificateCheck,
        [int]    $TimeoutSec = 60
    )

    if ($SkipCertificateCheck) { Set-PvwaTlsBypass }

    $base = $PvwaUrl.TrimEnd('/')
    $body = @{
        username          = $Credential.UserName
        password          = $Credential.GetNetworkCredential().Password
        concurrentSession = [bool]$ConcurrentSession
    } | ConvertTo-Json

    $uri = "$base/PasswordVault/API/Auth/$AuthMethod/Logon"
    try {
        $token = Invoke-RestMethod -Uri $uri -Method Post -Body $body `
                    -ContentType 'application/json' -TimeoutSec $TimeoutSec -ErrorAction Stop
    }
    catch {
        throw "Echec de connexion PVWA ($AuthMethod) sur $base : $($_.Exception.Message)"
    }

    $clean = ($token | Out-String).Trim().Trim('"')
    return [pscustomobject]@{
        PvwaUrl = $base
        Token   = $clean
        Headers = @{ Authorization = $clean }
    }
}

function Disconnect-PvwaSession {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Session)
    try {
        Invoke-RestMethod -Uri "$($Session.PvwaUrl)/PasswordVault/API/Auth/Logoff" `
            -Method Post -Headers $Session.Headers -TimeoutSec 30 -ErrorAction Stop | Out-Null
    }
    catch {
        if (Get-Command Write-PSMLog -ErrorAction SilentlyContinue) {
            Write-PSMLog -Level WARN -Message "Logoff PVWA non critique : $($_.Exception.Message)"
        }
    }
}

function Find-PvwaUser {
    <# Recherche des USERS du Vault (API v2). Renvoie les objets { id, username, ... }. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory)] [string] $Search,
        [int] $TimeoutSec = 60
    )
    $uri  = "$($Session.PvwaUrl)/PasswordVault/API/Users?search=$([uri]::EscapeDataString($Search))"
    $resp = Invoke-RestMethod -Uri $uri -Method Get -Headers $Session.Headers -TimeoutSec $TimeoutSec -ErrorAction Stop
    if ($resp.PSObject.Properties.Name -contains 'Users') { return @($resp.Users) }
    return @()
}

function Rename-PvwaUser {
    <#
        Renomme un user du Vault via l'API PVWA (PUT /API/Users/{id}) :
        recupere l'objet complet, remplace 'username', renvoie l'objet mis a jour.
        Utilise pour aligner les comptes composants PSM sur la convention de nommage.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory)] [string] $UserName,
        [Parameter(Mandatory)] [string] $NewUserName,
        [int] $TimeoutSec = 60
    )
    $match = @(Find-PvwaUser -Session $Session -Search $UserName | Where-Object { $_.username -eq $UserName })
    if ($match.Count -ne 1) {
        throw "Rename-PvwaUser : user '$UserName' introuvable ou ambigu ($($match.Count) resultat(s)) cote Vault."
    }
    $id = $match[0].id

    if (-not $PSCmdlet.ShouldProcess($UserName, "Renommer en '$NewUserName' (PVWA API)")) { return $null }

    $userUri = "$($Session.PvwaUrl)/PasswordVault/API/Users/$id"
    $user    = Invoke-RestMethod -Uri $userUri -Method Get -Headers $Session.Headers -TimeoutSec $TimeoutSec -ErrorAction Stop
    $user.username = $NewUserName
    try {
        return Invoke-RestMethod -Uri $userUri -Method Put -Headers $Session.Headers `
                -Body ($user | ConvertTo-Json -Depth 8) -ContentType 'application/json' `
                -TimeoutSec $TimeoutSec -ErrorAction Stop
    }
    catch {
        throw ("Echec du renommage PVWA de '$UserName' en '$NewUserName' : $($_.Exception.Message). " +
               'Alternative : renommer le user dans PVWA (Administration > Users) puis relancer.')
    }
}

function Find-PvwaAccount {
    <# Recherche des comptes (filtre par Safe + recherche texte user/objet/adresse). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Session,
        [string] $Safe,
        [string] $UserName,
        [string] $Search,
        [string] $Address,
        [int]    $TimeoutSec = 60
    )
    $q = @()
    if ($Safe) { $q += "filter=safeName eq $([uri]::EscapeDataString($Safe))" }
    $terms = @($UserName, $Search, $Address) | Where-Object { $_ }
    if ($terms) { $q += "search=$([uri]::EscapeDataString(($terms -join ' ')))" }

    $uri = "$($Session.PvwaUrl)/PasswordVault/API/Accounts"
    if ($q) { $uri += '?' + ($q -join '&') }

    $resp  = Invoke-RestMethod -Uri $uri -Method Get -Headers $Session.Headers -TimeoutSec $TimeoutSec -ErrorAction Stop
    $items = @($resp.value)
    if ($UserName) { $items = @($items | Where-Object { $_.userName -eq $UserName }) }
    return $items
}

function Get-PvwaAccountPassword {
    <#
        Recupere le mot de passe d'un compte du Vault via l'API PVWA (session admin).
        Localise le compte soit par AccountId, soit par Safe/UserName/Search.
        Renvoie un objet { AccountId, UserName, Credential }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Session,
        [string] $AccountId,
        [string] $Safe,
        [string] $UserName,
        [string] $Search,
        [string] $Reason = 'PSM automated deployment',
        [int]    $TimeoutSec = 60
    )

    if (-not $AccountId) {
        $found = Find-PvwaAccount -Session $Session -Safe $Safe -UserName $UserName -Search $Search
        if (@($found).Count -eq 0) {
            throw "Compte introuvable dans le PVWA (Safe='$Safe' User='$UserName' Search='$Search')."
        }
        if (@($found).Count -gt 1) {
            $ids = ($found | Select-Object -First 5 -ExpandProperty id) -join ', '
            throw "Plusieurs comptes correspondent ($(@($found).Count)). Precisez Safe/UserName. Ids: $ids"
        }
        $AccountId = $found[0].id
        if (-not $UserName) { $UserName = $found[0].userName }
    }

    $body = @{ reason = $Reason } | ConvertTo-Json
    $uri  = "$($Session.PvwaUrl)/PasswordVault/API/Accounts/$AccountId/Password/Retrieve"
    try {
        $pw = Invoke-RestMethod -Uri $uri -Method Post -Headers $Session.Headers `
                -Body $body -ContentType 'application/json' -TimeoutSec $TimeoutSec -ErrorAction Stop
    }
    catch {
        throw "Echec recuperation du mot de passe (AccountId '$AccountId') via PVWA : $($_.Exception.Message)"
    }

    $plain = ($pw | Out-String).Trim().Trim('"')
    if (Get-Command Register-PSMSecret -ErrorAction SilentlyContinue) { Register-PSMSecret -Secret $plain }

    if (-not $UserName) { $UserName = 'vaultuser' }
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    return [pscustomobject]@{
        AccountId  = $AccountId
        UserName   = $UserName
        Credential = [System.Management.Automation.PSCredential]::new($UserName, $secure)
    }
}

Export-ModuleMember -Function Set-PvwaTlsBypass, Connect-PvwaSession, Disconnect-PvwaSession, `
                              Find-PvwaAccount, Get-PvwaAccountPassword, Find-PvwaUser, Rename-PvwaUser
