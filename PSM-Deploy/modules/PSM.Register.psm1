<#
.SYNOPSIS
    Phase "Enregistrement Vault" : creation/enregistrement des comptes composants
    PSMApp / PSMGw via l'API REST PVWA.

.DESCRIPTION
    - Le compte admin/install Vault est recupere via le CCP (cf. PSM.Ccp).
    - Les comptes composants PSMApp/PSMGw sont AUTO-CREES par cette phase.
    - Les comptes de connexion PSMConnect/PSMAdminConnect (comptes de domaine
      geres par le CPM) ne sont PAS manipules ici : le service PSM recupere leurs
      mots de passe a l'execution via le credential file du compte composant
      (acces au Safe PSMConnect).

    API REST PVWA stable 12.6 -> 14.0 :
      POST {Pvwa}/PasswordVault/API/Auth/{method}/Logon
      ... operations ...
      POST {Pvwa}/PasswordVault/API/Auth/Logoff
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Connect-PVWA {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $PvwaUrl,
        [Parameter(Mandatory)] [pscredential] $AdminCredential,
        [ValidateSet('CyberArk', 'LDAP', 'RADIUS')] [string] $AuthMethod = 'CyberArk'
    )
    $body = @{
        username = $AdminCredential.UserName
        password = $AdminCredential.GetNetworkCredential().Password
    } | ConvertTo-Json
    $uri = "$($PvwaUrl.TrimEnd('/'))/PasswordVault/API/Auth/$AuthMethod/Logon"
    $token = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json'
    return $token.Trim('"')
}

function Disconnect-PVWA {
    param([string] $PvwaUrl, [string] $Token)
    try {
        Invoke-RestMethod -Uri "$($PvwaUrl.TrimEnd('/'))/PasswordVault/API/Auth/Logoff" `
            -Method Post -Headers @{ Authorization = $Token } | Out-Null
    } catch { Write-PSMLog -Level WARN -Message "Logoff PVWA non critique : $($_.Exception.Message)" }
}

function Invoke-PSMRegister {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] $ZoneConfig,
        [Parameter(Mandatory)] [pscredential] $AdminCredential   # issu du CCP
    )

    Invoke-IdempotentStep -Name "Enregistrement PSM (PSMApp/PSMGw) - $($ZoneConfig.Name)" `
        -Test   {
            # TODO (deploiement) : interroger PVWA pour verifier si ce PSM
            # (PSMServerID) est deja enregistre. Renvoyer $true si oui.
            $false
        } `
        -Action {
            $token = Connect-PVWA -PvwaUrl $ZoneConfig.PvwaUrl -AdminCredential $AdminCredential `
                                  -AuthMethod $ZoneConfig.PvwaAuthMethod
            try {
                # -------------------------------------------------------------
                # TODO (deploiement) : creer/enregistrer les comptes composants
                # PSMApp_<id> et PSMGw_<id>, puis associer le PSM Server ID.
                # (Selon le process : ajout dans le Safe composants + generation
                #  des credential files locaux via CreateCredFile/APIKey.)
                # -------------------------------------------------------------
                throw "STUB : brancher ici l'enregistrement REST PVWA des composants."
            }
            finally {
                Disconnect-PVWA -PvwaUrl $ZoneConfig.PvwaUrl -Token $token
            }
        }
}

Export-ModuleMember -Function Invoke-PSMRegister, Connect-PVWA, Disconnect-PVWA
