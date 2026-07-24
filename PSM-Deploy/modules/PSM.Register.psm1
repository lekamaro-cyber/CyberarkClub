<#
.SYNOPSIS
    Phase "Enregistrement Vault" : enregistrement des comptes composants
    PSMApp / PSMGw a partir d'une session PVWA deja ouverte.

.DESCRIPTION
    - La session PVWA est ouverte en amont par l'orchestrateur (module PSM.Pvwa),
      avec le compte de l'admin qui realise l'installation.
    - Le mot de passe du compte d'install/admin Vault est recupere via l'API PVWA
      (Get-PvwaAccountPassword) et passe ici en tant que $InstallCredential.
    - L'enregistrement lui-meme s'appuie sur la "registration automation" du media
      CyberArk + les XML fournis (cf. STUB ci-dessous, a brancher sur le media reel).
    - Les comptes de connexion PSMConnect/PSMAdminConnect (comptes de domaine)
      ne sont PAS manipules ici : le service PSM recupere leurs mots de passe a
      l'execution via le credential file du compte composant.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-PSMRegistered {
    <#
        Idempotence : renvoie $true si ce serveur PSM est deja enregistre.
        Strategie recommandee (a brancher sur le media/API) :
          - presence locale des credential files composants (psmapp.cred / psmgw.cred), ET/OU
          - existence dans le PVWA des comptes PSMApp_<host>/PSMGw_<host> (Find-PvwaAccount).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory)] $ZoneConfig,
        [string] $ServerId = $env:COMPUTERNAME
    )
    # TODO (deploiement) : implementer la detection reelle. Ex. :
    #   $comps = Find-PvwaAccount -Session $Session -Safe $ZoneConfig.ComponentsSafe -Search "PSMApp_$ServerId"
    #   return (@($comps).Count -gt 0)
    return $false
}

function Invoke-PSMRegister {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] $ZoneConfig,
        [Parameter(Mandatory)] $Session,                          # session PVWA active (PSM.Pvwa)
        [Parameter(Mandatory)] [pscredential] $InstallCredential, # compte install/admin Vault (via API)
        [Parameter(Mandatory)] [string] $SourcesRoot
    )

    Invoke-IdempotentStep -Name "Enregistrement PSM (PSMApp/PSMGw) - $($ZoneConfig.Name)" `
        -Test   { Test-PSMRegistered -Session $Session -ZoneConfig $ZoneConfig } `
        -Action {
            # ---------------------------------------------------------------
            # TODO (deploiement) : lancer la "registration automation" du media
            # CyberArk avec les XML fournis, en utilisant $InstallCredential
            # pour l'authentification Vault. La session $Session reste dispo
            # pour d'eventuelles verifications REST (Find-PvwaAccount, etc.).
            #
            #   $mediaPsm = Join-Path $SourcesRoot $Settings.Install.MediaRelativePath
            #   & <script-registration-du-media> -VaultUser $InstallCredential.UserName ...
            # ---------------------------------------------------------------
            throw "STUB : brancher ici la registration automation du media (auth via `$InstallCredential)."
        }
}

Export-ModuleMember -Function Invoke-PSMRegister, Test-PSMRegistered
