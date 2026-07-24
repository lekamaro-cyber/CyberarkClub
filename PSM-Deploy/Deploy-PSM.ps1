#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Orchestrateur de deploiement idempotent d'un Privileged Session Manager (PSM) CyberArk.

.DESCRIPTION
    Execution LOCALE sur chaque serveur PSM, depuis le dossier "sources" auto-portant.
    Idempotent (facon Ansible) : chaque phase Test -> Set, restitution OK/CHANGED/FAILED.
    Machine a etats avec reprise automatique apres reboot (RDS/PSM).
    Fail-fast : arret a la premiere erreur, reprise possible apres correction.

    Phases :
      PreVol -> Prereqs(RDS) -> [reboot] -> Logiciels -> InstallPSM
             -> Register(REST PVWA) -> Hardening(+AppLocker) -> Validation

.PARAMETER Zone
    Cle de zone dans config\zones.psd1 (ex: DC1, DC2). Selectionne Vault/PVWA.

.PARAMETER Resume
    Reprise apres reboot (declenchee par la tache planifiee). Reprend a la 1ere phase non terminee.

.PARAMETER NonInteractive
    Saute les confirmations interactives (a reserver a l'automatisation).

.EXAMPLE
    # Mode "plan" (dry-run) : ne modifie rien
    .\Deploy-PSM.ps1 -Zone DC1 -WhatIf

.EXAMPLE
    # Deploiement reel avec confirmations
    .\Deploy-PSM.ps1 -Zone DC1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string] $Zone,
    [switch] $Resume,
    [switch] $NonInteractive,

    # Compte PVWA de l'admin qui realise l'installation. Si omis en interactif,
    # il est demande via Get-Credential. Les secrets Vault sont ensuite recuperes
    # via l'API REST PVWA (pas de CCP/AIM).
    [pscredential] $PvwaCredential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Localisation & chargement des modules ---------------------------------
$SourcesRoot = $PSScriptRoot
Get-ChildItem (Join-Path $SourcesRoot 'modules') -Filter '*.psm1' |
    ForEach-Object { Import-Module $_.FullName -Force }

# --- Chargement de la configuration ----------------------------------------
$Settings = Import-PowerShellDataFile (Join-Path $SourcesRoot 'config\settings.psd1')
$Zones    = Import-PowerShellDataFile (Join-Path $SourcesRoot 'config\zones.psd1')
$Software = Import-PowerShellDataFile (Join-Path $SourcesRoot 'config\software.psd1')

if (-not $Zones.ContainsKey($Zone)) {
    throw "Zone '$Zone' inconnue. Zones disponibles : $($Zones.Keys -join ', ')."
}
$ZoneConfig = $Zones[$Zone]

# --- Init journalisation + etat --------------------------------------------
Initialize-PSMLogging -LogDirectory (Join-Path $SourcesRoot $Settings.Paths.Logs)
Initialize-PSMState   -StateDirectory (Join-Path $SourcesRoot $Settings.Paths.State)

Write-PSMLog -Level INFO -Message "=== Deploiement PSM $($Settings.PsmVersion) | Zone $Zone | Resume=$Resume | WhatIf=$($WhatIfPreference) ==="

try {
    Assert-PSMElevation

    # ===================== PHASE : PreVol =====================
    if (-not (Test-PSMPhaseComplete 'PreVol')) {
        Confirm-PSMZone -ZoneConfig $ZoneConfig -NonInteractive:$NonInteractive
        # TODO (deploiement) : verifs connectivite Vault/PVWA, OS supporte, media present.
        if ($PSCmdlet.ShouldProcess('PreVol', 'Valider les prerequis de vol')) {
            Set-PSMPhaseComplete 'PreVol'
        }
    }

    # ===================== PHASE : Prereqs (RDS) =====================
    if (-not (Test-PSMPhaseComplete 'Prereqs')) {
        $rebootRequired = Invoke-PSMPrereqs -Settings $Settings
        Set-PSMPhaseComplete 'Prereqs'
        if ($rebootRequired -and -not $WhatIfPreference) {
            Write-PSMLog -Level WARN -Message "Reboot requis (role RDS). Programmation de la reprise puis redemarrage."
            Register-PSMResumeTask -ScriptPath $MyInvocation.MyCommand.Path
            # La reprise relancera ce script avec -Resume ; on transmet aussi la zone.
            # TODO (deploiement) : persister la zone dans l'etat pour la reprise.
            Restart-Computer -Force
            return
        }
    }

    # ===================== PHASE : Logiciels additionnels =====================
    if (-not (Test-PSMPhaseComplete 'Software')) {
        Invoke-PSMSoftware -SoftwareList $Software.Applications -SourcesRoot $SourcesRoot
        Set-PSMPhaseComplete 'Software'
    }

    # ===================== PHASE : Installation PSM =====================
    if (-not (Test-PSMPhaseComplete 'InstallPSM')) {
        Invoke-PSMInstall -Settings $Settings -SourcesRoot $SourcesRoot
        Set-PSMPhaseComplete 'InstallPSM'
    }

    # ===================== PHASE : Enregistrement Vault =====================
    if (-not (Test-PSMPhaseComplete 'Register')) {
        # 1) Authentification PVWA de l'admin realisant l'installation.
        $pvwaCred = $PvwaCredential
        if (-not $pvwaCred) {
            if ($NonInteractive) {
                throw "PVWA : credential requis en mode NonInteractive (parametre -PvwaCredential)."
            }
            $pvwaCred = Get-Credential -Message "Compte PVWA de l'admin ($($ZoneConfig.PvwaAuthMethod)) - zone $($ZoneConfig.Name)"
        }

        $session = Connect-PvwaSession -PvwaUrl $ZoneConfig.PvwaUrl -Credential $pvwaCred `
                        -AuthMethod $ZoneConfig.PvwaAuthMethod `
                        -SkipCertificateCheck:$ZoneConfig.SkipCertificateCheck
        try {
            # 2) Mot de passe du compte d'install/admin Vault, recupere via l'API PVWA.
            #    Si aucun compte d'install n'est configure pour la zone, on reutilise
            #    directement le compte de l'admin connecte.
            if ($ZoneConfig.InstallAccountSafe) {
                $install = Get-PvwaAccountPassword -Session $session `
                                -Safe     $ZoneConfig.InstallAccountSafe `
                                -UserName $ZoneConfig.InstallAccountUserName
                $installCred = $install.Credential
            }
            else {
                $installCred = $pvwaCred
            }

            # 3) Enregistrement (utilise la session + le compte d'install).
            Invoke-PSMRegister -Settings $Settings -ZoneConfig $ZoneConfig `
                -Session $session -InstallCredential $installCred -SourcesRoot $SourcesRoot
        }
        finally {
            Disconnect-PvwaSession -Session $session
        }
        Set-PSMPhaseComplete 'Register'
    }

    # ===================== PHASE : Hardening (+ AppLocker) =====================
    if (-not (Test-PSMPhaseComplete 'Hardening')) {
        Invoke-PSMHardening -Settings $Settings -SourcesRoot $SourcesRoot
        Set-PSMPhaseComplete 'Hardening'
    }

    # ===================== PHASE : Validation =====================
    if (-not (Test-PSMPhaseComplete 'Validation')) {
        # TODO (deploiement) : smoke tests (services PSM up, enregistrement OK, AppLocker actif).
        Set-PSMPhaseComplete 'Validation'
    }

    # Nettoyage de la tache de reprise une fois tout termine.
    Unregister-PSMResumeTask
    Write-PSMLog -Level OK -Message "Deploiement termine."
}
catch {
    Write-PSMLog -Level ERROR -Message "Arret (fail-fast) : $($_.Exception.Message)"
    Write-PSMSummary
    exit 1
}

Write-PSMSummary
# Code de sortie : 0 = OK ; (convention possible : 2 si des CHANGED) - voir README.
exit 0
