#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Orchestrateur de deploiement idempotent d'un Privileged Session Manager (PSM) CyberArk.

.DESCRIPTION
    Execution LOCALE sur chaque serveur PSM, depuis le dossier "sources" auto-portant.
    Idempotent (facon Ansible) : chaque phase Test -> Set, restitution OK/CHANGED/FAILED.
    Machine a etats avec reprise automatique apres reboot (RDS/PSM).
    Fail-fast : arret a la premiere erreur, reprise possible apres correction.

    Phases (les stages CyberArk sont pilotes via InstallationAutomation\Execute-Stage.ps1) :
      PreVol -> Readiness -> Prerequisites(RDS) -> [reboot] -> RdsLicensing
             -> Logiciels -> Installation -> PostInstallation -> [reboot eventuel a chaque stage]
             -> Registration(secret via API PVWA) -> Hardening(+AppLocker) -> Validation

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
    # Zone cible (config\zones.psd1). Obligatoire au premier lancement ; en reprise
    # (-Resume) elle est relue depuis l'etat si omise (la tache planifiee la transmet).
    [string] $Zone,
    [switch] $Resume,

    # Repart de zero : reinitialise l'etat (progress.json) avant de deployer, pour
    # rejouer TOUTES les phases (utile apres avoir desinstalle/nettoye le PSM).
    # Incompatible avec -Resume.
    [switch] $Reset,
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

# --- Init journalisation + etat --------------------------------------------
$StateDir = Join-Path $SourcesRoot $Settings.Paths.State
Initialize-PSMLogging -LogDirectory (Join-Path $SourcesRoot $Settings.Paths.Logs)
Initialize-PSMState   -StateDirectory $StateDir

# --- Reinitialisation eventuelle de l'etat (partir de zero) ----------------
if ($Reset -and $Resume) {
    throw "-Reset et -Resume sont incompatibles (repartir de zero vs reprendre)."
}
if ($Reset) {
    Reset-PSMState
    Unregister-PSMResumeTask   # supprime une eventuelle tache de reprise perimee
}

# --- Resolution de la zone (parametre, sinon etat en reprise) --------------
if (-not $Zone -and $Resume) {
    $Zone = Get-PSMStateValue -Name 'Zone'
    if ($Zone) { Write-PSMLog -Level INFO -Message "Reprise : zone '$Zone' relue depuis l'etat." }
}
if (-not $Zone) {
    throw "Parametre -Zone requis pour un premier lancement (aucune zone persistee pour la reprise)."
}
if (-not $Zones.ContainsKey($Zone)) {
    throw "Zone '$Zone' inconnue. Zones disponibles : $($Zones.Keys -join ', ')."
}
$ZoneConfig = $Zones[$Zone]

Write-PSMLog -Level INFO -Message "=== Deploiement PSM $($Settings.PsmVersion) | Zone $Zone | Resume=$Resume | WhatIf=$($WhatIfPreference) ==="

# Programme la reprise supervisee (AtLogOn) puis redemarre. Ne marque PAS la
# phase courante comme terminee : elle sera rejouee/reprise apres reconnexion.
function Start-PSMResumeReboot {
    param([Parameter(Mandatory)] [string] $Reason)
    Write-PSMLog -Level WARN -Message "Reboot requis ($Reason). Programmation de la reprise (AtLogOn) puis redemarrage."
    $installUser = Get-PSMStateValue -Name 'InstallUser'
    if (-not $installUser) { $installUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
    Register-PSMResumeTask -ScriptPath $PSCommandPath -Zone $Zone -User $installUser
    Write-PSMLog -Level WARN -Message "Reconnectez-vous avec le compte '$installUser' : le deploiement reprendra automatiquement."
    Restart-Computer -Force
}

try {
    Assert-PSMElevation

    # ===================== PHASE : PreVol =====================
    if (-not (Test-PSMPhaseComplete 'PreVol')) {
        Confirm-PSMZone -ZoneConfig $ZoneConfig -NonInteractive:$NonInteractive
        # Controle de connectivite des serveurs de licence RDS (non bloquant : WARN).
        Test-PSMLicenseServers -Servers $Settings.Rds.LicenseServers | Out-Null
        # TODO (deploiement) : verifs connectivite Vault/PVWA, OS supporte, media present.
        if ($PSCmdlet.ShouldProcess('PreVol', 'Valider les prerequis de vol')) {
            # Persiste la zone + l'admin installateur pour la reprise apres reboot.
            Set-PSMStateValue -Name 'Zone'        -Value $Zone
            Set-PSMStateValue -Name 'InstallUser' -Value ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
            Set-PSMPhaseComplete 'PreVol'
        }
    }

    # ===================== STAGE CyberArk : Readiness =====================
    if (-not (Test-PSMPhaseComplete 'Readiness')) {
        $r = Invoke-PSMReadiness -Settings $Settings -SourcesRoot $SourcesRoot
        if (-not $r.Succeeded) { throw "Stage Readiness en echec : $($r.ErrorData)" }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'stage Readiness'; return }
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Readiness' }
    }

    # ===================== STAGE CyberArk : Prerequisites (RDS, .NET, NLA...) =====================
    if (-not (Test-PSMPhaseComplete 'Prerequisites')) {
        $r = Invoke-PSMPrerequisites -Settings $Settings -SourcesRoot $SourcesRoot
        if (-not $r.Succeeded) { throw "Stage Prerequisites en echec : $($r.ErrorData)" }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'stage Prerequisites (RDS)'; return }
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Prerequisites' }
    }

    # ===================== PHASE : Licence RDS (locale, apres RDS installe) =====================
    if (-not (Test-PSMPhaseComplete 'RdsLicensing')) {
        Invoke-PSMRdsLicensing -Settings $Settings
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'RdsLicensing' }
    }

    # ===================== PHASE : Logiciels additionnels =====================
    if (-not (Test-PSMPhaseComplete 'Software')) {
        Invoke-PSMSoftware -SoftwareList $Software.Applications -SourcesRoot $SourcesRoot
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Software' }
    }

    # ===================== STAGE CyberArk : Installation =====================
    if (-not (Test-PSMPhaseComplete 'Installation')) {
        $r = Invoke-PSMInstall -Settings $Settings -SourcesRoot $SourcesRoot
        if (-not $r.Succeeded) { throw "Stage Installation en echec : $($r.ErrorData)" }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'stage Installation'; return }
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Installation' }
    }

    # ===================== STAGE CyberArk : PostInstallation =====================
    if (-not (Test-PSMPhaseComplete 'PostInstallation')) {
        $r = Invoke-PSMPostInstall -Settings $Settings -SourcesRoot $SourcesRoot
        if (-not $r.Succeeded) { throw "Stage PostInstallation en echec : $($r.ErrorData)" }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'stage PostInstallation'; return }
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'PostInstallation' }
    }

    # ===================== STAGE CyberArk : Registration (secret via PVWA) =====================
    if (-not (Test-PSMPhaseComplete 'Registration')) {
        if ($WhatIfPreference) {
            Write-PSMLog -Level INFO -Message "WhatIf : le stage Registration serait execute (mot de passe Vault recupere via l'API PVWA)."
        }
        else {
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
                # 2) Mot de passe du compte d'install/admin Vault via l'API PVWA
                #    (sinon on reutilise le compte de l'admin connecte).
                if ($ZoneConfig.InstallAccountSafe) {
                    $install = Get-PvwaAccountPassword -Session $session `
                                    -Safe     $ZoneConfig.InstallAccountSafe `
                                    -UserName $ZoneConfig.InstallAccountUserName
                    $installCred = $install.Credential
                }
                else {
                    $installCred = $pvwaCred
                }

                # 3) Stage Registration CyberArk : l'adresse Vault (cluster,DR) vient
                #    de zones.psd1 et est injectee dans une copie de RegistrationConfig.xml
                #    (on ne modifie pas le media). Mot de passe injecte via -spwdObj.
                $r = Invoke-PSMRegister -Settings $Settings -SourcesRoot $SourcesRoot `
                        -InstallCredential $installCred `
                        -VaultAddress $ZoneConfig.VaultAddress
            }
            finally {
                Disconnect-PvwaSession -Session $session
            }
            if (-not $r.Succeeded) { throw "Stage Registration en echec : $($r.ErrorData)" }
            if ($r.RestartRequired) { Start-PSMResumeReboot -Reason 'stage Registration'; return }
            Set-PSMPhaseComplete 'Registration'
        }
    }

    # ===================== STAGE CyberArk : Hardening (+ AppLocker) =====================
    if (-not (Test-PSMPhaseComplete 'Hardening')) {
        $r = Invoke-PSMHardening -Settings $Settings -SourcesRoot $SourcesRoot
        if (-not $r.Succeeded) { throw "Stage Hardening en echec : $($r.ErrorData)" }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'stage Hardening'; return }
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Hardening' }
    }

    # ===================== PHASE : Validation =====================
    if (-not (Test-PSMPhaseComplete 'Validation')) {
        if (Test-PSMInstalled) {
            Write-PSMLog -Level OK   -Message "Validation : service PSM present."
        }
        else {
            Write-PSMLog -Level WARN -Message "Validation : service PSM introuvable (a verifier)."
        }
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Validation' }
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
