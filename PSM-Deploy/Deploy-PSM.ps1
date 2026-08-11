#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Idempotent deployment orchestrator for a CyberArk Privileged Session Manager (PSM).

.DESCRIPTION
    Runs LOCALLY on each PSM server, from the self-contained "sources" folder.
    Idempotent (Ansible-style): every phase Test -> Set, reported OK/CHANGED/FAILED.
    State machine with automatic resume after reboot (RDS/PSM).
    Fail-fast: stops at the first error, resumable after fixing.

    Phases (CyberArk stages are driven via InstallationAutomation\Execute-Stage.ps1):
      PreFlight -> Readiness -> Prerequisites(RDS) -> [reboot] -> RdsLicensing
             -> Software -> Installation -> PostInstallation -> [possible reboot at each stage]
             -> Registration(secret via PVWA API) -> Hardening(+AppLocker) -> Validation

.PARAMETER Zone
    Zone key in config\zones.psd1 (e.g. DC1, DC2). Selects Vault/PVWA.

.PARAMETER Resume
    Resume after reboot (triggered by the scheduled task). Restarts at the first unfinished phase.

.PARAMETER NonInteractive
    Skips the interactive confirmations (reserve for automation).

.EXAMPLE
    # "Plan" mode (dry-run): changes nothing
    .\Deploy-PSM.ps1 -Zone DC1 -WhatIf

.EXAMPLE
    # Real deployment with confirmations
    .\Deploy-PSM.ps1 -Zone DC1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Target zone (config\zones.psd1). Mandatory on first launch; on resume
    # (-Resume) it is re-read from state when omitted (the scheduled task passes it).
    [string] $Zone,
    [switch] $Resume,

    # Start from scratch: resets the state (progress.json) before deploying, to
    # replay ALL phases (useful after uninstalling/cleaning up the PSM).
    # Incompatible with -Resume.
    [switch] $Reset,
    [switch] $NonInteractive,

    # PVWA account of the admin performing the installation. When omitted in
    # interactive mode, it is requested via Get-Credential. Vault secrets are then
    # retrieved through the PVWA REST API (no CCP/AIM).
    [pscredential] $PvwaCredential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Location & module loading ---------------------------------------------
$SourcesRoot = $PSScriptRoot
Get-ChildItem (Join-Path $SourcesRoot 'modules') -Filter '*.psm1' |
    ForEach-Object { Import-Module $_.FullName -Force }

# --- Configuration loading --------------------------------------------------
$Settings = Import-PowerShellDataFile (Join-Path $SourcesRoot 'config\settings.psd1')
$Zones    = Import-PowerShellDataFile (Join-Path $SourcesRoot 'config\zones.psd1')
$Software = Import-PowerShellDataFile (Join-Path $SourcesRoot 'config\software.psd1')

# --- Logging + state init ---------------------------------------------------
$StateDir = Join-Path $SourcesRoot $Settings.Paths.State
Initialize-PSMLogging -LogDirectory (Join-Path $SourcesRoot $Settings.Paths.Logs)
Initialize-PSMState   -StateDirectory $StateDir

# The config is copied/hand-edited by the team: report the keys missing compared
# to this version of the script (features would otherwise be silently inactive).
Test-PSMSettingsDrift -Settings $Settings | Out-Null

# --- Optional state reset (start from scratch) ------------------------------
if ($Reset -and $Resume) {
    throw "-Reset and -Resume are incompatible (start from scratch vs resume)."
}
if ($Reset) {
    Reset-PSMState
    Unregister-PSMResumeTask   # removes a possibly stale resume task
}

# --- Zone resolution (parameter, otherwise state on resume) -----------------
if (-not $Zone -and $Resume) {
    $Zone = Get-PSMStateValue -Name 'Zone'
    if ($Zone) { Write-PSMLog -Level INFO -Message "Resume: zone '$Zone' re-read from state." }
}
if (-not $Zone) {
    throw "-Zone parameter required for a first launch (no persisted zone available for resume)."
}
if (-not $Zones.ContainsKey($Zone)) {
    throw "Unknown zone '$Zone'. Available zones: $($Zones.Keys -join ', ')."
}
$ZoneConfig = $Zones[$Zone]

Write-PSMLog -Level INFO -Message "=== PSM deployment $($Settings.PsmVersion) | Zone $Zone | Resume=$Resume | WhatIf=$($WhatIfPreference) ==="

# Schedules the supervised resume (AtLogOn) then reboots. Does NOT mark the
# current phase as completed: it will be replayed/resumed after reconnection.
function Start-PSMResumeReboot {
    param([Parameter(Mandatory)] [string] $Reason)
    Write-PSMLog -Level WARN -Message "Reboot required ($Reason). Scheduling the resume (AtLogOn) then restarting."
    $installUser = Get-PSMStateValue -Name 'InstallUser'
    if (-not $installUser) { $installUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
    Register-PSMResumeTask -ScriptPath $PSCommandPath -Zone $Zone -User $installUser
    Write-PSMLog -Level WARN -Message "Reconnect with account '$installUser': the deployment will resume automatically."
    Restart-Computer -Force
}

try {
    Assert-PSMElevation

    # ===================== PHASE: PreFlight =====================
    if (-not (Test-PSMPhaseComplete 'PreFlight')) {
        Confirm-PSMZone -ZoneConfig $ZoneConfig -NonInteractive:$NonInteractive
        # Connectivity check of the RDS license servers (non-blocking: WARN).
        Test-PSMLicenseServers -Servers $Settings.Rds.LicenseServers | Out-Null
        # The zone's PSM session accounts must resolve in the domain NOW, otherwise
        # the Hardening will fail much later ("identity references could not be
        # translated"). Classic trap: sAMAccountName limited to 20 characters,
        # truncated and therefore different from the Name/CN shown in the AD console.
        foreach ($acctKey in 'PSMConnectUserName', 'PSMAdminConnectUserName') {
            $acct = Get-PSMConfigValue -Config $ZoneConfig -Key $acctKey
            if ($acct -and -not (Test-PSMDomainAccount -Account $acct)) {
                throw ("PreFlight: zone account '$acct' ($acctKey) cannot be resolved in the domain. " +
                       "Check the account's REAL sAMAccountName in AD (20-character limit, " +
                       "often truncated compared to the Name/CN) and fix zones.psd1.")
            }
        }
        # TODO (deployment): Vault/PVWA connectivity checks, supported OS, media present.
        if ($PSCmdlet.ShouldProcess('PreFlight', 'Validate the pre-flight requirements')) {
            # Persist the zone + the installing admin for the resume after reboot.
            Set-PSMStateValue -Name 'Zone'        -Value $Zone
            Set-PSMStateValue -Name 'InstallUser' -Value ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
            Set-PSMPhaseComplete 'PreFlight'
        }
    }

    # Safety net: the resume task (AtLogOn) is armed RIGHT NOW, not only when the
    # orchestrator itself decides to reboot. Some CyberArk installers restart the
    # machine WITHOUT returning control (observed at the Installation stage):
    # without this pre-armed task, nothing would resume after reconnection.
    # Removed at the end of the deployment (Unregister-PSMResumeTask).
    if (-not $WhatIfPreference) {
        $resumeUser = Get-PSMStateValue -Name 'InstallUser'
        if (-not $resumeUser) { $resumeUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
        Register-PSMResumeTask -ScriptPath $PSCommandPath -Zone $Zone -User $resumeUser
    }

    # ===================== CyberArk STAGE: Readiness =====================
    if (-not (Test-PSMPhaseComplete 'Readiness')) {
        $r = Invoke-PSMReadiness -Settings $Settings -SourcesRoot $SourcesRoot
        if (-not $r.Succeeded) { throw "Readiness stage failed: $($r.ErrorData)" }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'Readiness stage'; return }
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Readiness' }
    }

    # ===================== CyberArk STAGE: Prerequisites (RDS, .NET, NLA...) =====================
    if (-not (Test-PSMPhaseComplete 'Prerequisites')) {
        $r = Invoke-PSMPrerequisites -Settings $Settings -SourcesRoot $SourcesRoot
        if (-not $r.Succeeded) { throw "Prerequisites stage failed: $($r.ErrorData)" }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'Prerequisites stage (RDS)'; return }
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Prerequisites' }
    }

    # ===================== PHASE: RDS licensing (local, after RDS is installed) =====================
    if (-not (Test-PSMPhaseComplete 'RdsLicensing')) {
        Invoke-PSMRdsLicensing -Settings $Settings
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'RdsLicensing' }
    }

    # ===================== PHASE: Additional software =====================
    if (-not (Test-PSMPhaseComplete 'Software')) {
        Invoke-PSMSoftware -SoftwareList $Software.Applications -SourcesRoot $SourcesRoot
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Software' }
    }

    # ===================== CyberArk STAGE: Installation =====================
    if (-not (Test-PSMPhaseComplete 'Installation')) {
        $r = Invoke-PSMInstall -Settings $Settings -SourcesRoot $SourcesRoot
        if (-not $r.Succeeded) { throw "Installation stage failed: $($r.ErrorData)" }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'Installation stage'; return }
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Installation' }
    }

    # ===================== CyberArk STAGE: PostInstallation =====================
    if (-not (Test-PSMPhaseComplete 'PostInstallation')) {
        # Zone's domain PSM accounts propagated to the CyberArk framework constants
        # (InstallationAutomation\Consts.ps1) before the steps that consume them.
        Set-PSMAutomationConsts -Settings $Settings -SourcesRoot $SourcesRoot -ZoneConfig $ZoneConfig | Out-Null
        $r = Invoke-PSMPostInstall -Settings $Settings -SourcesRoot $SourcesRoot
        if (-not $r.Succeeded) { throw "PostInstallation stage failed: $($r.ErrorData)" }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'PostInstallation stage'; return }
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'PostInstallation' }
    }

    # ===================== CyberArk STAGE: Registration (secret via PVWA) =====================
    if (-not (Test-PSMPhaseComplete 'Registration')) {
        if ($WhatIfPreference) {
            Write-PSMLog -Level INFO -Message "WhatIf: the Registration stage would run (Vault password retrieved via the PVWA API)."
        }
        else {
            # 1) PVWA authentication of the admin performing the installation.
            $pvwaCred = $PvwaCredential
            if (-not $pvwaCred) {
                if ($NonInteractive) {
                    throw "PVWA: credential required in NonInteractive mode (-PvwaCredential parameter)."
                }
                $pvwaCred = Get-Credential -Message "Admin PVWA account ($($ZoneConfig.PvwaAuthMethod)) - zone $($ZoneConfig.Name)"
            }

            $session = Connect-PvwaSession -PvwaUrl $ZoneConfig.PvwaUrl -Credential $pvwaCred `
                            -AuthMethod $ZoneConfig.PvwaAuthMethod `
                            -SkipCertificateCheck:$ZoneConfig.SkipCertificateCheck
            try {
                # 2) Vault install/admin account password via the PVWA API
                #    (otherwise the connected admin's account is reused).
                if ($ZoneConfig.InstallAccountSafe) {
                    $install = Get-PvwaAccountPassword -Session $session `
                                    -Safe     $ZoneConfig.InstallAccountSafe `
                                    -UserName $ZoneConfig.InstallAccountUserName
                    $installCred = $install.Credential
                }
                else {
                    $installCred = $pvwaCred
                }

                # 3) CyberArk Registration stage: the Vault address (cluster,DR) comes
                #    from zones.psd1 and is injected into a copy of RegistrationConfig.xml
                #    (the media is not modified). Password injected via -spwdObj.
                $r = Invoke-PSMRegister -Settings $Settings -SourcesRoot $SourcesRoot `
                        -InstallCredential $installCred `
                        -VaultAddress $ZoneConfig.VaultAddress

                # 4) Component account naming convention (PSM-<HOST> / PSMA<HOST>):
                #    RegisterComponent.exe generates random names (PSMApp_<hex>) with no
                #    naming option -> automated rename right after the registration
                #    (Vault via the still-open PVWA session + cred files + basic_psm.ini).
                if ($r.Succeeded) {
                    Rename-PSMComponentAccounts -Settings $Settings -Session $session | Out-Null
                }
            }
            finally {
                Disconnect-PvwaSession -Session $session
            }
            if (-not $r.Succeeded) { throw "Registration stage failed: $($r.ErrorData)" }
            if ($r.RestartRequired) { Start-PSMResumeReboot -Reason 'Registration stage'; return }
            Set-PSMPhaseComplete 'Registration'
        }
    }

    # ===================== CyberArk STAGE: Hardening (+ AppLocker) =====================
    if (-not (Test-PSMPhaseComplete 'Hardening')) {
        # Domain PSM session accounts: Consts.ps1 (framework) + variables of the
        # PSMHardening.ps1 / PSMConfigureAppLocker.ps1 scripts (via Invoke-PSMHardening).
        Set-PSMAutomationConsts -Settings $Settings -SourcesRoot $SourcesRoot -ZoneConfig $ZoneConfig | Out-Null
        $r = Invoke-PSMHardening -Settings $Settings -SourcesRoot $SourcesRoot -ZoneConfig $ZoneConfig
        if (-not $r.Succeeded) {
            # Hardening.NonBlocking: a hardening failure does not block the deployment
            # (e.g. EDR blocking system ACL modifications). The failed steps remain
            # TO BE REDONE once the cause is fixed.
            $hCfg = Get-PSMConfigValue -Config $Settings -Key 'Hardening'
            $tolerated = $hCfg -and [bool](Get-PSMConfigValue -Config $hCfg -Key 'NonBlocking')
            if ($tolerated) {
                Write-PSMLog -Level WARN -Message ("Hardening stage FAILURE TOLERATED (Hardening.NonBlocking): $($r.ErrorData) " +
                    "-> deployment continues. TO BE REDONE: fix the cause (e.g. EDR exclusion), remove 'Hardening' " +
                    "from state\progress.json then relaunch, or replay the failed steps via Execute-Stage.")
            }
            else {
                throw "Hardening stage failed: $($r.ErrorData)"
            }
        }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'Hardening stage'; return }
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Hardening' }
    }

    # ===================== PHASE: Validation =====================
    if (-not (Test-PSMPhaseComplete 'Validation')) {
        if (Test-PSMInstalled) {
            Write-PSMLog -Level OK   -Message "Validation: PSM service present."
        }
        else {
            Write-PSMLog -Level WARN -Message "Validation: PSM service not found (to be checked)."
        }
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Validation' }
    }

    # Resume task cleanup once everything is done.
    Unregister-PSMResumeTask
    Write-PSMLog -Level OK -Message "Deployment completed."
}
catch {
    Write-PSMLog -Level ERROR -Message "Stop (fail-fast): $($_.Exception.Message)"
    Write-PSMLog -Level WARN  -Message ("The 'PSM-Deploy-Resume' task stays armed: after fixing, the deployment " +
        "will resume at reconnection (or relaunch .\Deploy-PSM.ps1 -Zone $Zone). " +
        "To cancel it: Unregister-ScheduledTask PSM-Deploy-Resume.")
    Write-PSMSummary
    exit 1
}

Write-PSMSummary
# Exit code: 0 = OK; (possible convention: 2 when CHANGED) - see README.
exit 0
