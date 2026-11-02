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
             -> Registration(secret via PVWA API) -> Hardening(+AppLocker)
             -> RdpCertificate(VIP certificate on RDP, every launch) -> Validation
             -> configuration check (read-only, every launch: framed alert listing the defects)

.PARAMETER Zone
    Zone key in config\zones.psd1 (e.g. DC1, DC2). Selects Vault/PVWA.

.PARAMETER Resume
    Resume after reboot (triggered by the scheduled task). Restarts at the first unfinished phase.

.PARAMETER NonInteractive
    Skips the interactive confirmations (reserve for automation).

.PARAMETER NoPvwa
    For a server with NO network flow to the PVWA: no PVWA call at all. The
    Vault install account (a CyberArk/Vault account - LDAP accounts are refused
    by the registration) is entered directly and checked by the Vault on port
    1858; the component accounts are NOT renamed (a framed alert lists the
    manual steps). Remembered for the resume after a reboot.

.PARAMETER RedoHardening
    For a PSM ALREADY in place (deployed by this script or not): replays ONLY
    the Hardening stage (+ AppLocker), with the same config and tolerance as
    the deployment, then the RDP certificate and the configuration check. No
    other phase runs, no resume task, never an automatic reboot (live
    sessions: a reboot the stage asks for is announced, to do by hand).
    Typical use: after an EDR exclusion, instead of editing state\progress.json.

.PARAMETER Upgrade
    Upgrades the installed PSM with the media under media\PSM when the media
    carries a HIGHER version (e.g. a 14.0 build fixing a vulnerability). The
    14.0 CyberArk automation has no upgrade mode: the script runs the checks
    (service running, no pending reboot, free space, open sessions listed, YES),
    backs up the PSM configuration, launches the CyberArk wizard (the operator
    clicks through it), resumes after its reboot, checks the new version, then
    replays the Hardening, the RDP certificate and the configuration check.
    No registration, no rename (an upgrade keeps them). Each step is recorded:
    any relaunch (or the resume task) continues an unfinished upgrade.

.EXAMPLE
    # "Plan" mode (dry-run): changes nothing
    .\Deploy-PSM.ps1 -Zone DC1 -WhatIf

.EXAMPLE
    # Real deployment with confirmations
    .\Deploy-PSM.ps1 -Zone DC1

.EXAMPLE
    # Server that cannot reach the PVWA
    .\Deploy-PSM.ps1 -Zone DC1 -NoPvwa

.EXAMPLE
    # Replay the Hardening on a PSM already in place (e.g. after an EDR exclusion)
    .\Deploy-PSM.ps1 -Zone DC1 -RedoHardening

.EXAMPLE
    # Upgrade the installed PSM with the newer media (dry-run first)
    .\Deploy-PSM.ps1 -Zone DC1 -Upgrade -WhatIf
    .\Deploy-PSM.ps1 -Zone DC1 -Upgrade
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
    # With -NoPvwa: the Vault install account itself.
    [pscredential] $PvwaCredential,

    # No network flow to the PVWA from this server (see .PARAMETER NoPvwa).
    [switch] $NoPvwa,

    # Replay ONLY the Hardening stage on a PSM in place (see .PARAMETER RedoHardening).
    [switch] $RedoHardening,

    # Upgrade the installed PSM with the newer media (see .PARAMETER Upgrade).
    [switch] $Upgrade
)

# --- "Downloaded from the Internet" mark ------------------------------------
# Files extracted from a downloaded archive carry a Zone.Identifier mark, and
# robocopy carries it to every server: PowerShell then refuses or asks to
# confirm each module/script, installers may show a security warning. Remove
# it from the whole sources tree BEFORE loading the modules (no-op when there
# is none; -WhatIf:$false so plan mode does not print one line per file).
Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -File -ErrorAction SilentlyContinue |
    Unblock-File -ErrorAction SilentlyContinue -WhatIf:$false

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Location & module loading ---------------------------------------------
$SourcesRoot = $PSScriptRoot
Get-ChildItem (Join-Path $SourcesRoot 'modules') -Filter '*.psm1' |
    ForEach-Object { Import-Module $_.FullName -Force }

# --- Configuration loading --------------------------------------------------
$Settings = Import-PowerShellDataFile (Join-Path $SourcesRoot 'config\settings.psd1')
$Zones    = Import-PowerShellDataFile (Join-Path $SourcesRoot 'config\zones.psd1')

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
if ($RedoHardening -and ($Reset -or $Resume)) {
    throw "-RedoHardening cannot be combined with -Reset or -Resume (it replays the Hardening stage only)."
}
if ($Upgrade -and ($Reset -or $RedoHardening)) {
    throw "-Upgrade cannot be combined with -Reset or -RedoHardening (the upgrade replays the Hardening itself)."
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

# --- -NoPvwa (no flow to the PVWA from this server) --------------------------
# Remembered in the state: the resume after a reboot does not pass it. A manual
# launch uses exactly what it is given (and records it).
if ($Resume) {
    if (-not $NoPvwa -and [bool](Get-PSMStateValue -Name 'NoPvwa')) {
        $NoPvwa = $true
        Write-PSMLog -Level INFO -Message 'Resume: -NoPvwa re-read from state.'
    }
}
elseif (-not $WhatIfPreference -and -not $RedoHardening -and -not $Upgrade) { Set-PSMStateValue -Name 'NoPvwa' -Value ([bool]$NoPvwa) }

Write-PSMLog -Level INFO -Message ("=== PSM deployment $($Settings.PsmVersion) | Zone $Zone | Resume=$Resume | NoPvwa=$NoPvwa | " +
    "RedoHardening=$RedoHardening | Upgrade=$Upgrade | WhatIf=$($WhatIfPreference) ===")
if ($NoPvwa) {
    Write-PSMLog -Level WARN -Message ('-NoPvwa: no PVWA call. At Registration the Vault install account is entered directly ' +
        '(CyberArk/Vault account, checked by the Vault), and the component accounts are NOT renamed (manual steps listed then).')
}

# Schedules the supervised resume (AtLogOn) then reboots. Callers mark the phase
# complete BEFORE calling this when the stage succeeded; a phase interrupted by a
# "wild" installer reboot is simply replayed (nothing was marked).
function Start-PSMResumeReboot {
    param([Parameter(Mandatory)] [string] $Reason)
    # Loop guard: the same phase requesting reboots over and over means the stage
    # never converges (seen with version-dependent installer behavior) - stop
    # explicitly instead of cycling forever. Counters are wiped by -Reset.
    $rebootKey = "RebootCount:$Reason"
    $rebootCount = [int](Get-PSMStateValue -Name $rebootKey)
    if ($rebootCount -ge 2) {
        throw ("Reboot requested by '$Reason' for the 3rd time - reboot loop detected, stopping. " +
               'Check the CyberArk stage log before relaunching.')
    }
    Set-PSMStateValue -Name $rebootKey -Value ($rebootCount + 1)
    Write-PSMLog -Level WARN -Message "Reboot required ($Reason). Scheduling the resume (AtLogOn) then restarting."
    $installUser = Get-PSMStateValue -Name 'InstallUser'
    if (-not $installUser) { $installUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
    Register-PSMResumeTask -ScriptPath $PSCommandPath -Zone $Zone -User $installUser
    Write-PSMLog -Level WARN -Message "Reconnect with account '$installUser': the deployment will resume automatically."
    Restart-Computer -Force
}

# The zone's PSM session accounts must resolve in the domain NOW, otherwise
# the Hardening will fail much later ("identity references could not be
# translated"). Classic trap: sAMAccountName limited to 20 characters,
# truncated and therefore different from the Name/CN shown in the AD console.
function Assert-PSMZoneAccounts {
    foreach ($acctKey in 'PSMConnectUserName', 'PSMAdminConnectUserName') {
        $acct = Get-PSMConfigValue -Config $ZoneConfig -Key $acctKey
        if ($acct -and -not (Test-PSMDomainAccount -Account $acct)) {
            throw ("PreFlight: zone account '$acct' ($acctKey) cannot be resolved in the domain. " +
                   "Check the account's REAL sAMAccountName in AD (20-character limit, " +
                   "often truncated compared to the Name/CN) and fix zones.psd1.")
        }
    }
}

# Hardening stage (+ AppLocker), shared by the deployment and -RedoHardening.
# Records its outcome in the state (read by the configuration check). Returns
# the stage result; throws on failure unless Hardening.NonBlocking tolerates it.
function Invoke-PSMHardeningPhase {
    # Domain PSM session accounts: Consts.ps1 (framework) + variables of the
    # PSMHardening.ps1 / PSMConfigureAppLocker.ps1 scripts (via Invoke-PSMHardening).
    Set-PSMAutomationConsts -Settings $Settings -SourcesRoot $SourcesRoot -ZoneConfig $ZoneConfig | Out-Null
    $r = Invoke-PSMHardening -Settings $Settings -SourcesRoot $SourcesRoot -ZoneConfig $ZoneConfig
    if (-not $WhatIfPreference) {
        Set-PSMStateValue -Name 'LastHardening' -Value ([pscustomobject]@{
            Date = (Get-Date -Format 's'); Succeeded = [bool]$r.Succeeded
            ErrorData = [string]$r.ErrorData; LogPath = [string]$r.LogPath })
    }
    if (-not $r.Succeeded) {
        # Hardening.NonBlocking: a hardening failure does not block the deployment
        # (e.g. EDR blocking system ACL modifications). The failed steps remain
        # TO BE REDONE once the cause is fixed.
        $hCfg = Get-PSMConfigValue -Config $Settings -Key 'Hardening'
        $tolerated = $hCfg -and [bool](Get-PSMConfigValue -Config $hCfg -Key 'NonBlocking')
        if ($tolerated) {
            Write-PSMLog -Level WARN -Message ("Hardening stage FAILURE TOLERATED (Hardening.NonBlocking): $($r.ErrorData) " +
                "-> deployment continues. TO BE REDONE: fix the cause (e.g. EDR exclusion), then relaunch " +
                ".\Deploy-PSM.ps1 -Zone $Zone -RedoHardening.")
        }
        else {
            throw "Hardening stage failed: $($r.ErrorData)"
        }
    }
    return $r
}

# RDP certificate (PSM behind a VIP): certificate with the VIP name in its SAN
# (zones.psd1 PsmVips) bound to the RDP listener. Checked on EVERY launch
# (quick and idempotent: manual fix, renewed certificate). Any problem = ALERT,
# never a stop. Returns $true when an alert was raised.
function Invoke-PSMRdpCertificatePhase {
    try {
        return (-not (Invoke-PSMRdpCertificate -ZoneConfig $ZoneConfig -WhatIf:$WhatIfPreference))
    }
    catch {
        Write-PSMLog -Level WARN -Message "RDP certificate: unexpected error, nothing changed ($($_.Exception.Message)) - check by hand."
        return $true
    }
}

# Read-only configuration check closing every launch. Returns the number of
# defects (ALERT); a check that cannot run never stops the script.
function Invoke-PSMAuditPhase {
    param([bool] $RdpCertAlert)
    try {
        $audit = Invoke-PSMConfigurationAudit -Settings $Settings -Zones $Zones -ZoneKey $Zone `
                    -LastHardening (Get-PSMStateValue -Name 'LastHardening') -RdpCertificateOk (-not $RdpCertAlert)
        return @($audit | Where-Object { $_.Status -eq 'ALERT' }).Count
    }
    catch {
        Write-PSMLog -Level WARN -Message "Configuration check skipped: $($_.Exception.Message)"
        return [int]$RdpCertAlert
    }
}

function Write-PSMEndMessage {
    param([string] $What, [bool] $RdpCertAlert, [int] $AuditAlerts)
    if ($AuditAlerts -gt 0) {
        Write-PSMLog -Level WARN -Message ("$What completed WITH $AuditAlerts configuration alert(s): see the CONFIGURATION CHECK above " +
            '(the check changed nothing - fix each point, then .\tools\Test-PSMConfiguration.ps1).')
    }
    elseif ($RdpCertAlert) {
        Write-PSMLog -Level WARN -Message ("$What completed WITH an RDP certificate ALERT (see above): fix it by hand, " +
            "then relaunch .\Deploy-PSM.ps1 -Zone $Zone to re-check and bind.")
    }
    else {
        Write-PSMLog -Level OK -Message "$What completed."
    }
}

$upgradeInProgress = $false   # read by the catch block below
try {
    Assert-PSMElevation

    # An unfinished -Upgrade (state 'Upgrade', step not 'Done') takes over any
    # launch: the resume task after the installer's reboot, or a relaunch.
    $upgradeState      = Get-PSMStateValue -Name 'Upgrade'
    $upgradeInProgress = [bool]($upgradeState -and ([string]$upgradeState.Step -ne 'Done'))

    # ===================== -RedoHardening: the Hardening stage ONLY =====================
    # For a PSM ALREADY in place, deployed by this script or not: none of the
    # other phases runs, the resume task is never armed and the machine is never
    # restarted automatically (live sessions). Then the RDP certificate and the
    # configuration check, as at the end of a deployment.
    if ($RedoHardening) {
        if ($upgradeInProgress) {
            throw ("-RedoHardening: an upgrade is in progress (step '$($upgradeState.Step)') - " +
                   "relaunch .\Deploy-PSM.ps1 -Zone $Zone -Upgrade to finish it (it replays the Hardening).")
        }
        if (-not (Test-PSMInstalled)) {
            throw '-RedoHardening: no PSM service on this machine - nothing to harden (deploy it first).'
        }
        # Our own deployment stopped BEFORE the Registration: the Hardening comes after it.
        if ((Test-PSMPhaseComplete 'PreFlight') -and -not (Test-PSMPhaseComplete 'Registration')) {
            throw ("-RedoHardening: the deployment of this server is not finished (Registration not done) - " +
                   "relaunch .\Deploy-PSM.ps1 -Zone $Zone to finish it.")
        }
        try { Test-PSMZoneByVip -Zones $Zones -ZoneKey $Zone | Out-Null }
        catch { Write-PSMLog -Level WARN -Message "Zone check skipped: $($_.Exception.Message)" }
        Write-PSMLog -Level WARN -Message ('-RedoHardening: the CyberArk Hardening stage changes system settings (permissions, ' +
            'services, AppLocker) under the open sessions - prefer a maintenance window.')
        Confirm-PSMZone -ZoneConfig $ZoneConfig -NonInteractive:$NonInteractive
        Assert-PSMZoneAccounts

        $r = Invoke-PSMHardeningPhase
        # A server this script deployed keeps its phase marker up to date.
        if (-not $WhatIfPreference -and (Test-PSMPhaseComplete 'Registration')) { Set-PSMPhaseComplete 'Hardening' }

        $rdpCertAlert = Invoke-PSMRdpCertificatePhase
        $auditAlerts  = Invoke-PSMAuditPhase -RdpCertAlert $rdpCertAlert
        if ($r.RestartRequired -and -not $WhatIfPreference) {
            Write-PSMAlert -Title 'REBOOT REQUIRED' -Lines @(
                'The Hardening stage asks for a reboot to finish applying its settings.',
                '-RedoHardening never reboots by itself (open sessions): reboot in a maintenance window,',
                'then check with .\tools\Test-PSMConfiguration.ps1.')
        }
        Write-PSMEndMessage -What 'Hardening replay' -RdpCertAlert $rdpCertAlert -AuditAlerts $auditAlerts
        Write-PSMSummary
        exit 0
    }

    # ===================== -Upgrade: newer media over the installed PSM =====================
    # Steps recorded in the state ('Upgrade': From, Target, Setup, Backup, Step):
    # Installer (CyberArk wizard, run by the operator) -> Hardening -> Checks -> Done.
    # No registration, no rename: an upgrade keeps the PSM's Vault identity.
    if ($Upgrade -or $upgradeInProgress) {
        $wizardRan = $false
        if (-not $upgradeInProgress) {
            # --- Checks: any failure stops BEFORE changing anything ---------------
            $installed = Get-PSMInstalledVersion
            if (-not $installed) { throw '-Upgrade: no PSM service on this machine - deploy it instead.' }
            if ($installed -isnot [version]) { throw '-Upgrade: the version of the installed PSM cannot be read (service path) - upgrade it by hand.' }
            if ((Test-PSMPhaseComplete 'PreFlight') -and -not (Test-PSMPhaseComplete 'Registration')) {
                throw "-Upgrade: the deployment of this server is not finished - relaunch .\Deploy-PSM.ps1 -Zone $Zone to finish it first."
            }
            $setup = Get-PSMMediaSetup -Settings $Settings -SourcesRoot $SourcesRoot
            if ($setup.Version -le (ConvertTo-PSMFullVersion $installed)) {
                throw ("-Upgrade: nothing to upgrade - installed PSM $installed, media $($setup.Version) ($($setup.Path)). " +
                       'Drop the newer CyberArk media under media\PSM first.')
            }
            $mediaMM = '{0}.{1}' -f $setup.Version.Major, $setup.Version.Minor
            if ($mediaMM -ne [string]$Settings.PsmVersion) {
                throw "-Upgrade: the media is $($setup.Version) but settings.psd1 PsmVersion is '$($Settings.PsmVersion)' - set PsmVersion = '$mediaMM' first."
            }
            $svc = Get-Service -Name 'CyberArk Privileged Session Manager'
            if ([string]$svc.Status -ne 'Running') {
                throw "-Upgrade: the PSM service is $($svc.Status) - an upgrade does not repair a PSM: fix it first."
            }
            $pending = @(Test-PSMPendingReboot | Where-Object { $_ -ne 'pending file renames' })
            if ($pending) { throw "-Upgrade: a reboot is pending ($($pending -join ', ')) - reboot first." }
            $psmDir = Get-PSMInstalledPsmDir -Settings $Settings
            foreach ($drive in @('C', (Split-Path $psmDir -Qualifier).TrimEnd(':')) | Select-Object -Unique) {
                $freeGb = [math]::Round((Get-PSDrive -Name $drive -ErrorAction Stop).Free / 1GB, 1)
                if ($freeGb -lt 3) { throw "-Upgrade: only $freeGb GB free on ${drive}: - free some space first." }
            }
            try { Test-PSMZoneByVip -Zones $Zones -ZoneKey $Zone | Out-Null }
            catch { Write-PSMLog -Level WARN -Message "Zone check skipped: $($_.Exception.Message)" }
            $others = @(Get-PSMOtherSessions)
            Write-PSMAlert -Title "PSM UPGRADE $installed -> $($setup.Version) on $env:COMPUTERNAME" -Lines @(
                "Installer: $($setup.Path)",
                'The PSM service stops during the upgrade: OPEN SESSIONS ARE CUT.',
                "Open sessions now: $(if ($others) { $others -join ', ' } else { 'none' })",
                'Take the server out of the VIP pool first when it serves users.',
                'Then: backup of the PSM configuration -> CyberArk wizard (you click through it; accept its',
                'restart: the script resumes at your next logon) -> new version checked -> Hardening replayed',
                '-> RDP certificate -> configuration check. No registration, no rename.')
            if ($others -and $NonInteractive) { throw "-Upgrade -NonInteractive: sessions are open ($($others -join ', ')) - stopping." }
            Confirm-PSMZone -ZoneConfig $ZoneConfig -NonInteractive:$NonInteractive
            Assert-PSMZoneAccounts

            $backup = Backup-PSMConfiguration -PsmDir $psmDir -Label "$installed" -WhatIf:$WhatIfPreference
            if ($WhatIfPreference) {
                Write-PSMLog -Level INFO -Message ("WhatIf: the CyberArk wizard $($setup.Path) would run ($installed -> $($setup.Version)), " +
                    'then the Hardening, the RDP certificate and the configuration check.')
                $auditAlerts = Invoke-PSMAuditPhase -RdpCertAlert (Invoke-PSMRdpCertificatePhase)
                Write-PSMSummary
                exit 0
            }
            $upgradeState = [pscustomobject]@{
                From = "$installed"; Target = "$($setup.Version)"; Setup = $setup.Path; Backup = $backup
                Step = 'Installer'; Started = (Get-Date -Format 's') }
            Set-PSMStateValue -Name 'Upgrade' -Value $upgradeState
        }
        else {
            Write-PSMLog -Level INFO -Message "Upgrade $($upgradeState.From) -> $($upgradeState.Target) in progress: resuming at step '$($upgradeState.Step)'."
        }

        # Armed for the whole upgrade: the installer may restart the machine by itself.
        $resumeUser = Get-PSMStateValue -Name 'InstallUser'
        if (-not $resumeUser) { $resumeUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
        Register-PSMResumeTask -ScriptPath $PSCommandPath -Zone $Zone -User $resumeUser

        # --- Step Installer: the CyberArk wizard, until the new version is there ---
        if ($upgradeState.Step -eq 'Installer') {
            $target = ConvertTo-PSMFullVersion $upgradeState.Target
            $now    = ConvertTo-PSMFullVersion (Get-PSMInstalledVersion)
            if (-not $now -or $now -lt $target) {
                Write-PSMLog -Level WARN -Message ("Launching the CyberArk wizard ($($upgradeState.Setup)): follow it to the end. If it asks to " +
                    "restart, accept: the script resumes at the next logon of '$resumeUser'.")
                Start-Process -FilePath $upgradeState.Setup -WorkingDirectory (Split-Path $upgradeState.Setup -Parent) -Wait
                $wizardRan = $true
                $now = ConvertTo-PSMFullVersion (Get-PSMInstalledVersion)
                if (-not $now -or $now -lt $target) {
                    throw ("Upgrade NOT applied: installed version $(if ($now) { $now } else { 'unreadable' }), expected $target " +
                           "(wizard cancelled or failed - see its log). Relaunch .\Deploy-PSM.ps1 -Zone $Zone -Upgrade to run it again.")
                }
            }
            Write-PSMLog -Level OK -Message "PSM upgraded: $now (from $($upgradeState.From)). Backup of the previous configuration: $($upgradeState.Backup)"
            $upgradeState.Step = 'Hardening'
            Set-PSMStateValue -Name 'Upgrade' -Value $upgradeState
            # The installer finished in THIS run and left a reboot pending: reboot
            # (resume task armed) before replaying the Hardening.
            if ($wizardRan -and @(Test-PSMPendingReboot).Count -gt 0) {
                Start-PSMResumeReboot -Reason 'PSM upgrade (installer)'
                return
            }
        }

        # --- Step Hardening: replayed as is (same config and tolerance) -------------
        if ($upgradeState.Step -eq 'Hardening') {
            $r = Invoke-PSMHardeningPhase
            if (Test-PSMPhaseComplete 'Registration') { Set-PSMPhaseComplete 'Hardening' }
            $upgradeState.Step = 'Checks'
            Set-PSMStateValue -Name 'Upgrade' -Value $upgradeState
            if ($r.RestartRequired) { Start-PSMResumeReboot -Reason 'Hardening stage (upgrade)'; return }
        }

        # --- Step Checks: RDP certificate + configuration check, then done -----------
        $rdpCertAlert = Invoke-PSMRdpCertificatePhase
        $upgradeState.Step = 'Done'
        $upgradeState | Add-Member -NotePropertyName Finished -NotePropertyValue (Get-Date -Format 's') -Force
        Set-PSMStateValue -Name 'Upgrade' -Value $upgradeState
        Unregister-PSMResumeTask
        $auditAlerts = Invoke-PSMAuditPhase -RdpCertAlert $rdpCertAlert
        Write-PSMEndMessage -What "Upgrade $($upgradeState.From) -> $(Get-PSMInstalledVersion)" -RdpCertAlert $rdpCertAlert -AuditAlerts $auditAlerts
        Write-PSMSummary
        exit 0
    }

    # ===================== PHASE: PreFlight =====================
    if (-not (Test-PSMPhaseComplete 'PreFlight')) {
        # Guard: this script INSTALLS, it does not UPGRADE. On a machine already
        # running another PSM version (e.g. 12.6), the Installation stage would be
        # skipped (service present) and the target version's PostInstallation /
        # Registration / Hardening would run on top of the old binaries,
        # re-registering a live PSM. Stop before touching anything.
        $installed = Get-PSMInstalledVersion
        $expected  = [string]$Settings.PsmVersion
        if ($installed -is [string]) {   # 'Unreadable' (a [version] compared to a string would throw)
            Write-PSMLog -Level WARN -Message ("PreFlight: a PSM service is present but its version could not be read - " +
                "make sure it is the target version ($expected) before going further.")
        }
        elseif ($installed) {
            $installedMM = '{0}.{1}' -f $installed.Major, $installed.Minor
            if ($expected -and ($installedMM -ne $expected)) {
                throw ("PreFlight: PSM $installed is ALREADY installed on this machine, the target is $expected " +
                       "(settings.psd1 PsmVersion). A normal launch installs, it does not upgrade - nothing was changed. " +
                       "Upgrade with .\Deploy-PSM.ps1 -Zone $Zone -Upgrade (CyberArk wizard), or deploy on a fresh machine.")
            }
            Write-PSMLog -Level INFO -Message "PreFlight: PSM $installed already installed (target $expected) - resuming our own deployment."
        }
        # Logic check of -Zone (no mapping: the zones' PsmVips members), shown
        # BEFORE the zone confirmation. An alert, never a stop.
        try { Test-PSMZoneByVip -Zones $Zones -ZoneKey $Zone | Out-Null }
        catch { Write-PSMLog -Level WARN -Message "Zone check skipped: $($_.Exception.Message)" }
        Confirm-PSMZone -ZoneConfig $ZoneConfig -NonInteractive:$NonInteractive
        # Connectivity check of the RDS license servers (non-blocking: WARN).
        Test-PSMLicenseServers -Servers $Settings.Rds.LicenseServers | Out-Null
        # The zone's session accounts must resolve in the domain (see the function).
        Assert-PSMZoneAccounts
        # Local Administrators membership, provisioned ahead of time in AD (per-server
        # ACL group placed in the machine's local Administrators group):
        #   - PSMAdminConnect MUST be a local admin (PVWA live session monitoring /
        #     shadowing requires it);
        #   - PSMConnect must NOT be one (user sessions run under it - the hardening
        #     assumes a restricted account).
        # WARN only (AD fix to be done by the team), the deployment continues.
        $adminAcct = Get-PSMConfigValue -Config $ZoneConfig -Key 'PSMAdminConnectUserName'
        if ($adminAcct) {
            $m = Test-PSMLocalAdminMember -Account $adminAcct
            if ($m -eq $false) {
                Write-PSMLog -Level WARN -Message ("PreFlight: '$adminAcct' is NOT a member of the local Administrators group " +
                    "- PVWA live session monitoring (shadowing) will fail. Add it to the per-server AD ACL group " +
                    "(e.g. ...-Administrators-$env:COMPUTERNAME) ahead of time.")
            }
            elseif ($null -eq $m) {
                Write-PSMLog -Level WARN -Message "PreFlight: could not verify the local Administrators membership of '$adminAcct'."
            }
            else { Write-PSMLog -Level OK -Message "PreFlight: '$adminAcct' is a local Administrator (required for session monitoring)." }
        }
        $connAcct = Get-PSMConfigValue -Config $ZoneConfig -Key 'PSMConnectUserName'
        if ($connAcct) {
            if ((Test-PSMLocalAdminMember -Account $connAcct) -eq $true) {
                Write-PSMLog -Level WARN -Message ("PreFlight: SECURITY - '$connAcct' IS a member of the local Administrators group. " +
                    "User sessions run under this account: it must NOT be an administrator. " +
                    "Remove it from the per-server AD ACL group.")
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
        # The stage reported SUCCESS: all its steps ran. Mark the phase complete
        # BEFORE any reboot so the resume continues at the NEXT phase (re-running
        # a completed stage is version-dependent: harmless no-op on 12.6, endless
        # REINSTALL loop on 14.0). A mid-stage "wild" reboot still replays the
        # phase: the process dies before this marker is written.
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Readiness' }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'Readiness stage'; return }
    }

    # ===================== CyberArk STAGE: Prerequisites (RDS, .NET, NLA...) =====================
    if (-not (Test-PSMPhaseComplete 'Prerequisites')) {
        $r = Invoke-PSMPrerequisites -Settings $Settings -SourcesRoot $SourcesRoot
        if (-not $r.Succeeded) {
            # Known first-run quirk of the CyberArk InstallRDS step: it installs the
            # RDS role then immediately configures it, but the freshly installed
            # 'RDManagement' PowerShell module is not loadable yet ("The module
            # 'RDManagement' could not be loaded"). A second attempt succeeds
            # (CyberArk's recovery resumes at the failed step only), so retry the
            # stage ONCE automatically after letting the module staging settle.
            Write-PSMLog -Level WARN -Message ("Prerequisites stage failed ($($r.ErrorData)) - " +
                'automatic retry in 30s (known first-run RDS module quirk, recovery resumes at the failed step)...')
            Start-Sleep -Seconds 30
            $r = Invoke-PSMPrerequisites -Settings $Settings -SourcesRoot $SourcesRoot
        }
        if (-not $r.Succeeded) { throw "Prerequisites stage failed: $($r.ErrorData)" }
        # The stage reported SUCCESS: all its steps ran. Mark the phase complete
        # BEFORE any reboot so the resume continues at the NEXT phase (re-running
        # a completed stage is version-dependent: harmless no-op on 12.6, endless
        # REINSTALL loop on 14.0). A mid-stage "wild" reboot still replays the
        # phase: the process dies before this marker is written.
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Prerequisites' }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'Prerequisites stage (RDS)'; return }
    }

    # ===================== PHASE: RDS licensing (local, after RDS is installed) =====================
    if (-not (Test-PSMPhaseComplete 'RdsLicensing')) {
        Invoke-PSMRdsLicensing -Settings $Settings
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'RdsLicensing' }
    }

    # ===================== PHASE: Additional software =====================
    if (-not (Test-PSMPhaseComplete 'Software')) {
        # Common list (software.psd1) + the server type's additions (software.extra.psd1).
        Invoke-PSMSoftware -SoftwareList (Get-PSMSoftwareList -SourcesRoot $SourcesRoot) -SourcesRoot $SourcesRoot
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Software' }
    }

    # ===================== CyberArk STAGE: Installation =====================
    if (-not (Test-PSMPhaseComplete 'Installation')) {
        if (Test-PSMInstalled) {
            # Orchestrator-level PreCheck: the PSM service already exists, meaning a
            # previous pass completed the installation but its reboot killed the
            # orchestrator BEFORE the phase marker was written ("wild" installer
            # reboot). Re-running the stage is version-dependent: the 14.0
            # RunInstallation step logs the installed version then REINSTALLS
            # anyway (endless install/reboot loop). Installed => phase complete.
            Write-PSMLog -Level WARN -Message 'PSM already installed (service present): skipping the Installation stage (wild-reboot recovery).'
            if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Installation' }
        }
        else {
            $r = Invoke-PSMInstall -Settings $Settings -SourcesRoot $SourcesRoot
            if (-not $r.Succeeded) { throw "Installation stage failed: $($r.ErrorData)" }
            # The stage reported SUCCESS: all its steps ran. Mark the phase complete
            # BEFORE any reboot so the resume continues at the NEXT phase (re-running
            # a completed stage is version-dependent: harmless no-op on 12.6, endless
            # REINSTALL loop on 14.0). A mid-stage "wild" reboot still replays the
            # phase: the process dies before this marker is written.
            if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Installation' }
            if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'Installation stage'; return }
        }
    }

    # ===================== CyberArk STAGE: PostInstallation =====================
    if (-not (Test-PSMPhaseComplete 'PostInstallation')) {
        # Zone's domain PSM accounts propagated to the CyberArk framework constants
        # (InstallationAutomation\Consts.ps1) before the steps that consume them.
        Set-PSMAutomationConsts -Settings $Settings -SourcesRoot $SourcesRoot -ZoneConfig $ZoneConfig | Out-Null
        $r = Invoke-PSMPostInstall -Settings $Settings -SourcesRoot $SourcesRoot
        if (-not $r.Succeeded) { throw "PostInstallation stage failed: $($r.ErrorData)" }
        # The stage reported SUCCESS: all its steps ran. Mark the phase complete
        # BEFORE any reboot so the resume continues at the NEXT phase (re-running
        # a completed stage is version-dependent: harmless no-op on 12.6, endless
        # REINSTALL loop on 14.0). A mid-stage "wild" reboot still replays the
        # phase: the process dies before this marker is written.
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'PostInstallation' }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'PostInstallation stage'; return }
    }

    # ===================== CyberArk STAGE: Registration (secret via PVWA) =====================
    if (-not (Test-PSMPhaseComplete 'Registration')) {
        if ($WhatIfPreference) {
            if ($NoPvwa) { Write-PSMLog -Level INFO -Message 'WhatIf: the Registration stage would run (-NoPvwa: Vault install account entered directly, no rename).' }
            else         { Write-PSMLog -Level INFO -Message 'WhatIf: the Registration stage would run (Vault password retrieved via the PVWA API).' }
        }
        elseif ($NoPvwa) {
            # No flow to the PVWA from this server: the Vault install account is
            # entered directly and checked by the Vault itself during the
            # registration (port 1858). No PVWA call, hence no component rename.
            if (-not [bool](Get-PSMStateValue -Name 'RegistrationStageDone')) {
                if ($ZoneConfig.InstallAccountSafe) {
                    Write-PSMLog -Level WARN -Message ('-NoPvwa: zones.psd1 InstallAccountSafe/InstallAccountUserName ignored ' +
                        '(fetching that account needs the PVWA API) - enter the Vault install account instead.')
                }
                $installCred = $PvwaCredential
                if (-not $installCred) {
                    if ($NonInteractive) { throw '-NoPvwa -NonInteractive: pass the Vault install account with -PvwaCredential.' }
                    $installCred = Get-Credential -Message ('Vault install account for the PSM registration (-NoPvwa). CyberArk/Vault ' +
                        'account (LDAP is refused); checked by the Vault: a wrong password fails the registration.')
                    if (-not $installCred) { throw 'Registration cancelled: no Vault install account entered.' }
                }
                Register-PSMSecret -Secret $installCred.Password
                $r = Invoke-PSMRegister -Settings $Settings -SourcesRoot $SourcesRoot `
                        -InstallCredential $installCred `
                        -VaultAddress $ZoneConfig.VaultAddress
                if (-not $r.Succeeded) {
                    throw ("Registration stage failed: $($r.ErrorData) (-NoPvwa: a wrong Vault password also ends here - " +
                           'mind the account lockout before retrying).')
                }
                Set-PSMStateValue -Name 'RegistrationStageDone' -Value $true
            }
            else {
                Write-PSMLog -Level INFO -Message 'CyberArk registration already completed.'
                $r = [pscustomobject]@{ Succeeded = $true; RestartRequired = $false }
            }
            Write-PSMManualRenameAlert -Settings $Settings
            Set-PSMPhaseComplete 'Registration'
            if ($r.RestartRequired) { Start-PSMResumeReboot -Reason 'Registration stage'; return }
        }
        else {
            # 1) PVWA authentication of the admin performing the installation, WITH
            #    credential validation: a wrong account/password triggers a WARN and
            #    a fresh prompt (capped attempts, lockout-aware) instead of failing
            #    the whole deployment. Infrastructure errors still fail fast.
            #    -ConcurrentSession: during the stage, RegisterComponent.exe logs into
            #    the Vault with the SAME account; without concurrent sessions the Vault
            #    invalidates our PVWA token mid-phase (observed: 401 then timeouts on
            #    the component rename).
            $logon = Connect-PvwaSessionWithRetry -PvwaUrl $ZoneConfig.PvwaUrl `
                        -AuthMethod $ZoneConfig.PvwaAuthMethod -ZoneName $ZoneConfig.Name `
                        -Credential $PvwaCredential -ConcurrentSession `
                        -SkipCertificateCheck:$ZoneConfig.SkipCertificateCheck `
                        -NonInteractive:$NonInteractive
            $session  = $logon.Session
            $pvwaCred = $logon.Credential
            try {
                # The CyberArk registration itself is tracked SEPARATELY from the phase:
                # re-running Execute-Stage Registration would create ANOTHER server ID
                # (CyberArk behavior). If a previous run failed AFTER a successful
                # registration (e.g. during the component rename), the retry must only
                # redo the rename - never a second registration.
                if (-not [bool](Get-PSMStateValue -Name 'RegistrationStageDone')) {
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
                    if (-not $r.Succeeded) { throw "Registration stage failed: $($r.ErrorData)" }
                    Set-PSMStateValue -Name 'RegistrationStageDone' -Value $true
                }
                else {
                    Write-PSMLog -Level INFO -Message 'CyberArk registration already completed - resuming at the component account rename.'
                    $r = [pscustomobject]@{ Succeeded = $true; RestartRequired = $false }
                }

                # 4) Component account naming convention (PSM-<HOST> / PSMA<HOST>):
                #    RegisterComponent.exe generates random names (PSMApp_<hex>) with no
                #    naming option -> automated rename right after the registration
                #    (Vault via the still-open PVWA session + cred files). MANDATORY when
                #    Registration.RenameComponents is enabled: a failure here stops the
                #    deployment (fail-fast), and the retry redoes ONLY the rename.
                #    If the PVWA session died during the long registration (401/timeout),
                #    reconnect with the in-memory credential and retry ONCE - no secret
                #    is ever written to disk.
                try {
                    Rename-PSMComponentAccounts -Settings $Settings -Session $session -NonInteractive:$NonInteractive | Out-Null
                }
                catch {
                    $msg = $_.Exception.Message
                    if ($msg -match '\(401\)|Unauthorized|timed out|timeout') {
                        Write-PSMLog -Level WARN -Message "PVWA session lost after the registration ($msg) - reconnecting and retrying the rename once..."
                        $session = Connect-PvwaSession -PvwaUrl $ZoneConfig.PvwaUrl -Credential $pvwaCred `
                                        -AuthMethod $ZoneConfig.PvwaAuthMethod -ConcurrentSession `
                                        -SkipCertificateCheck:$ZoneConfig.SkipCertificateCheck
                        Rename-PSMComponentAccounts -Settings $Settings -Session $session -NonInteractive:$NonInteractive | Out-Null
                    }
                    else { throw }
                }
            }
            finally {
                Disconnect-PvwaSession -Session $session
            }
            # Same rule as the other stages: success => phase complete BEFORE reboot.
            Set-PSMPhaseComplete 'Registration'
            if ($r.RestartRequired) { Start-PSMResumeReboot -Reason 'Registration stage'; return }
        }
    }

    # ===================== CyberArk STAGE: Hardening (+ AppLocker) =====================
    if (-not (Test-PSMPhaseComplete 'Hardening')) {
        # Tolerated failure (Hardening.NonBlocking) handled inside: see the function.
        $r = Invoke-PSMHardeningPhase
        # The stage reported SUCCESS: all its steps ran. Mark the phase complete
        # BEFORE any reboot so the resume continues at the NEXT phase (re-running
        # a completed stage is version-dependent: harmless no-op on 12.6, endless
        # REINSTALL loop on 14.0). A mid-stage "wild" reboot still replays the
        # phase: the process dies before this marker is written.
        if (-not $WhatIfPreference) { Set-PSMPhaseComplete 'Hardening' }
        if ($r.RestartRequired -and -not $WhatIfPreference) { Start-PSMResumeReboot -Reason 'Hardening stage'; return }
    }

    # ===================== PHASE: RDP certificate (PSM behind a VIP) =====================
    # NOT recorded in progress.json: re-checked on every launch (see the function).
    $rdpCertAlert = Invoke-PSMRdpCertificatePhase

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

    # ===================== Configuration check (read-only) =====================
    $auditAlerts = Invoke-PSMAuditPhase -RdpCertAlert $rdpCertAlert
    Write-PSMEndMessage -What 'Deployment' -RdpCertAlert $rdpCertAlert -AuditAlerts $auditAlerts
}
catch {
    Write-PSMLog -Level ERROR -Message "Stop (fail-fast): $($_.Exception.Message)"
    if ($RedoHardening) {
        Write-PSMLog -Level WARN -Message "-RedoHardening stopped: fix the cause, then relaunch .\Deploy-PSM.ps1 -Zone $Zone -RedoHardening."
    }
    elseif ($Upgrade -or $upgradeInProgress) {
        Write-PSMLog -Level WARN -Message ("-Upgrade stopped: fix the cause, then relaunch .\Deploy-PSM.ps1 -Zone $Zone -Upgrade " +
            '(a started upgrade resumes at its step; the PSM-Deploy-Resume task, when armed, relaunches it at the next logon). ' +
            "To abandon a started upgrade: Unregister-ScheduledTask PSM-Deploy-Resume, and remove 'Upgrade' from state\progress.json.")
    }
    else {
        Write-PSMLog -Level WARN  -Message ("The 'PSM-Deploy-Resume' task stays armed: after fixing, the deployment " +
            "will resume at reconnection (or relaunch .\Deploy-PSM.ps1 -Zone $Zone). " +
            "To cancel it: Unregister-ScheduledTask PSM-Deploy-Resume.")
    }
    Write-PSMSummary
    exit 1
}

Write-PSMSummary
# Exit code: 0 = OK; (possible convention: 2 when CHANGED) - see README.
exit 0
