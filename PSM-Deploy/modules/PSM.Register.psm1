<#
.SYNOPSIS
    "Vault registration" phase: CyberArk "Registration" stage via Execute-Stage.ps1,
    with the Vault address (cluster,DR) injected from zones.psd1.

.DESCRIPTION
    Goal: be able to drop in a NEW CyberArk source without ever hand-editing its
    RegistrationConfig.xml. The Vault address ("clusterIp,drIp" format) comes from
    zones.psd1; the script patches a COPY (under state\) and runs Execute-Stage on
    it - the media stays intact.

    - The Vault install/admin account password is provided via -spwdObj
      (SecureString), retrieved beforehand through the PVWA API.
    - The location of the Vault address field in the XML is configurable
      (settings.psd1 Registration.VaultAddressXPath / VaultAddressAttribute), to
      adapt to the media's schema without touching the code.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-PSMRegister {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        [pscredential] $InstallCredential,   # password injected via -spwdObj
        [string] $VaultAddress               # "clusterIp,drIp" (from zones.psd1)
    )
    # Vault address AND vault user driven by the deployment: DYNAMIC injection
    # into a patched copy of RegistrationConfig.xml (media intact), through the
    # generic stage engine. The vaultuser injection keeps the XML's username
    # ALIGNED with the account whose password goes through -spwdObj (the media
    # ships vaultuser="administrator": mismatch = ITATS004E Authentication
    # failure for User administrator). Field locations are configurable
    # (settings.psd1 Registration.*).
    $extra = @{}
    if ($VaultAddress) {
        $xpath = $Settings.Registration.VaultAddressXPath
        $attr  = $Settings.Registration.VaultAddressAttribute
        if (-not $xpath) {
            throw "settings.psd1: Registration.VaultAddressXPath not set."
        }
        $extra[$xpath] = @{ Attribute = $attr; Value = $VaultAddress }
    }
    else {
        Write-PSMLog -Level WARN -Message "No zone Vault address (VaultAddress): using the media's RegistrationConfig.xml as-is."
    }
    if ($InstallCredential) {
        $userXpath = Get-PSMConfigValue -Config $Settings.Registration -Key 'VaultUserXPath'
        if ($userXpath) {
            $userAttr = Get-PSMConfigValue -Config $Settings.Registration -Key 'VaultUserAttribute'
            $extra[$userXpath] = @{ Attribute = $userAttr; Value = $InstallCredential.UserName }
            Write-PSMLog -Level INFO -Message "Registration: vaultuser injected = '$($InstallCredential.UserName)' (aligned with the retrieved password)."
        }
        else {
            Write-PSMLog -Level WARN -Message ("settings.psd1: Registration.VaultUserXPath not set - the media's own 'vaultuser' value is used " +
                "and MUST match the install account ('$($InstallCredential.UserName)'), otherwise the Vault logon fails (ITATS004E).")
        }
    }
    if ($extra.Keys.Count -eq 0) { $extra = $null }

    $stage = Resolve-PSMStageConfig -Settings $Settings -SourcesRoot $SourcesRoot `
                -StageKey 'Registration' -ExtraInjections $extra

    $securePwd = if ($InstallCredential) { $InstallCredential.Password } else { $null }

    return Invoke-PSMStage -StageName 'Registration' `
                           -ExecuteStagePath $stage.ExecuteStage `
                           -ConfigFilePath   $stage.ConfigFilePath `
                           -VaultPassword    $securePwd
}

function New-PSMComponentPassword {
    <#
        Random password for a component Vault user (password-sync flow).
        64-character charset (A-Za-z0-9 plus '-' and '_'): unbiased modulo
        mapping, and CLI-safe (the value goes on the CreateCredFile.exe command
        line - no quotes, spaces or '&'). Registered as a secret for log masking.
    #>
    [CmdletBinding()]
    param([int] $Length = 32)
    $charset = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    $rng     = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try {
        $bytes = New-Object byte[] $Length
        $rng.GetBytes($bytes)
        $newPwd = -join ($bytes | ForEach-Object { $charset[$_ % $charset.Count] })
    }
    finally { $rng.Dispose() }
    if (Get-Command Register-PSMSecret -ErrorAction SilentlyContinue) { Register-PSMSecret -Secret $newPwd }
    return $newPwd
}

function Update-PSMCredFile {
    <#
        Regenerates a CyberArk cred file with CreateCredFile.exe (<PsmDir>\Vault):
          CreateCredFile.exe <cred> Password /Username <u> /Password <p> /EntropyFile
        VERIFIED: exit code 0, file really rewritten, Username= line as expected.
        The backup is taken by the caller (Sync-PSMComponentCredential).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $CredPath,
        [Parameter(Mandatory)] [string] $UserName,
        [Parameter(Mandatory)] [string] $Password
    )
    $psmDir = (Get-PSMInstallPaths -Settings $Settings).PsmDir
    $exe    = Join-Path $psmDir 'Vault\CreateCredFile.exe'
    if (-not (Test-Path $exe)) {
        throw "Update-PSMCredFile: CreateCredFile.exe not found ($exe) - check Install.InstallDir."
    }
    if (-not (Test-Path $CredPath)) { throw "Update-PSMCredFile: cred file not found: $CredPath." }

    $extra = @('/EntropyFile')

    if (-not $PSCmdlet.ShouldProcess($CredPath, "Regenerate the cred file (Username=$UserName)")) { return $false }
    $writtenBefore = (Get-Item -Path $CredPath).LastWriteTime

    # Run FROM the cred file's folder with the bare file name, exactly like the
    # manual procedure that works (cd <PsmDir>\Vault; .\CreateCredFile.exe
    # psmapp.cred ...): launched from another folder with a full path, the
    # regenerated file did not authenticate.
    $credDir  = Split-Path -Path $CredPath -Parent
    $credName = Split-Path -Path $CredPath -Leaf
    Write-PSMLog -Level INFO -Message ("CreateCredFile (in $credDir): `"$exe`" $credName Password /Username $UserName /Password *** " + ($extra -join ' '))
    Push-Location -Path $credDir
    try {
        # Native stderr redirected under the module's EAP=Stop would become a
        # terminating error in PowerShell 5.1: relax it for this call only.
        $ErrorActionPreference = 'Continue'
        $out = & $exe $credName Password /Username $UserName /Password $Password @extra 2>&1
    }
    finally {
        $ErrorActionPreference = 'Stop'
        Pop-Location
    }
    if ($LASTEXITCODE -ne 0) {
        throw "CreateCredFile.exe failed (exit code $LASTEXITCODE): $out"
    }
    # Checks: the file was really rewritten and carries the expected user.
    if ((Get-Item -Path $CredPath).LastWriteTime -le $writtenBefore) {
        throw "Update-PSMCredFile: '$CredPath' was NOT rewritten by CreateCredFile (exit code 0). Output: $out"
    }
    if ((Get-Content -Path $CredPath -Raw) -notmatch ('(?im)^\s*Username\s*=\s*' + [regex]::Escape($UserName) + '\s*$')) {
        throw "Update-PSMCredFile: '$CredPath' does not carry Username=$UserName after regeneration. CreateCredFile output: $out"
    }
    $entropy = Get-Item -Path "$CredPath.entropy" -ErrorAction SilentlyContinue
    $entropyInfo = if ($entropy) { "entropy file written $($entropy.LastWriteTime)" } else { 'NO entropy file next to it' }
    Write-PSMLog -Level INFO -Message "Cred file regenerated: $CredPath (Username=$UserName; $entropyInfo)."
    return $true
}

function New-PSMSyncError {
    # Exception carrying whether the LOCAL cred file is back in its pre-sync
    # state (backup failed or restored) - the caller then knows whether the
    # Vault-side rename can be rolled back to match it.
    param([string] $Message, [bool] $LocalUnchanged)
    $e = [System.InvalidOperationException]::new($Message)
    $e.Data['LocalUnchanged'] = $LocalUnchanged
    return $e
}

function Sync-PSMComponentCredential {
    <#
        Gives a component Vault user a NEW password, in this order, each step
        verified, with a pause between steps (the PSM service is stopped by the
        caller):
          1. backup of the cred file and its .entropy (timestamped copies);
          2. CreateCredFile with the new password (Update-PSMCredFile);
          3. Vault password reset through the PVWA API (Reset-PvwaUserPassword).
        Cred file first, Vault second (CyberArk's own order): if step 2 or the
        reset call fails, the backup is restored and the Vault still has the old
        password, so the old pair stays consistent. If the reset is applied but
        leaves the user unusable (suspended, disabled...), the NEW cred file is
        kept - it matches the new Vault password.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory)] [string] $CredPath,
        [Parameter(Mandatory)] [string] $UserName,
        [int] $StepDelaySec = 5
    )
    $stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $entropy = "$CredPath.entropy"
    $bakCred = "$CredPath.bak-$stamp"
    $bakEnt  = "$entropy.bak-$stamp"

    # 1. Backup (verified).
    try {
        Copy-Item -Path $CredPath -Destination $bakCred -Force
        if (Test-Path $entropy) { Copy-Item -Path $entropy -Destination $bakEnt -Force } else { $bakEnt = $null }
    }
    catch { throw (New-PSMSyncError "Backup of '$CredPath' failed: $($_.Exception.Message)" $true) }
    if (-not (Test-Path $bakCred) -or ($bakEnt -and -not (Test-Path $bakEnt))) {
        throw (New-PSMSyncError "Backup of '$CredPath' could not be verified - nothing changed." $true)
    }
    Write-PSMLog -Level INFO -Message ("Backup: $bakCred" + $(if ($bakEnt) { " + $bakEnt" } else { ' (no entropy file)' }))
    Start-Sleep -Seconds $StepDelaySec

    $restore = {
        Copy-Item -Path $bakCred -Destination $CredPath -Force
        if ($bakEnt) { Copy-Item -Path $bakEnt -Destination $entropy -Force }
        Write-PSMLog -Level WARN -Message "Cred file restored from backup: $CredPath (Vault password unchanged)."
    }

    # 2. New cred file (verified by Update-PSMCredFile).
    $newPwd = New-PSMComponentPassword
    try {
        Update-PSMCredFile -Settings $Settings -CredPath $CredPath -UserName $UserName -Password $newPwd | Out-Null
    }
    catch {
        $msg = $_.Exception.Message
        & $restore
        throw (New-PSMSyncError "CreateCredFile step failed for '$UserName': $msg" $true)
    }
    Start-Sleep -Seconds $StepDelaySec

    # 3. Vault password (verified by Reset-PvwaUserPassword: call result + user state).
    try {
        Reset-PvwaUserPassword -Session $Session -UserName $UserName `
            -NewPassword (ConvertTo-SecureString $newPwd -AsPlainText -Force) | Out-Null
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'answered OK, but the user is now') {
            # Password APPLIED in the Vault: the new cred file matches it - keep it.
            throw (New-PSMSyncError "$msg The new cred file was KEPT (it matches the new Vault password)." $false)
        }
        & $restore
        throw (New-PSMSyncError "Vault password reset failed for '$UserName': $msg" $true)
    }
    Write-PSMLog -Level INFO -Message "Vault: new password set for '$UserName' (cred file and Vault in sync)."
    Start-Sleep -Seconds $StepDelaySec
}

function Start-PSMServiceVerified {
    <#
        Starts the PSM service and VERIFIES it really stays up: waits for
        'Running', lets it settle, then checks it is still running and that
        PSMConsole.log got no authentication/termination error since the start
        (the service can reach Running then die on ITATS004E a few seconds later).
    #>
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $ConsoleLog,
        [int] $StartTimeoutSec = 180,
        [int] $StabilizeSec    = 60
    )
    $linesBefore = if (Test-Path $ConsoleLog) { @(Get-Content -Path $ConsoleLog).Count } else { 0 }
    $newConsoleLines = {
        if (-not (Test-Path $ConsoleLog)) { return @() }
        $all = @(Get-Content -Path $ConsoleLog)
        if ($all.Count -ge $linesBefore) { return @($all | Select-Object -Skip $linesBefore) }
        return $all   # log rotated: read it all
    }
    Write-PSMLog -Level INFO -Message 'Starting the PSM service...'
    try { Start-Service -Name $Name -ErrorAction Stop }
    catch { Write-PSMLog -Level WARN -Message "Start-Service: $($_.Exception.Message) - checking the service state..." }

    $svc = Get-Service -Name $Name
    $deadline = (Get-Date).AddSeconds($StartTimeoutSec)
    while ($svc.Status -ne 'Running' -and (Get-Date) -lt $deadline) {
        if ($svc.Status -eq 'Stopped') { break }
        Start-Sleep -Seconds 5
        $svc.Refresh()
    }
    if ($svc.Status -ne 'Running') {
        $detail = @(& $newConsoleLines | Select-Object -Last 5) -join ' | '
        throw "PSM service did not start (state: $($svc.Status)). PSMConsole.log: $(if ($detail) { $detail } else { 'no new line' })"
    }
    Write-PSMLog -Level INFO -Message "PSM service Running - checking it stays up for $StabilizeSec s..."
    Start-Sleep -Seconds $StabilizeSec
    $svc.Refresh()
    $errors = @(& $newConsoleLines | Where-Object { $_ -match 'ITATS\d+E|PSMSR037E|terminated' })
    if ($svc.Status -ne 'Running' -or $errors.Count -gt 0) {
        $detail = if ($errors.Count -gt 0) { $errors -join ' | ' } else { 'no new line' }
        throw "PSM service did not stay up (state: $($svc.Status)). PSMConsole.log: $detail"
    }
    Write-PSMLog -Level OK -Message "PSM service running and stable ($StabilizeSec s), no authentication error in PSMConsole.log."
}

function Resolve-PSMExistingComponentUser {
    <#
        Handles a NAME COLLISION on the Vault side: the target component name
        (e.g. PSM-<HOST>) already exists, leftover from a previous deployment of
        the SAME server (wiping/reverting the machine never removes the Vault
        users). Such a stale user is exactly what causes the "password mismatch"
        at PSM service restart: the local cred file and the Vault user then come
        from different cycles.

        Resolution driven by settings.psd1 Registration.ExistingAccountAction:
          - Ask (default) : interactive choice (Overwrite recommended);
          - Overwrite     : DELETE the stale user; the freshly registered one is
                            then renamed into its place (cred file keeps its
                            valid secret + the CURRENT registration's Safe
                            memberships) -> most consistent end state;
          - ResetPassword : KEEP the stale user, reset its password (PVWA API)
                            and regenerate the local cred file with it; the
                            freshly registered orphan is deleted. The kept user
                            retains its OLD Safe memberships;
          - Fail          : stop with the manual-cleanup error (historic behavior).

        Returns $true when the collision was fully handled by the password-sync
        (nothing left to rename for this target), $false when the way is clear
        for the normal rename (no collision, or stale user deleted).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory)] $Target,       # @{ CredPath; OldName; NewName }
        [string] $Action = 'Ask',
        [switch] $NonInteractive
    )
    $existing = @(Find-PvwaUser -Session $Session -Search $Target.NewName | Where-Object { $_.username -eq $Target.NewName })
    if ($existing.Count -eq 0) { return $false }   # no collision: normal rename

    Write-PSMLog -Level WARN -Message ("Vault user '$($Target.NewName)' ALREADY exists (leftover from a previous " +
        'installation of this server): the local cred file and this user come from different cycles - ' +
        'this is what causes the logon/password mismatch when the PSM service restarts.')

    if ($Action -eq 'Ask') {
        if ($NonInteractive) {
            throw ("Rename-PSMComponentAccounts: user '$($Target.NewName)' already exists on the Vault side and " +
                   "Registration.ExistingAccountAction='Ask' cannot prompt in NonInteractive mode. Set the policy in " +
                   "settings.psd1 ('Overwrite' | 'ResetPassword' | 'Fail') or run interactively.")
        }
        $choices = [System.Management.Automation.Host.ChoiceDescription[]]@(
            (New-Object System.Management.Automation.Host.ChoiceDescription '&Overwrite',
                ("Delete the existing Vault user '$($Target.NewName)' and rename the freshly registered " +
                 "'$($Target.OldName)' into its place (recommended: keeps the current registration's Safe memberships and cred file)."))
            (New-Object System.Management.Automation.Host.ChoiceDescription '&Password sync',
                ("Keep the existing Vault user '$($Target.NewName)': reset its password and rewrite the local cred file " +
                 "with it; the freshly registered '$($Target.OldName)' is deleted (the kept user retains its OLD Safe memberships)."))
            (New-Object System.Management.Automation.Host.ChoiceDescription '&Abort',
                'Stop the deployment (manual cleanup, historic behavior).')
        )
        $picked = $Host.UI.PromptForChoice("Existing Vault user: $($Target.NewName)",
                     'How should the existing component user be handled?', $choices, 0)
        $Action = @('Overwrite', 'ResetPassword', 'Fail')[$picked]
    }

    switch ($Action) {
        'Overwrite' {
            Remove-PvwaUser -Session $Session -UserName $Target.NewName | Out-Null
            Write-PSMLog -Level OK -Message ("Vault: stale user '$($Target.NewName)' deleted (Overwrite) - " +
                "the freshly registered '$($Target.OldName)' will take its place.")
            return $false   # way clear for the normal rename
        }
        'ResetPassword' {
            # Same verified sequence as after a rename: backup, CreateCredFile, then Vault reset.
            Sync-PSMComponentCredential -Settings $Settings -Session $Session `
                -CredPath $Target.CredPath -UserName $Target.NewName
            try {
                Remove-PvwaUser -Session $Session -UserName $Target.OldName | Out-Null
                Write-PSMLog -Level INFO -Message "Vault: freshly registered orphan '$($Target.OldName)' deleted."
            }
            catch {
                Write-PSMLog -Level WARN -Message ("Orphan '$($Target.OldName)' not deleted ($($_.Exception.Message)) - " +
                    'remove it manually (PVWA > Administration > Users).')
            }
            Write-PSMLog -Level WARN -Message ("'$($Target.NewName)' kept with its OLD Safe memberships: verify they " +
                'still match what the current registration would have granted.')
            return $true    # fully handled: nothing left to rename for this target
        }
        default {
            throw ("Rename-PSMComponentAccounts: user '$($Target.NewName)' ALREADY exists on the Vault side " +
                   "(leftover from a previous installation of this server). Delete it (PVWA/PrivateArk), " +
                   "along with the old orphaned PSMApp_/PSMGw_ users, then relaunch - or set " +
                   "Registration.ExistingAccountAction = 'Overwrite' / 'ResetPassword' to automate it.")
        }
    }
}

function Rename-PSMComponentAccounts {
    <#
        Aligns the PSM component accounts with the team's naming convention
        (procedure previously applied by hand on the existing PSMs, automated here):
          - "App" user PSMApp_<hex>  -> PSM-<HOSTNAME>   (configurable pattern)
          - "Gw"  user PSMGw_<hex>   -> PSMA<HOSTNAME>
        RegisterComponent.exe offers NO naming parameter for PSM: the rename
        therefore happens AFTER the registration, step by step, each step
        verified, with pauses in between:
          1. stop the PSM service (verified stopped), then let the Vault settle;
          per account:
          2. rename of the Vault user (PVWA API), verified by re-reading it;
          3. backup of the cred file and its .entropy (timestamped copies);
          4. new cred file with CreateCredFile and a new password (verified);
          5. Vault password reset through the PVWA API (verified);
             a failure at 4/5 restores the backup and rolls the rename back;
          6. start the PSM service and verify it stays up (no ITATS error).
        basic_psm.ini PSMServerId / PSMServerAdminId: opt-in (RenameServerIds).

        Driven by settings.psd1 Registration.RenameComponents ($true/$false).
        Idempotent: when the cred files already carry the target names, does nothing.
        When the TARGET name already exists on the Vault side (leftover from a
        previous deployment of the same server), the collision is resolved per
        Registration.ExistingAccountAction (Ask/Overwrite/ResetPassword/Fail) -
        see Resolve-PSMExistingComponentUser.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] $Session,     # open PVWA session (Connect-PvwaSession)
        [switch] $NonInteractive             # forbids the 'Ask' collision prompt
    )
    $regCfg = Get-PSMConfigValue -Config $Settings -Key 'Registration'
    if (-not $regCfg -or -not (Get-PSMConfigValue -Config $regCfg -Key 'RenameComponents')) { return $false }
    # Policy when the TARGET name already exists on the Vault side (leftover from
    # a previous deployment of the same server) - see Resolve-PSMExistingComponentUser.
    $existingAction = Get-PSMConfigValue -Config $regCfg -Key 'ExistingAccountAction'
    if (-not $existingAction) { $existingAction = 'Ask' }
    if ($existingAction -notin @('Ask', 'Overwrite', 'ResetPassword', 'Fail')) {
        throw "settings.psd1: Registration.ExistingAccountAction='$existingAction' invalid (expected: Ask | Overwrite | ResetPassword | Fail)."
    }
    # basic_psm.ini PSMServerId/PSMServerAdminId must stay ALIGNED with the "PSM
    # Server" object in PVWA (PVConfiguration), which the REST API cannot rename.
    # Their update is therefore OPT-IN (Registration.RenameServerIds) and must be
    # paired with the manual object rename in PVWA Options (as done in production).
    $renameIds = [bool](Get-PSMConfigValue -Config $regCfg -Key 'RenameServerIds')

    $hostName   = $env:COMPUTERNAME.ToUpper()
    $appPattern = Get-PSMConfigValue -Config $regCfg -Key 'AppUserPattern'
    $gwPattern  = Get-PSMConfigValue -Config $regCfg -Key 'GwUserPattern'
    if (-not $appPattern) { $appPattern = 'PSM-{HOSTNAME}' }
    if (-not $gwPattern)  { $gwPattern  = 'PSMA{HOSTNAME}' }
    $appNew = $appPattern.Replace('{HOSTNAME}', $hostName)
    $gwNew  = $gwPattern.Replace('{HOSTNAME}', $hostName)

    # basic_psm.ini -> cred file paths + IDs to update.
    $iniPath = Join-Path (Get-PSMInstallPaths -Settings $Settings).PsmDir 'basic_psm.ini'
    if (-not (Test-Path $iniPath)) {
        throw "Rename-PSMComponentAccounts: basic_psm.ini not found ($iniPath) - is the PSM installed?"
    }
    $ini = Get-Content -Path $iniPath -Raw
    $credPaths = @{}
    foreach ($k in 'PSMAppCredFile', 'PSMGWCredFile') {
        $m = [regex]::Match($ini, '(?im)^\s*' + $k + '\s*=\s*"?([^"\r\n]+?)"?\s*$')
        if (-not $m.Success) { throw "Rename-PSMComponentAccounts: key '$k' not found in $iniPath." }
        $credPaths[$k] = $m.Groups[1].Value
    }

    # Current names read from the cred files (local source of truth).
    $targets = @(
        @{ CredPath = $credPaths['PSMAppCredFile']; NewName = $appNew; IniKey = 'PSMServerId' }
        @{ CredPath = $credPaths['PSMGWCredFile'];  NewName = $gwNew;  IniKey = 'PSMServerAdminId' }
    )
    foreach ($t in $targets) {
        if (-not (Test-Path $t.CredPath)) { throw "Cred file not found: $($t.CredPath) (registration finished?)" }
        $m = [regex]::Match((Get-Content -Path $t.CredPath -Raw), '(?im)^\s*Username\s*=\s*(.+?)\s*$')
        if (-not $m.Success) { throw "'Username=' line not found in $($t.CredPath)." }
        $t.OldName = $m.Groups[1].Value
    }

    if (-not (@($targets | Where-Object { $_.OldName -cne $_.NewName }))) {
        Write-PSMLog -Level OK -Message "Component accounts already match the convention ($appNew / $gwNew)."
        return $false
    }
    if (-not $PSCmdlet.ShouldProcess("$($targets[0].OldName) -> $appNew ; $($targets[1].OldName) -> $gwNew",
                                     'Rename the PSM component accounts')) { return $false }

    # Pauses between the steps, to leave the Vault and the service time to settle.
    $stepDelaySec   = 5    # between two steps
    $vaultSettleSec = 15   # after the stop, for the Vault to close the component sessions
    $svcName    = 'Cyberark Privileged Session Manager'
    $consoleLog = Join-Path (Get-PSMInstallPaths -Settings $Settings).PsmDir 'Logs\PSMConsole.log'

    # 1. STOP the service, whatever its state (RegisterComponent starts it at the
    #    end of the registration, so it is often still 'StartPending' here: a
    #    component logged on to the Vault keeps the rename from being applied),
    #    and VERIFY it is stopped before touching anything.
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        $deadline = (Get-Date).AddSeconds(180)
        while ($svc.Status -in 'StartPending', 'StopPending', 'ContinuePending', 'PausePending' -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 5
            $svc.Refresh()
        }
        if ($svc.Status -ne 'Stopped') {
            Write-PSMLog -Level INFO -Message "Stopping the PSM service (state: $($svc.Status)) for the component account rename..."
            Stop-Service -Name $svcName -Force
            $deadline = (Get-Date).AddSeconds(120)
            do { Start-Sleep -Seconds 2; $svc.Refresh() } while ($svc.Status -ne 'Stopped' -and (Get-Date) -lt $deadline)
            if ($svc.Status -ne 'Stopped') { throw "PSM service did not stop (state: $($svc.Status)) - nothing was changed." }
        }
        Write-PSMLog -Level INFO -Message "PSM service stopped (verified) - waiting $vaultSettleSec s for the Vault to close its sessions..."
        Start-Sleep -Seconds $vaultSettleSec
    }

    $failure = $null
    try {
        foreach ($t in $targets) {
            if ($t.OldName -cne $t.NewName) {
                # The target name may ALREADY exist on the Vault side (leftover from
                # a previous installation of the SAME server). Resolved per the
                # configured policy - see Resolve-PSMExistingComponentUser.
                $handled = Resolve-PSMExistingComponentUser -Settings $Settings -Session $Session `
                              -Target $t -Action $existingAction -NonInteractive:$NonInteractive
                if (-not $handled) {
                    # 2. RENAME in the Vault, VERIFIED by re-reading the user (up to
                    #    30 s): the PVWA may accept the PUT without applying it.
                    Rename-PvwaUser -Session $Session -UserName $t.OldName -NewUserName $t.NewName | Out-Null
                    $renamed = $false
                    for ($i = 1; $i -le 6 -and -not $renamed; $i++) {
                        $found   = @(Find-PvwaUser -Session $Session -Search $t.NewName)
                        $renamed = [bool]@($found | Where-Object { $_.username -eq $t.NewName }).Count
                        Write-PSMLog -Level INFO -Message ("[PVWA] rename check $i/6: search '$($t.NewName)' -> $($found.Count) result(s): " +
                            ((@($found | ForEach-Object { "$($_.username) (id $($_.id))" })) -join ', '))
                        if (-not $renamed) { Start-Sleep -Seconds 5 }
                    }
                    if (-not $renamed) {
                        throw ("Vault rename of '$($t.OldName)' to '$($t.NewName)' was accepted by the PVWA but NOT applied " +
                               "(user still '$($t.OldName)'). Cred file left untouched. Rename the user in PVWA/PrivateArk " +
                               'with the PSM service stopped, then relaunch.')
                    }
                    Write-PSMLog -Level INFO -Message "Vault: user '$($t.OldName)' renamed to '$($t.NewName)' (verified)."
                    Start-Sleep -Seconds $stepDelaySec

                    # 3-5. Backup of the cred file, new cred file, Vault password -
                    #      each step verified (Sync-PSMComponentCredential).
                    try {
                        Sync-PSMComponentCredential -Settings $Settings -Session $Session `
                            -CredPath $t.CredPath -UserName $t.NewName -StepDelaySec $stepDelaySec
                    }
                    catch {
                        $syncError = $_
                        if ($syncError.Exception.Data['LocalUnchanged']) {
                            # The cred file is back under the OLD name: put the Vault
                            # name back too, so that both match again.
                            $back = $false
                            try {
                                Rename-PvwaUser -Session $Session -UserName $t.NewName -NewUserName $t.OldName | Out-Null
                                Start-Sleep -Seconds $stepDelaySec
                                $back = [bool]@(Find-PvwaUser -Session $Session -Search $t.OldName |
                                                Where-Object { $_.username -eq $t.OldName }).Count
                            }
                            catch { Write-PSMLog -Level ERROR -Message "Vault rename rollback call failed: $($_.Exception.Message)" }
                            if ($back) {
                                Write-PSMLog -Level WARN -Message "Vault: rename rolled back ('$($t.NewName)' -> '$($t.OldName)', verified) to match the unchanged cred file."
                            }
                            else {
                                Write-PSMLog -Level ERROR -Message ("Vault rename rollback NOT applied: the Vault user is '$($t.NewName)' but the " +
                                    "cred file still says '$($t.OldName)' - rename the user back in PVWA before relaunching.")
                            }
                        }
                        throw $syncError
                    }
                }
            }
            # basic_psm.ini: matching ID (OPT-IN, see RenameServerIds above).
            if ($renameIds) {
                if ($ini -notmatch ('(?im)^\s*' + $t.IniKey + '\s*=\s*"')) {
                    throw "Rename-PSMComponentAccounts: key '$($t.IniKey)' not found in $iniPath."
                }
                $ini = ([regex]('(?im)^(\s*' + $t.IniKey + '\s*=\s*")[^"]*(")')).Replace($ini, ('${1}' + $t.NewName + '${2}'), 1)
            }
        }
        if ($renameIds) {
            $iniBackup = "$iniPath.orig"
            if (-not (Test-Path $iniBackup)) { Copy-Item -Path $iniPath -Destination $iniBackup -Force }
            Set-Content -Path $iniPath -Value $ini -NoNewline
            Write-PSMLog -Level WARN -Message ("basic_psm.ini updated (PSMServerId=$appNew, PSMServerAdminId=$gwNew). " +
                "REQUIRED PAIRED STEP: rename the PSM server object ID accordingly in PVWA " +
                "(Administration > Options > Privileged Session Management > Configured PSM Servers), " +
                "otherwise the PSM will not find its server configuration.")
        }
        else {
            Write-PSMLog -Level INFO -Message ("basic_psm.ini PSMServerId/PSMServerAdminId left unchanged " +
                "(Registration.RenameServerIds=false): they stay aligned with the PSM server object in PVWA Options.")
        }
    }
    catch { $failure = $_ }

    # 6. START the service and VERIFY it stays up. Also attempted after a failure
    #    (the PSM may still run under its previous accounts); the original error
    #    is then re-raised.
    if ($svc) {
        if ($failure) {
            try { Start-PSMServiceVerified -Name $svcName -ConsoleLog $consoleLog }
            catch { Write-PSMLog -Level ERROR -Message "PSM service after the failure: $($_.Exception.Message)" }
            throw $failure
        }
        Start-PSMServiceVerified -Name $svcName -ConsoleLog $consoleLog
    }
    elseif ($failure) { throw $failure }
    Write-PSMLog -Level OK -Message "Component accounts renamed: $appNew / $gwNew."
    return $true
}

Export-ModuleMember -Function Invoke-PSMRegister, Rename-PSMComponentAccounts, `
                              Resolve-PSMExistingComponentUser, New-PSMComponentPassword, Update-PSMCredFile
