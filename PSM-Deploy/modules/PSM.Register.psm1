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
    # Vault address driven by the zone: DYNAMIC injection into a patched copy of
    # RegistrationConfig.xml (media intact), through the generic stage engine.
    # The field's location in the XML is configurable (settings.psd1 Registration.*).
    $extra = $null
    if ($VaultAddress) {
        $xpath = $Settings.Registration.VaultAddressXPath
        $attr  = $Settings.Registration.VaultAddressAttribute
        if (-not $xpath) {
            throw "settings.psd1: Registration.VaultAddressXPath not set."
        }
        $extra = @{ $xpath = @{ Attribute = $attr; Value = $VaultAddress } }
    }
    else {
        Write-PSMLog -Level WARN -Message "No zone Vault address (VaultAddress): using the media's RegistrationConfig.xml as-is."
    }

    $stage = Resolve-PSMStageConfig -Settings $Settings -SourcesRoot $SourcesRoot `
                -StageKey 'Registration' -ExtraInjections $extra

    $securePwd = if ($InstallCredential) { $InstallCredential.Password } else { $null }

    return Invoke-PSMStage -StageName 'Registration' `
                           -ExecuteStagePath $stage.ExecuteStage `
                           -ConfigFilePath   $stage.ConfigFilePath `
                           -VaultPassword    $securePwd
}

function Rename-PSMComponentAccounts {
    <#
        Aligns the PSM component accounts with the team's naming convention
        (procedure previously applied by hand on the existing PSMs, automated here):
          - "App" user PSMApp_<hex>  -> PSM-<HOSTNAME>   (configurable pattern)
          - "Gw"  user PSMGw_<hex>   -> PSMA<HOSTNAME>
        RegisterComponent.exe offers NO naming parameter for PSM: the rename
        therefore happens AFTER the registration, in 4 steps:
          1. rename of the Vault users (PVWA API, admin session reused);
          2. update of the Username= line in the cred files (the password does not
             change, the encrypted Secret stays valid; .orig backup);
          3. update of basic_psm.ini (PSMServerId / PSMServerAdminId);
          4. PSM service stopped during the operation then restarted if it was running.

        Driven by settings.psd1 Registration.RenameComponents ($true/$false).
        Idempotent: when the cred files already carry the target names, does nothing.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] $Session      # open PVWA session (Connect-PvwaSession)
    )
    $regCfg = Get-PSMConfigValue -Config $Settings -Key 'Registration'
    if (-not $regCfg -or -not (Get-PSMConfigValue -Config $regCfg -Key 'RenameComponents')) { return $false }
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

    # Service stopped during the operation (it authenticates with the cred files).
    $svc = Get-Service -Name 'Cyberark Privileged Session Manager' -ErrorAction SilentlyContinue
    $wasRunning = $svc -and $svc.Status -eq 'Running'
    if ($wasRunning) {
        Write-PSMLog -Level INFO -Message 'Stopping the PSM service for the component account rename...'
        Stop-Service -Name 'Cyberark Privileged Session Manager' -Force
    }

    foreach ($t in $targets) {
        if ($t.OldName -cne $t.NewName) {
            # 0) The target name must not already exist on the Vault side (leftover
            #    from a previous installation of the SAME server: wiping the machine
            #    does not remove the Vault users).
            $existing = @(Find-PvwaUser -Session $Session -Search $t.NewName | Where-Object { $_.username -eq $t.NewName })
            if ($existing.Count -gt 0) {
                throw ("Rename-PSMComponentAccounts: user '$($t.NewName)' ALREADY exists on the Vault side " +
                       "(leftover from a previous installation of this server). Delete it (PVWA/PrivateArk), " +
                       "along with the old orphaned PSMApp_/PSMGw_ users, then relaunch.")
            }
            # 1) Vault side (PVWA API).
            Rename-PvwaUser -Session $Session -UserName $t.OldName -NewUserName $t.NewName | Out-Null
            Write-PSMLog -Level INFO -Message "Vault: user '$($t.OldName)' renamed to '$($t.NewName)'."
            # 2) Cred file: Username= line (password unchanged), .orig backup.
            $backup = "$($t.CredPath).orig"
            if (-not (Test-Path $backup)) { Copy-Item -Path $t.CredPath -Destination $backup -Force }
            $raw = Get-Content -Path $t.CredPath -Raw
            $raw = ([regex]'(?im)^(\s*Username\s*=\s*).+?\s*$').Replace($raw, ('${1}' + $t.NewName), 1)
            Set-Content -Path $t.CredPath -Value $raw -NoNewline
            Write-PSMLog -Level INFO -Message "Cred file updated: $($t.CredPath) (Username=$($t.NewName))."
        }
        # 3) basic_psm.ini: matching ID (OPT-IN, see RenameServerIds above).
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

    if ($wasRunning) {
        Start-Service -Name 'Cyberark Privileged Session Manager'
        Write-PSMLog -Level INFO -Message 'PSM service restarted.'
    }
    Write-PSMLog -Level OK -Message "Component accounts renamed: $appNew / $gwNew."
    return $true
}

Export-ModuleMember -Function Invoke-PSMRegister, Rename-PSMComponentAccounts
