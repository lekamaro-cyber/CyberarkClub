<#
.SYNOPSIS
    "Hardening" phase: CyberArk "Hardening" stage via Execute-Stage.ps1.

.DESCRIPTION
    The Hardening stage applies the CyberArk hardening and the AppLocker rules
    (RunTheHardeningScript, SetupAppLockerRules...). The in-house customization
    lives in HardeningConfig.xml and the CSV files of the media's Hardening folder
    (PSMConfigureRemoteSessionControl.csv, PSMHideDrives.csv, etc.), filled in by
    the team - no separate AppLocker policy to maintain on our side.

    Returns the Invoke-PSMStage result object; the orchestrator handles the reboot.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Set-PSMConnectAccounts {
    <#
        Injects the zone's DOMAIN PSMConnect / PSMAdminConnect accounts into the
        VARIABLES at the top of the CyberArk hardening scripts (files GENERATED AT
        INSTALL TIME under <InstallDir>\PSM\Hardening, NOT in the media):
          - PSMHardening.ps1          : $PSM_CONNECT_USER / $PSM_ADMIN_CONNECT_USER
          - PSMConfigureAppLocker.ps1 : $PSM_CONNECT      / $PSM_ADMIN_CONNECT
        (configurable mapping: settings.psd1 Hardening.ScriptAccountVariables).

        Patched IN PLACE with a '.orig' backup made only once; we ALWAYS start
        over from the original -> replayable, no stacking. Passwords are NOT
        touched (PSM Safe on the Vault side).

        INACTIVE when the zone provides no account: does nothing and returns $false.
        Returns $true when at least one file was patched.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        $ZoneConfig
    )
    if (-not $ZoneConfig) { return $false }

    $psmConnect = Get-PSMConfigValue -Config $ZoneConfig -Key 'PSMConnectUserName'
    $psmAdmin   = Get-PSMConfigValue -Config $ZoneConfig -Key 'PSMAdminConnectUserName'
    if (-not $psmConnect -and -not $psmAdmin) { return $false }   # nothing to inject

    $h = Get-PSMConfigValue -Config $Settings -Key 'Hardening'
    if (-not $h) { throw "settings.psd1: 'Hardening' block missing (zone accounts provided)." }
    $varMap = Get-PSMConfigValue -Config $h -Key 'ScriptAccountVariables'
    if ($null -eq $varMap) { throw "settings.psd1: Hardening.ScriptAccountVariables not set (zone accounts provided)." }
    if ($varMap.Keys.Count -eq 0) {
        # DELIBERATELY empty mapping (14.0 flow): the framework's Hardening step
        # dot-sources Consts.ps1 - which Set-PSMAutomationConsts already patches -
        # and passes the accounts to PSMHardening.ps1 as PARAMETERS
        # (-connectionUserName/-connectionAdminUserName...). Nothing to patch here.
        Write-PSMLog -Level INFO -Message 'Hardening.ScriptAccountVariables is empty: accounts flow through Consts.ps1 (14.0 flow), no hardening script patch needed.'
        return $false
    }

    # Explicit Hardening folder when provided, otherwise DERIVED from Install.InstallDir.
    $hardDir = Get-PSMConfigValue -Config $h -Key 'HardeningDir'
    if (-not $hardDir) { $hardDir = (Get-PSMInstallPaths -Settings $Settings).HardeningDir }

    $patched = $false
    foreach ($fileName in $varMap.Keys) {
        $filePath = Join-Path $hardDir $fileName
        $map      = $varMap[$fileName]

        # Variables to write in THIS file (only the provided accounts).
        $todo = @()
        $vConnect = Get-PSMConfigValue -Config $map -Key 'Connect'
        $vAdmin   = Get-PSMConfigValue -Config $map -Key 'AdminConnect'
        if ($psmConnect -and $vConnect) { $todo += ,@($vConnect, $psmConnect) }
        if ($psmAdmin   -and $vAdmin)   { $todo += ,@($vAdmin,   $psmAdmin) }
        if (-not $todo) { continue }

        if (-not $PSCmdlet.ShouldProcess($filePath, 'Patch the PSM account variables (domain)')) {
            Write-PSMLog -Level INFO -Message "WhatIf: '$fileName' would be patched (domain accounts)."
            continue
        }
        if (-not (Test-Path $filePath)) {
            throw "'$fileName' not found: $filePath (generated at INSTALL time; check Install.InstallDir / Hardening.HardeningDir)."
        }

        # Back up the original only once; ALWAYS start over from the original.
        $backup = "$filePath.orig"
        if (-not (Test-Path $backup)) { Copy-Item -Path $filePath -Destination $backup -Force }
        $content = Get-Content -Path $backup -Raw

        foreach ($t in $todo) {
            $varName = $t[0]; $value = [string]$t[1]
            # First assignment of the variable: $VAR = "..." or '...' (quote preserved).
            $pattern = '(?m)^(\s*\$' + [regex]::Escape($varName) + '\s*=\s*)(["''])(.*?)\2'
            $rx = [regex]$pattern
            if (-not $rx.IsMatch($content)) {
                # Diagnostic aid: lists the file's candidate assignments.
                $cands = ([regex]::Matches($content, '(?m)^\s*\$(\w*PSM\w*)\s*=') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique) -join ', '
                throw ("'$fileName': variable `$$varName not found. Candidate variables: $cands. " +
                       'Adjust settings.psd1 Hardening.ScriptAccountVariables.')
            }
            $safeValue = $value.Replace('$', '$$')   # neutralizes regex substitutions
            $content   = $rx.Replace($content, ('${1}${2}' + $safeValue + '${2}'), 1)
            Write-PSMLog -Level INFO -Message "'$fileName': `$$varName <- '$value'"
        }

        Set-Content -Path $filePath -Value $content -NoNewline
        Write-PSMLog -Level INFO -Message "'$fileName' patched (domain accounts) -> $filePath"
        $patched = $true
    }
    return $patched
}

function Invoke-PSMHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        $ZoneConfig     # zone's PSMConnect/PSMAdminConnect accounts (optional)
    )
    # Domain session accounts: in-place patch of the PSMHardening.ps1 /
    # PSMConfigureAppLocker.ps1 variables BEFORE running the stage
    # (the RunHardening / RunApplocker steps re-read these scripts afterwards).
    Set-PSMConnectAccounts -Settings $Settings -ZoneConfig $ZoneConfig | Out-Null

    $stage = Resolve-PSMStageConfig -Settings $Settings -SourcesRoot $SourcesRoot -StageKey 'Hardening'
    return Invoke-PSMStage -StageName 'Hardening' `
                           -ExecuteStagePath $stage.ExecuteStage `
                           -ConfigFilePath   $stage.ConfigFilePath
}

Export-ModuleMember -Function Invoke-PSMHardening, Set-PSMConnectAccounts
