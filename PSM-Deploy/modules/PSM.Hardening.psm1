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

function Merge-PSMAppLockerConfig {
    <#
        AppLocker exceptions, ADDED to the file in place on this server:
        <PSM>\Hardening\PSMConfigureAppLocker.xml (CyberArk's default after an
        install or upgrade, or a file already customized by hand). That file is
        never rebuilt: nothing in it is removed or changed. Every <Application>
        of applocker\PSMConfigureAppLocker.xml (sources; it may be a complete
        production file) that the file does not have yet - same Type + Path,
        whatever the Name or Method - is appended to it, preceded by a
        <!-- custom --> comment. An entry whose file is missing on this server is
        left out with an ALERT (the CyberArk AppLocker script would fail on it).
        Called right before the Hardening stage (its RunApplocker step applies the
        file); the file is kept as .<stamp>.bak before a change. Nothing to add =
        nothing written. No custom file, or no <Application> in it: nothing done.
        Returns OK | CHANGED | WHATIF | SKIPPED.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        [string] $PsmDir   # empty -> the installed PSM's folder (service), else derived from settings
    )
    $customPath = Join-Path $SourcesRoot 'applocker\PSMConfigureAppLocker.xml'
    if (-not (Test-Path -LiteralPath $customPath)) {
        Write-PSMLog -Level INFO -Message "AppLocker: no $customPath - PSMConfigureAppLocker.xml of the server left as is."
        return 'SKIPPED'
    }
    [xml]$custom = Get-Content -LiteralPath $customPath -Raw
    $customApps = @($custom.SelectNodes('//Application'))
    if (-not $customApps) {
        Write-PSMLog -Level INFO -Message "AppLocker: no <Application> entry in $customPath - PSMConfigureAppLocker.xml of the server left as is."
        return 'SKIPPED'
    }

    if (-not $PsmDir) { $PsmDir = Get-PSMInstalledPsmDir -Settings $Settings }
    if (-not $PsmDir) { $PsmDir = (Get-PSMInstallPaths -Settings $Settings).PsmDir }
    $target = Join-Path $PsmDir 'Hardening\PSMConfigureAppLocker.xml'
    if (-not (Test-Path -LiteralPath $target)) {
        throw "AppLocker: $target not found (laid down by the PSM installer) - is the PSM installed? Nothing changed."
    }
    # Whitespace kept: the file in place is only appended to, its layout untouched.
    $doc = New-Object System.Xml.XmlDocument
    $doc.PreserveWhitespace = $true
    $doc.Load($target)
    $inPlace = @($doc.SelectNodes('//Application'))
    if (-not $inPlace) { throw "AppLocker: $target has no <Application> entry - is it the CyberArk PSMConfigureAppLocker.xml? Nothing changed." }

    $keyOf = { param($n) '{0}|{1}' -f ([string]$n.GetAttribute('Type')).Trim().ToLowerInvariant(),
                                      ([string]$n.GetAttribute('Path')).Trim().TrimEnd('\').ToLowerInvariant() }
    $known = @{}
    foreach ($n in $inPlace) { $known[(& $keyOf $n)] = $true }
    $todo = @(); $already = 0; $missing = @()
    foreach ($n in $customApps) {
        $k = & $keyOf $n
        if ($known.ContainsKey($k)) { $already++; continue }
        $path = [Environment]::ExpandEnvironmentVariables(([string]$n.GetAttribute('Path')).Trim())
        if ($path -and $path -notmatch '[*?]' -and -not (Test-Path -LiteralPath $path)) {
            $missing += "$($n.GetAttribute('Name')): $path"
            continue
        }
        $known[$k] = $true
        $todo += $n
    }

    Write-PSMLog -Level INFO -Message ("AppLocker: $target ($($inPlace.Count) entries) vs $customPath ($($customApps.Count) entries): " +
        "$($todo.Count) to add$(if ($todo) { ' (' + (($todo | ForEach-Object { $_.GetAttribute('Name') }) -join ', ') + ')' }), " +
        "$already already there, $($missing.Count) left out.")
    if ($missing) {
        Write-PSMAlert -Title 'APPLOCKER EXCEPTIONS LEFT OUT' -Lines (@(
            "Entries of $customPath whose file does not exist on this server (NOT allowed by AppLocker):") +
            @($missing | ForEach-Object { "  $_" }) + @(
            'Install the software at that path, or fix the path in applocker\PSMConfigureAppLocker.xml,',
            "then: .\Deploy-PSM.ps1 -Zone <zone> -RedoHardening"))
    }

    return Invoke-IdempotentStep -Name "AppLocker exceptions added to $target" `
        -Test { $todo.Count -eq 0 } `
        -Action {
            # Indentation of the existing entries; inserted before the closing tag's line break.
            $first  = $inPlace[0]
            $indent = if ($first.PreviousSibling -and $first.PreviousSibling.NodeType -eq 'Whitespace') { $first.PreviousSibling.Value } else { "`r`n    " }
            foreach ($n in $todo) {
                # Same parent element as in our file when the file has it (e.g. AllowedApplications).
                $parent = @($doc.GetElementsByTagName($n.ParentNode.LocalName))[0]
                if (-not $parent) { $parent = $first.ParentNode }
                $anchor = $parent.LastChild
                if (-not ($anchor -and $anchor.NodeType -eq 'Whitespace')) { $anchor = $null }
                foreach ($new in @($doc.CreateWhitespace($indent), $doc.CreateComment(' custom '),
                                   $doc.CreateWhitespace($indent), $doc.ImportNode($n, $true))) {
                    if ($anchor) { [void]$parent.InsertBefore($new, $anchor) } else { [void]$parent.AppendChild($new) }
                }
            }
            Copy-Item -LiteralPath $target -Destination ('{0}.{1}.bak' -f $target, (Get-Date -Format 'yyyyMMdd-HHmmss')) -Force
            $doc.Save($target)
        } -WhatIf:$WhatIfPreference
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

    # Our missing AppLocker exceptions added to the server's file BEFORE the stage
    # (its RunApplocker step applies <PSM>\Hardening\PSMConfigureAppLocker.xml).
    Merge-PSMAppLockerConfig -Settings $Settings -SourcesRoot $SourcesRoot -WhatIf:$WhatIfPreference | Out-Null

    $stage = Resolve-PSMStageConfig -Settings $Settings -SourcesRoot $SourcesRoot -StageKey 'Hardening'
    return Invoke-PSMStage -StageName 'Hardening' `
                           -ExecuteStagePath $stage.ExecuteStage `
                           -ConfigFilePath   $stage.ConfigFilePath
}

Export-ModuleMember -Function Invoke-PSMHardening, Set-PSMConnectAccounts, Merge-PSMAppLockerConfig
