<#
.SYNOPSIS
    "Stage-by-stage" driving of the CyberArk automation framework
    (InstallationAutomation\Execute-Stage.ps1).

.DESCRIPTION
    Our orchestrator calls CyberArk stage by stage (Installation,
    PostInstallation, Registration, Hardening...). Each stage is described by
    its XML config file (filled in by the team). Execute-Stage.ps1:
      - is called with  -configFilePath <xml> -silentMode Silent -displayJson
      - accepts the Vault password via -spwdObj (SecureString) [Registration]
      - returns JSON: { isSucceeded (0=OK,1=Warn,2=Err), errorData, logPath,
        restartRequired }
      - handles its OWN per-step recovery (Recovery registry); it is up to the
        CALLER to reboot when restartRequired = $true (then resumed through our
        AtLogOn task which reruns the same stage).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PSMStagePaths {
    <#
        Builds the CyberArk framework paths for a given stage
        (media root -> InstallationAutomation -> Execute-Stage.ps1 + XML config).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        [Parameter(Mandatory)] [string] $StageKey
    )
    $mediaPsm = Join-Path $SourcesRoot $Settings.Install.MediaRelativePath
    $iaRoot   = Join-Path $mediaPsm  $Settings.Install.InstallationAutomationSubPath
    $execute  = Join-Path $iaRoot    'Execute-Stage.ps1'

    $rel = $Settings.Install.Stages[$StageKey]
    if (-not $rel) {
        throw "No config file declared for stage '$StageKey' (settings.psd1 Install.Stages)."
    }
    $config = Join-Path $iaRoot $rel

    return [pscustomobject]@{
        MediaPsm     = $mediaPsm
        IaRoot       = $iaRoot
        ExecuteStage = $execute
        Config       = $config
    }
}

function Update-PSMStageXml {
    <#
        Injects values (from our config) into a CyberArk stage *Config.xml and
        saves a patched COPY under state\config\<Stage>\.
        The media stays intact -> dropping in a new source requires no manual
        editing of the XML files.

        -Injections : table @{ '<xpath>' = @{ Attribute='Value'; Value='...' } }
                      (empty Attribute => the node's InnerText is written).
        Returns the path of the patched copy to pass to Execute-Stage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]    $SourceConfigPath,
        [Parameter(Mandatory)] [hashtable] $Injections,
        [Parameter(Mandatory)] [string]    $StateDir,
        [Parameter(Mandatory)] [string]    $StageName
    )
    if (-not (Test-Path $SourceConfigPath)) {
        throw "'$StageName' config not found: $SourceConfigPath (check the media)."
    }

    [xml]$doc = Get-Content -Path $SourceConfigPath -Raw

    foreach ($xpath in $Injections.Keys) {
        $spec  = $Injections[$xpath]
        $value = [string]$spec.Value
        $node  = $doc.SelectSingleNode($xpath)
        if (-not $node) {
            # Diagnostic aid: lists Steps and Parameters to help adjust the XPath
            # (reminder: XPath is case-sensitive -> 'Step'/'Parameter').
            $steps  = ($doc.SelectNodes('//Step')      | ForEach-Object { $_.Name }) -join ', '
            $params = ($doc.SelectNodes('//Parameter') | ForEach-Object { $_.Name }) -join ', '
            throw ("'$StageName' config: node not found (XPath: $xpath - mind the case). " +
                   "Available Steps: $steps. Available Parameters: $params. Adjust settings.psd1.")
        }
        if ($spec.Attribute) { [void]$node.SetAttribute($spec.Attribute, $value) }
        else                 { $node.InnerText = $value }
        Write-PSMLog -Level INFO -Message "'$StageName' config: '$xpath' <- '$value'"
    }

    $outDir = Join-Path $StateDir (Join-Path 'config' $StageName)
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $outXml = Join-Path $outDir (Split-Path $SourceConfigPath -Leaf)
    $doc.Save($outXml)
    Write-PSMLog -Level INFO -Message "'$StageName' config patched -> $outXml"
    return $outXml
}

function Set-PSMAutomationConsts {
    <#
        Propagates the zone's DOMAIN PSMConnect / PSMAdminConnect accounts into the
        media's InstallationAutomation\Consts.ps1:
            Set-Variable PSM_CONNECT       -value "PSMConnect"
            Set-Variable PSM_ADMIN_CONNECT -value "PSMAdminConnect"
        These constants are consumed by the automation steps themselves
        (ConfigureOutOfDomainPSMServer, EnableUsersToPrintPSMSessions...).

        Only exception to the "media intact" principle: Consts.ps1 is loaded by the
        framework from ITS OWN folder (no -configFilePath to redirect it to a copy).
        Patched IN PLACE with a '.orig' backup made only once; we ALWAYS start over
        from the original -> replayable, and a NEWLY dropped source is re-patched
        automatically (still zero manual editing).

        INACTIVE when the zone provides no account: returns $false without doing anything.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        $ZoneConfig
    )
    if (-not $ZoneConfig) { return $false }
    $psmConnect = Get-PSMConfigValue -Config $ZoneConfig -Key 'PSMConnectUserName'
    $psmAdmin   = Get-PSMConfigValue -Config $ZoneConfig -Key 'PSMAdminConnectUserName'
    if (-not $psmConnect -and -not $psmAdmin) { return $false }

    $mediaPsm = Join-Path $SourcesRoot $Settings.Install.MediaRelativePath
    $path     = Join-Path (Join-Path $mediaPsm $Settings.Install.InstallationAutomationSubPath) 'Consts.ps1'

    if (-not $PSCmdlet.ShouldProcess($path, 'Patch Consts.ps1 (domain PSM accounts)')) {
        Write-PSMLog -Level INFO -Message "WhatIf: Consts.ps1 would be patched (domain accounts)."
        return $false
    }
    if (-not (Test-Path $path)) {
        throw "Consts.ps1 not found: $path (check the media under media\PSM)."
    }

    # Back up the original only once; ALWAYS start over from the original.
    $backup = "$path.orig"
    if (-not (Test-Path $backup)) { Copy-Item -Path $path -Destination $backup -Force }
    $content = Get-Content -Path $backup -Raw

    $todo = @()
    if ($psmConnect) { $todo += ,@('PSM_CONNECT',       $psmConnect) }
    if ($psmAdmin)   { $todo += ,@('PSM_ADMIN_CONNECT', $psmAdmin) }
    foreach ($t in $todo) {
        $varName = $t[0]; $value = [string]$t[1]
        $rx = [regex]('(?im)^(\s*Set-Variable\s+' + [regex]::Escape($varName) + '\s+-value\s+)(["''])(.*?)\2')
        if (-not $rx.IsMatch($content)) {
            $cands = ([regex]::Matches($content, '(?im)^\s*Set-Variable\s+(\w+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique) -join ', '
            throw "Consts.ps1: 'Set-Variable $varName' not found. Candidate variables: $cands."
        }
        $content = $rx.Replace($content, ('${1}${2}' + $value.Replace('$', '$$') + '${2}'), 1)
        Write-PSMLog -Level INFO -Message "Consts.ps1: $varName <- '$value'"
    }

    Set-Content -Path $path -Value $content -NoNewline
    Write-PSMLog -Level INFO -Message "Consts.ps1 patched (domain accounts) -> $path"
    return $true
}

function Resolve-PSMStageConfig {
    <#
        Single entry point that returns a CyberArk stage's paths READY to be
        passed to Invoke-PSMStage:
          - resolves Execute-Stage.ps1 + the media's *Config.xml (Get-PSMStagePaths);
          - when injections are defined for this stage (STATIC values from
            settings.psd1 Install.Injections[<StageKey>], merged with the DYNAMIC
            values passed via -ExtraInjections), patches a COPY under
            state\config\<Stage>\ (media intact) via Update-PSMStageXml;
          - otherwise returns the media's XML as-is (historical behavior).

        -ExtraInjections : dynamic injections (e.g. the zone's Vault address),
                           same shape as Update-PSMStageXml (@{ '<xpath>' = @{ Attribute; Value } }).
                           They win over static injections on the same XPath.
        Returns [pscustomobject]@{ ExecuteStage; ConfigFilePath }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        [Parameter(Mandatory)] [string] $StageKey,
        [hashtable] $ExtraInjections
    )
    $paths      = Get-PSMStagePaths -Settings $Settings -SourcesRoot $SourcesRoot -StageKey $StageKey
    $configPath = $paths.Config

    # Static (optional) injections declared in settings.psd1.
    $injections = @{}
    $staticSet = $null
    if ($Settings.Install.PSObject.Properties.Name -contains 'Injections') {
        $staticSet = $Settings.Install.Injections
    }
    elseif ($Settings.Install -is [hashtable] -and $Settings.Install.ContainsKey('Injections')) {
        $staticSet = $Settings.Install.Injections
    }
    if ($staticSet -and $staticSet[$StageKey]) {
        foreach ($xpath in $staticSet[$StageKey].Keys) {
            $injections[$xpath] = $staticSet[$StageKey][$xpath]
        }
    }

    # Dynamic injections (win on XPath conflicts).
    if ($ExtraInjections) {
        foreach ($xpath in $ExtraInjections.Keys) {
            $injections[$xpath] = $ExtraInjections[$xpath]
        }
    }

    if ($injections.Count -gt 0) {
        $configPath = Update-PSMStageXml -SourceConfigPath $paths.Config `
                        -Injections $injections `
                        -StateDir   (Get-PSMStateDir) `
                        -StageName  $StageKey
    }

    return [pscustomobject]@{
        ExecuteStage   = $paths.ExecuteStage
        ConfigFilePath = $configPath
    }
}

function Invoke-PSMStage {
    <#
        Runs a CyberArk stage through Execute-Stage.ps1 and returns an object:
          { StageName, Succeeded, RestartRequired, LogPath, ErrorData, Raw }
        Honors -WhatIf (runs nothing, returns a neutral result).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $StageName,
        [Parameter(Mandatory)] [string] $ExecuteStagePath,
        [Parameter(Mandatory)] [string] $ConfigFilePath,
        [securestring] $VaultPassword
    )

    if (-not (Test-Path $ExecuteStagePath)) {
        throw "Execute-Stage.ps1 not found: $ExecuteStagePath (check the media under media\PSM)."
    }
    if (-not (Test-Path $ConfigFilePath)) {
        throw "'$StageName' stage config not found: $ConfigFilePath (to be filled in by the team)."
    }

    if (-not $PSCmdlet.ShouldProcess("CyberArk stage '$StageName'", 'Run Execute-Stage.ps1')) {
        return [pscustomobject]@{
            StageName = $StageName; Succeeded = $true; RestartRequired = $false
            LogPath = $null; ErrorData = $null; Raw = $null; WhatIf = $true
        }
    }

    Write-PSMLog -Level INFO -Message "CyberArk stage '$StageName': running (Execute-Stage.ps1)..."

    $params = @{
        configFilePath = $ConfigFilePath
        silentMode     = 'Silent'
        displayJson    = $true
    }
    if ($VaultPassword) { $params['spwdObj'] = $VaultPassword }

    # Execute-Stage.ps1 relies on its own folder (stage modules).
    $iaDir = Split-Path $ExecuteStagePath -Parent
    Push-Location $iaDir
    try {
        # IMPORTANT: CyberArk's scripts are NOT written for StrictMode.
        # Our modules enable it (Latest) and the child script would inherit it,
        # causing errors (NullReference / missing properties). Disable it for the
        # child call (scope local to this function).
        Set-StrictMode -Off
        $raw = & $ExecuteStagePath @params
    }
    catch {
        $cyberLog = Get-ChildItem "$env:windir\Temp\PSM$StageName-*.log" -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $hint = if ($cyberLog) { " CyberArk log: $($cyberLog.FullName)" } else { '' }
        throw "Stage '$StageName': Execute-Stage.ps1 threw an exception: $($_.Exception.Message).$hint"
    }
    finally {
        Pop-Location
    }

    # Execute-Stage returns its result as JSON (via 'return ... | ConvertTo-Json').
    $text   = ($raw | Out-String).Trim()
    $result = $null
    try {
        $result = $text | ConvertFrom-Json
    }
    catch {
        $m = [regex]::Match($text, '(?s)\{.*\}')
        if ($m.Success) { $result = $m.Value | ConvertFrom-Json }
    }
    if (-not $result) {
        throw "Stage '$StageName': unreadable JSON result from Execute-Stage. Raw output: $text"
    }

    # isSucceeded: 0=Success, 1=Warning, 2=Error
    $succeeded = ($result.isSucceeded -eq 0) -or ($result.isSucceeded -eq 1)

    if ($result.logPath) {
        Write-PSMLog -Level INFO -Message "Stage '$StageName' - CyberArk log: $($result.logPath)"
    }
    if ($result.isSucceeded -eq 1) {
        Write-PSMLog -Level WARN -Message "Stage '$StageName' completed with warning(s) - see the CyberArk log."
    }
    if (-not $succeeded) {
        Write-PSMLog -Level ERROR -Message "Stage '$StageName' failed: $($result.errorData)"
    }

    return [pscustomobject]@{
        StageName       = $StageName
        Succeeded       = $succeeded
        RestartRequired = [bool]$result.restartRequired
        LogPath         = $result.logPath
        ErrorData       = $result.errorData
        Raw             = $result
    }
}

Export-ModuleMember -Function Get-PSMStagePaths, Resolve-PSMStageConfig, Invoke-PSMStage, Update-PSMStageXml, Set-PSMAutomationConsts
