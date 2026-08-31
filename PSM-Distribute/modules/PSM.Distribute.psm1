<#
.SYNOPSIS
    Source distribution engine: staging composition (base + per-type overlay)
    and SMB push to the PSM servers. Runs ON the CPM.

.DESCRIPTION
    The PSM sources cannot be ONE tree: installers\ binaries and
    config\software.psd1 differ per server type (PRD / DRP / PREPRD / PRDNPR).
    Composition model:
      base (PSM-Deploy, common)  +  overlays\<TYPE> (the DELTA only)
        -> staging\<TYPE> (complete tree, what the servers of that type receive)
    An overlay file at the same relative path as a base file ALWAYS wins.

    Transport: robocopy over the admin share (\\<server>\D$...), SMB session
    authenticated beforehand with New-PSDrive + the DATACENTER's credential
    (one admin account per datacenter; no plaintext password on any command
    line, unlike 'net use').
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-PSMRobocopy {
    <#
        robocopy wrapper: exit codes 0-7 = success (0 = nothing to copy,
        1-7 = changes applied), >= 8 = failure (throws with the output tail).
        Returns the exit code so callers can tell "already in sync" (0) from
        "changed" (1-7).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $Source,
        [Parameter(Mandatory)] [string]   $Destination,
        [string[]] $Options = @()
    )
    if (-not (Get-Command robocopy.exe -ErrorAction SilentlyContinue)) {
        throw 'Invoke-PSMRobocopy: robocopy.exe not available (Windows required).'
    }
    $output = & robocopy.exe $Source $Destination @Options
    $code   = $LASTEXITCODE
    if ($code -ge 8) {
        $tail = (@($output) | Select-Object -Last 8) -join "`n"
        throw "robocopy failed (exit code $code) '$Source' -> '$Destination':`n$tail"
    }
    return $code
}

function Build-PSMStagingTree {
    <#
        Composes the complete tree for ONE server type:
          1. base -> staging: /MIR (staging converges to the base; stale files
             are removed) excluding state\, logs\ and .git (a server's LOCAL
             state must never be shipped);
          2. overlay -> staging: /E /IS /IT (copy even identical/tweaked files:
             the overlay ALWAYS wins over the base, whatever the timestamps).
        A missing/empty overlay is allowed (base-only type): the caller decides
        whether to WARN. Returns the summed robocopy exit codes (0 = staging
        was already up to date).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $BaseRoot,
        [string] $OverlayPath,
        [Parameter(Mandatory)] [string] $StagingPath
    )
    if (-not (Test-Path $BaseRoot)) {
        throw "Build-PSMStagingTree: base tree not found: $BaseRoot (distribution.psd1 SourceRoot)."
    }
    New-Item -ItemType Directory -Path $StagingPath -Force | Out-Null
    $quiet   = '/R:2', '/W:5', '/NP', '/NFL', '/NDL', '/NJH', '/NJS'
    $changed = Invoke-PSMRobocopy -Source $BaseRoot -Destination $StagingPath `
                   -Options (@('/MIR', '/XD', 'state', 'logs', '.git') + $quiet)
    if ($OverlayPath -and (Test-Path $OverlayPath)) {
        $changed += Invoke-PSMRobocopy -Source $OverlayPath -Destination $StagingPath `
                        -Options (@('/E', '/IS', '/IT') + $quiet)
    }
    return $changed
}

function Push-PSMSourcesToServer {
    <#
        Mirrors a composed staging tree to ONE server over its admin share.
        - SMB session authenticated with New-PSDrive + the datacenter credential
          (robocopy then reuses the established session for the same server);
        - /MIR converges the target to the staging tree (stale binaries removed)
          while /XD state logs PRESERVES the server's local progress.json and
          deployment logs;
        - the temporary PSDrive is always removed (finally).
        Returns the robocopy exit code (0 = already in sync, 1-7 = changed).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ServerName,
        [Parameter(Mandatory)] [string] $StagingPath,
        [Parameter(Mandatory)] [string] $TargetUnc,       # \\server\D$\PSMSources\PSM-Deploy
        [pscredential] $Credential
    )
    if (-not (Test-Path $StagingPath)) {
        throw "Push-PSMSourcesToServer: staging tree not found: $StagingPath (compose it first - run without -SkipStaging)."
    }
    $m = [regex]::Match($TargetUnc, '^(\\\\[^\\]+\\[^\\]+)')
    if (-not $m.Success) { throw "Push-PSMSourcesToServer: invalid UNC target: $TargetUnc" }
    $shareRoot = $m.Groups[1].Value

    $drive = $null
    try {
        if ($Credential) {
            # Authenticates the SMB session for this server; no plaintext
            # password on a command line (unlike 'net use').
            $driveName = 'PSMDIST' + ([guid]::NewGuid().ToString('N').Substring(0, 6))
            $drive = New-PSDrive -Name $driveName -PSProvider FileSystem -Root $shareRoot `
                        -Credential $Credential -Scope Local -ErrorAction Stop
        }
        if (-not (Test-Path $shareRoot)) {
            throw "share unreachable: $shareRoot (445 flow / account rights on this datacenter?)"
        }
        return Invoke-PSMRobocopy -Source $StagingPath -Destination $TargetUnc `
                   -Options @('/MIR', '/XD', 'state', 'logs',
                              '/R:2', '/W:5', '/MT:16', '/NP', '/NFL', '/NDL', '/NJH', '/NJS')
    }
    finally {
        if ($drive) { Remove-PSDrive -Name $drive.Name -Force -ErrorAction SilentlyContinue }
    }
}

Export-ModuleMember -Function Invoke-PSMRobocopy, Build-PSMStagingTree, Push-PSMSourcesToServer
