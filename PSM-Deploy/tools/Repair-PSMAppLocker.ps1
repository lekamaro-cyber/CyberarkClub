<#
.SYNOPSIS
    Re-pins the AppLocker HASH of the PSM's allowed files after a patch
    replaced them (Windows Update: rdpclip.exe, conhost.exe...; Chrome...).

.DESCRIPTION
    CyberArk's AppLocker script allows each application of
    <PSM>\Hardening\PSMConfigureAppLocker.xml by its HASH. A patch that replaces
    one of these files changes its hash: AppLocker then blocks it (copy/paste
    gone when rdpclip.exe is patched) until someone re-runs the AppLocker
    script. This script does that repair, file by file, and nothing else:

      1. reads the server's PSMConfigureAppLocker.xml (NEVER modified) to know
         the paths of the allowed files;
      2. computes the current AppLocker hash of each file that exists;
      3. reads the LOCAL AppLocker policy (the one CyberArk's script wrote) and
         looks, for each FILE NAME, at the hashes pinned there. A pinned hash
         that no longer matches any current file of that name is STALE;
      4. a stale file is re-pinned ONLY when every current file of that name
         has a valid digital signature (embedded or catalog) AND neither the
         file nor its folder can be written by anyone but SYSTEM,
         Administrators or TrustedInstaller. Otherwise it is LEFT BLOCKED and
         logged: a file a user could replace must never be re-allowed
         automatically (that would defeat the hash rule);
      5. in each rule / exception that pinned the stale hash, that hash is
         replaced by the current one. Nothing else changes: same rules, same
         users, same other files. The local policy is backed up first, then
         Set-AppLockerPolicy, gpupdate /target:computer, and a check on the
         EFFECTIVE policy.

    Never adds a file CyberArk did not pin, never touches a Path/Publisher rule,
    never touches PSMConfigureAppLocker.xml.

    Run by the scheduled task "PSM AppLocker hash repair" (SYSTEM, at startup
    and every night), installed from the CPM with
    PSM-Distribute\Install-PSMAppLockerTask.ps1. Can also be run by hand, as
    an administrator (-WhatIf = check only).

    Exit code: 0 = up to date or repaired; 1 = a file left blocked, or an error.

.PARAMETER XmlPath
    The server's PSMConfigureAppLocker.xml. Default: <folder of the PSM
    service executable>\Hardening\PSMConfigureAppLocker.xml.

.PARAMETER LogDirectory
    Log and policy backups. Default: Logs\ next to this script.

.EXAMPLE
    .\Repair-PSMAppLocker.ps1 -WhatIf     # check only: what is stale, what would be re-pinned
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $XmlPath,
    [string] $LogDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# SIDs allowed to write the files we re-pin: SYSTEM, Administrators,
# TrustedInstaller, CREATOR OWNER (inherit-only templates on folders).
$script:TrustedWriterSids = @(
    'S-1-5-18', 'S-1-5-32-544', 'S-1-3-0',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)
$script:LogFile = $null

function Write-RepairLog {
    param(
        [ValidateSet('INFO', 'OK', 'CHANGED', 'WARN', 'ERROR')] [string] $Level = 'INFO',
        [Parameter(Mandatory)] [string] $Message
    )
    $line = '[{0}] [{1,-7}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line   # not Write-Output: called inside functions that return data
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line -WhatIf:$false }
}

function Get-PSMAppLockerXmlPath {
    # <folder of the executable the PSM service runs>\Hardening\PSMConfigureAppLocker.xml
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='Cyberark Privileged Session Manager'" -ErrorAction SilentlyContinue
    if (-not $svc) { throw 'PSM service not found on this machine: pass -XmlPath.' }
    $m = [regex]::Match([string]$svc.PathName, '^\s*"?(?<exe>[^"]+?\.exe)')
    if (-not $m.Success) { throw "PSM service path unreadable ($($svc.PathName)): pass -XmlPath." }
    return Join-Path (Split-Path $m.Groups['exe'].Value -Parent) 'Hardening\PSMConfigureAppLocker.xml'
}

function Get-PSMAllowedFilePaths {
    # Paths of the XML entries allowed by HASH (Method="Hash", or no Method),
    # environment variables expanded. Wildcards are skipped (not a file).
    param([Parameter(Mandatory)] [xml] $Xml)
    $paths = foreach ($app in @($Xml.SelectNodes('//Application'))) {
        $method = $app.GetAttribute('Method')
        if ($method -and $method -ine 'Hash') { continue }
        $p = [Environment]::ExpandEnvironmentVariables($app.GetAttribute('Path')).Trim()
        if (-not $p -or $p.IndexOfAny([char[]]'*?') -ge 0) { continue }
        $p
    }
    return @($paths | Sort-Object -Unique)
}

function Get-PSMCurrentHash {
    # Current AppLocker hash of a file, as the policy writes it.
    param([Parameter(Mandatory)] [string] $Path)
    $h = (Get-AppLockerFileInformation -Path $Path -ErrorAction Stop).Hash
    $text = [string]$h
    $type = if ($h.PSObject.Properties['HashType']) { [string]$h.HashType } else { ($text -split '\s+')[0] }
    $data = if ($h.PSObject.Properties['HashDataString']) { [string]$h.HashDataString } else { ($text -split '\s+')[-1] }
    $len  = if ($h.PSObject.Properties['SourceFileLength']) { [string]$h.SourceFileLength } else { [string](Get-Item -LiteralPath $Path).Length }
    return [pscustomobject]@{
        Path = $Path; Name = (Split-Path $Path -Leaf); Type = $type; Data = $data; Length = $len
    }
}

function Get-PSMUnsafeWriters {
    # Who, besides the trusted SIDs, may modify / delete / re-permission the
    # file or its folder. Empty = protected. InheritOnly and Deny ACEs ignored.
    param([Parameter(Mandatory)] [string] $Path)
    $rights = [System.Security.AccessControl.FileSystemRights]
    $mask = [int64]($rights::WriteData -bor $rights::AppendData -bor $rights::Delete -bor
                    $rights::DeleteSubdirectoriesAndFiles -bor $rights::ChangePermissions -bor $rights::TakeOwnership)
    $mask = $mask -bor 0x10000000 -bor 0x40000000   # GENERIC_ALL, GENERIC_WRITE
    $found = foreach ($target in @($Path, (Split-Path $Path -Parent))) {
        $acl = Get-Acl -LiteralPath $target
        foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
            if ($ace.IdentityReference.Value -in $script:TrustedWriterSids) { continue }
            if (([int64]$ace.FileSystemRights -band $mask) -eq 0) { continue }
            $who = try { $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { $ace.IdentityReference.Value }
            "$who on $target"
        }
    }
    return @($found | Sort-Object -Unique)
}

function Get-PSMRepinBlocker {
    # $null when the file may be re-pinned automatically, else the reason.
    param([Parameter(Mandatory)] [string] $Path)
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ([string]$sig.Status -ne 'Valid') { return "signature $($sig.Status)" }
    $writers = @(Get-PSMUnsafeWriters -Path $Path)
    if ($writers) { return "writable by $($writers -join '; ')" }
    return $null
}

function Find-PSMStaleHashes {
    <#
        Pinned hashes (FileHash elements of the policy) whose file name is one
        of $Current's names but whose Data matches no current file of that
        name. Returns one object per stale element.
        $Current: objects { Name, Type, Data, Length } (Get-PSMCurrentHash).
    #>
    param([Parameter(Mandatory)] [xml] $Policy, [Parameter(Mandatory)] [object[]] $Current)
    $byName = @{}
    foreach ($c in $Current) {
        $k = $c.Name.ToLowerInvariant()
        if (-not $byName.ContainsKey($k)) { $byName[$k] = @() }
        $byName[$k] += $c
    }
    foreach ($fh in @($Policy.SelectNodes('//FileHashCondition/FileHash'))) {
        $k = $fh.GetAttribute('SourceFileName').ToLowerInvariant()
        if (-not $byName.ContainsKey($k)) { continue }
        $data = $fh.GetAttribute('Data')
        if (@($byName[$k] | Where-Object { $_.Data -ieq $data }).Count -gt 0) { continue }
        [pscustomobject]@{ Name = $k; Element = $fh; OldData = $data }
    }
}

function Get-PSMPinnedNames {
    # File names (lowercase) that have at least one pinned hash in the policy.
    param([Parameter(Mandatory)] [xml] $Policy)
    return @($Policy.SelectNodes('//FileHashCondition/FileHash') |
             ForEach-Object { $_.GetAttribute('SourceFileName').ToLowerInvariant() } | Sort-Object -Unique)
}

function Update-PSMPinnedHashes {
    <#
        In each FileHashCondition holding a stale hash of an allowed name:
        removes the stale element and adds the current hash(es) of that name
        the condition does not hold yet, at the same place. Modifies $Policy
        in place; returns the number of elements replaced.
    #>
    param(
        [Parameter(Mandatory)] [xml]      $Policy,
        [Parameter(Mandatory)] [object[]] $Current,
        [Parameter(Mandatory)] [object[]] $Stale,
        [Parameter(Mandatory)] [string[]] $AllowedNames
    )
    $count = 0
    foreach ($s in $Stale) {
        if ($s.Name -notin $AllowedNames) { continue }
        $cond = $s.Element.ParentNode
        $have = @($cond.SelectNodes('FileHash') | ForEach-Object { $_.GetAttribute('Data').ToLowerInvariant() })
        foreach ($c in @($Current | Where-Object { $_.Name.ToLowerInvariant() -eq $s.Name })) {
            if ($c.Data.ToLowerInvariant() -in $have) { continue }
            $new = $Policy.CreateElement('FileHash')
            $new.SetAttribute('Type', $c.Type)
            $new.SetAttribute('Data', $c.Data)
            $new.SetAttribute('SourceFileName', $c.Name)
            $new.SetAttribute('SourceFileLength', $c.Length)
            [void]$cond.InsertBefore($new, $s.Element)
            $have += $c.Data.ToLowerInvariant()
        }
        [void]$cond.RemoveChild($s.Element)
        $count++
    }
    return $count
}

# Dot-sourced (tests): functions only.
if ($MyInvocation.InvocationName -eq '.') { return }

# ============================================================================
if (-not $LogDirectory) { $LogDirectory = Join-Path $PSScriptRoot 'Logs' }
New-Item -ItemType Directory -Path $LogDirectory -Force -WhatIf:$false | Out-Null
$script:LogFile = Join-Path $LogDirectory 'Repair-PSMAppLocker.log'
if ((Test-Path -LiteralPath $script:LogFile) -and (Get-Item -LiteralPath $script:LogFile).Length -gt 2MB) {
    Move-Item -LiteralPath $script:LogFile -Destination "$script:LogFile.old" -Force -WhatIf:$false
}

$exitCode = 0
try {
    if (-not $XmlPath) { $XmlPath = Get-PSMAppLockerXmlPath }
    if (-not (Test-Path -LiteralPath $XmlPath)) { throw "AppLocker list not found: $XmlPath" }
    [xml]$list = Get-Content -LiteralPath $XmlPath -Raw

    $current = @(foreach ($p in (Get-PSMAllowedFilePaths -Xml $list)) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        try { Get-PSMCurrentHash -Path $p }
        catch { Write-RepairLog -Level WARN -Message "Hash unreadable, skipped: $p ($($_.Exception.Message))" }
    })
    if (-not $current) { throw "No file of $XmlPath could be hashed." }

    [xml]$policy = Get-AppLockerPolicy -Local -Xml
    $pinned = @(Get-PSMPinnedNames -Policy $policy)
    $checked = @($current | Where-Object { $_.Name.ToLowerInvariant() -in $pinned })
    if (-not $checked) {
        Write-RepairLog -Level WARN -Message ("No file of the AppLocker list is pinned by hash in the LOCAL policy " +
            '(AppLocker never applied here, or applied by a domain GPO): nothing to repair.')
        exit 0
    }

    $stale = @(Find-PSMStaleHashes -Policy $policy -Current $current)
    if (-not $stale) {
        Write-RepairLog -Level OK -Message "$(@($checked).Count) pinned file(s) checked against $XmlPath - all up to date."
        exit 0
    }

    # Which stale names may be re-pinned: EVERY current file of that name must
    # be signed and protected.
    $allowed = @()
    foreach ($name in @($stale | ForEach-Object { $_.Name } | Sort-Object -Unique)) {
        $files = @($current | Where-Object { $_.Name.ToLowerInvariant() -eq $name })
        $why = @(foreach ($f in $files) { $b = Get-PSMRepinBlocker -Path $f.Path; if ($b) { "$($f.Path): $b" } })
        if ($why) {
            $exitCode = 1
            Write-RepairLog -Level ERROR -Message ("LEFT BLOCKED - $name changed but is not re-pinned automatically: " +
                "$($why -join ' | '). Re-run the CyberArk AppLocker step after checking the file.")
        }
        else {
            $allowed += $name
            Write-RepairLog -Level WARN -Message "$name changed (patch): $(($files | ForEach-Object { $_.Path }) -join ', ') - to re-pin."
        }
    }
    if (-not $allowed) { exit $exitCode }

    if (-not $PSCmdlet.ShouldProcess("local AppLocker policy", "re-pin $($allowed -join ', ')")) {
        Write-RepairLog -Level INFO -Message "WhatIf: would re-pin $($allowed -join ', ') - nothing changed."
        exit $exitCode
    }

    $stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backup = Join-Path $LogDirectory "AppLocker-local-$stamp.xml"
    Get-AppLockerPolicy -Local -Xml | Set-Content -LiteralPath $backup -Encoding UTF8
    Get-ChildItem -LiteralPath $LogDirectory -Filter 'AppLocker-local-*.xml' | Sort-Object Name -Descending |
        Select-Object -Skip 10 | Remove-Item -Force

    $n = Update-PSMPinnedHashes -Policy $policy -Current $current -Stale $stale -AllowedNames $allowed
    $newPolicy = Join-Path $LogDirectory "AppLocker-new-$stamp.xml"
    $policy.Save($newPolicy)
    Set-AppLockerPolicy -XmlPolicy $newPolicy
    Remove-Item -LiteralPath $newPolicy -Force
    Write-RepairLog -Level CHANGED -Message "Local AppLocker policy: $n stale hash(es) replaced for $($allowed -join ', ') (backup: $backup)."

    $gp = & "$env:SystemRoot\System32\gpupdate.exe" /target:computer /force 2>&1
    if ($LASTEXITCODE -ne 0) { Write-RepairLog -Level WARN -Message "gpupdate exit code $LASTEXITCODE : $(($gp | Out-String).Trim())" }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $effData = @($effective.SelectNodes('//FileHashCondition/FileHash') | ForEach-Object { $_.GetAttribute('Data').ToLowerInvariant() })
    $missing = @($current | Where-Object { $_.Name.ToLowerInvariant() -in $allowed -and $_.Data.ToLowerInvariant() -notin $effData })
    if ($missing) {
        Write-RepairLog -Level WARN -Message ("Applied to the local policy but not yet effective for: " +
            "$(($missing | ForEach-Object { $_.Path }) -join ', ') (next Group Policy refresh).")
    }
    else {
        Write-RepairLog -Level OK -Message "Effective policy checked: $($allowed -join ', ') allowed again."
    }
}
catch {
    $exitCode = 1
    Write-RepairLog -Level ERROR -Message "AppLocker repair failed: $($_.Exception.Message)"
}
exit $exitCode
