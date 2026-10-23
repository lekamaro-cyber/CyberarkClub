<#
.SYNOPSIS
    RDP certificate of the PSMs behind a load-balancer VIP.

.DESCRIPTION
    The users connect to the PSMs through a VIP (zones.psd1 PsmVips): the RDP
    listener must present a certificate carrying the VIP name in its SAN,
    otherwise the client shows a name mismatch warning.

    On each member server of a VIP:
      1. look in Cert:\LocalMachine\My for a certificate whose SAN contains
         the VIP name (exact match, case-insensitive, no wildcard);
      2. keep the usable ones: private key present, valid dates, Server
         Authentication EKU (or no EKU); the latest expiry wins;
      3. check that NETWORK SERVICE (TermService account) can read the private
         key file - CHECK ONLY, the ACL is never modified;
      4. bind it to the RDP-Tcp listener (WMI Win32_TSGeneralSetting).

    Every problem (certificate absent, not usable, key not readable, binding
    failure) is an ALERT with the manual fix, never a deployment stop.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ServerAuthEku = '1.3.6.1.5.5.7.3.1'
$script:SanOid        = '2.5.29.17'

function Write-PSMAlert {
    # Framed multi-line WARN, so the alert stands out in the console and the log.
    param(
        [Parameter(Mandatory)] [string]   $Title,
        [Parameter(Mandatory)] [string[]] $Lines
    )
    $bar = '*' * 78
    Write-PSMLog -Level WARN -Message $bar
    Write-PSMLog -Level WARN -Message "ALERT - $Title"
    foreach ($l in $Lines) { Write-PSMLog -Level WARN -Message "  $l" }
    Write-PSMLog -Level WARN -Message $bar
}

function Test-PSMSanMatch {
    <#
        $true when the SAN DNS name matches the expected name: exact,
        case-insensitive, trailing dot ignored. A wildcard SAN (*.domain)
        does NOT match: the VIP name itself must be in the certificate.
    #>
    param(
        [string] $SanName,
        [Parameter(Mandatory)] [string] $ExpectedName
    )
    if (-not $SanName) { return $false }
    return ($SanName.Trim().TrimEnd('.') -ieq $ExpectedName.Trim().TrimEnd('.'))
}

function Read-PSMDerLength {
    # DER length (short or long form) at $Position, which is advanced past it.
    param([byte[]] $Bytes, [ref] $Position)
    $len = [int]$Bytes[$Position.Value]
    $Position.Value++
    if ($len -band 0x80) {
        $count = $len -band 0x7F
        $len = 0
        for ($i = 0; $i -lt $count; $i++) {
            $len = ($len -shl 8) -bor [int]$Bytes[$Position.Value]
            $Position.Value++
        }
    }
    return $len
}

function Get-PSMCertSanDnsNames {
    <#
        DNS names of the certificate's SAN extension, decoded from the raw
        DER: SEQUENCE of GeneralName, dNSName = [2] IMPLICIT IA5String (tag
        0x82). Locale-independent (the Format()/DnsNameList text depends on
        the OS language). Returns nothing when there is no SAN.
    #>
    param([Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

    $names = New-Object System.Collections.Generic.List[string]
    $ext = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq $script:SanOid } | Select-Object -First 1
    if (-not $ext) { return @() }
    $b = $ext.RawData
    try {
        if ($b.Length -lt 2 -or $b[0] -ne 0x30) { return @() }
        $pos = 1
        $end = (Read-PSMDerLength -Bytes $b -Position ([ref]$pos)) + $pos
        while ($pos -lt $end) {
            $tag = $b[$pos]
            $pos++
            $len = Read-PSMDerLength -Bytes $b -Position ([ref]$pos)
            if ($tag -eq 0x82) { $names.Add([System.Text.Encoding]::ASCII.GetString($b, $pos, $len)) }
            $pos += $len
        }
    }
    catch {
        Write-PSMLog -Level WARN -Message "Certificate $($Certificate.Thumbprint): SAN extension could not be decoded ($($_.Exception.Message))."
    }
    return $names.ToArray()   # callers wrap in @() (no name / a single name)
}

function Get-PSMServerVips {
    <#
        VIP names (zones.psd1 PsmVips keys) whose Members include this server.
        Members are compared on the short name, case-insensitive ('HOST' or
        'HOST.domain' both match). A malformed entry is WARNed and skipped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $ZoneConfig,
        [string] $ComputerName = $env:COMPUTERNAME
    )
    $cfg = Get-PSMConfigValue -Config $ZoneConfig -Key 'PsmVips'
    if ($null -eq $cfg) { return @() }
    if ($cfg -isnot [System.Collections.IDictionary]) {
        Write-PSMLog -Level WARN -Message "zones.psd1: PsmVips must be a table @{ '<vip fqdn>' = @{ Members = @(...) } } - ignored."
        return @()
    }
    $vips = @()
    foreach ($vip in $cfg.Keys) {
        $members = Get-PSMConfigValue -Config $cfg[$vip] -Key 'Members'
        if (-not $members) {
            Write-PSMLog -Level WARN -Message "zones.psd1: PsmVips '$vip' has no Members - entry ignored."
            continue
        }
        foreach ($m in @($members)) {
            if (([string]$m).Split('.')[0] -ieq $ComputerName) { $vips += [string]$vip; break }
        }
    }
    return $vips
}

function Get-PSMPrivateKeyFile {
    # Machine key file of the certificate's private key, $null when not found
    # (e.g. key held by a TPM/HSM provider).
    param([Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

    $names = @()
    foreach ($getKey in @(
            { [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate) },
            { [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Certificate) })) {
        try {
            $key = & $getKey
            if ($null -eq $key) { continue }
            if ($key.PSObject.Properties['Key'] -and $key.Key) { $names += $key.Key.UniqueName }                          # CNG
            if ($key.PSObject.Properties['CspKeyContainerInfo']) { $names += $key.CspKeyContainerInfo.UniqueKeyContainerName } # CAPI
        }
        catch { }
    }
    $crypto = Join-Path $env:ProgramData 'Microsoft\Crypto'
    foreach ($n in ($names | Where-Object { $_ } | Select-Object -Unique)) {
        foreach ($dir in 'Keys', 'RSA\MachineKeys') {
            $file = Join-Path (Join-Path $crypto $dir) $n
            if (Test-Path -LiteralPath $file) { return $file }
        }
    }
    return $null
}

function Test-PSMNetworkServiceKeyRead {
    <#
        CHECK ONLY: can NETWORK SERVICE (account of TermService) read the
        private key file? Allow ACE for NETWORK SERVICE, Authenticated Users or
        Everyone carrying read (key files often hold GENERIC_READ/GENERIC_ALL),
        and no matching Deny ACE.
        Returns @{ Readable = $true | $false | $null (undetermined); KeyFile; Detail }.
    #>
    param([Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

    $file = Get-PSMPrivateKeyFile -Certificate $Certificate
    if (-not $file) {
        return @{ Readable = $null; KeyFile = $null; Detail = 'private key file not found (TPM/HSM provider?)' }
    }
    try {
        $acl = Get-Acl -LiteralPath $file
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    }
    catch {
        return @{ Readable = $null; KeyFile = $file; Detail = "ACL not readable: $($_.Exception.Message)" }
    }
    $sids    = @('S-1-5-20', 'S-1-5-11', 'S-1-1-0')   # NETWORK SERVICE, Authenticated Users, Everyone
    $readMask = [int]::MinValue -bor 0x10000000 -bor 0x1   # GENERIC_READ | GENERIC_ALL | FILE_READ_DATA
    $allowed = $false
    foreach ($r in $rules) {
        if ($sids -notcontains $r.IdentityReference.Value) { continue }
        if (-not ([int]$r.FileSystemRights -band $readMask)) { continue }
        if ($r.AccessControlType -eq 'Deny') {
            return @{ Readable = $false; KeyFile = $file; Detail = "Deny ACE for $($r.IdentityReference.Value)" }
        }
        $allowed = $true
    }
    if ($allowed) { return @{ Readable = $true;  KeyFile = $file; Detail = 'NETWORK SERVICE has Read' } }
    return              @{ Readable = $false; KeyFile = $file; Detail = 'no Read ACE for NETWORK SERVICE' }
}

function Invoke-PSMRdpCertificate {
    <#
        RdpCertificate phase (see the module header). Returns $true when the
        RDP listener presents the VIP certificate (or no VIP concerns this
        server), $false after an ALERT. Never throws for a certificate problem.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $ZoneConfig,
        [string] $ComputerName = $env:COMPUTERNAME
    )
    $zoneName = Get-PSMConfigValue -Config $ZoneConfig -Key 'Name'
    if ($null -eq (Get-PSMConfigValue -Config $ZoneConfig -Key 'PsmVips')) {
        Write-PSMLog -Level WARN -Message ("RDP certificate: no PsmVips key in zones.psd1 zone '$zoneName' -> check INACTIVE. " +
            "Copy the PsmVips key from the branch's config\zones.psd1 (keep @{} when no VIP).")
        return $true
    }
    $vips = @(Get-PSMServerVips -ZoneConfig $ZoneConfig -ComputerName $ComputerName)
    if ($vips.Count -eq 0) {
        Write-PSMLog -Level INFO -Message "RDP certificate: $ComputerName is not a member of any PsmVips of zone '$zoneName' -> RDP certificate unchanged."
        return $true
    }
    $vipList = $vips -join ', '
    Write-PSMLog -Level INFO -Message "RDP certificate: $ComputerName is behind VIP(s) $vipList -> looking for the certificate in Cert:\LocalMachine\My."

    # 1. Certificates whose SAN covers ALL the VIP names of this server (one
    #    RDP listener = one certificate).
    $all = @(Get-ChildItem -Path 'Cert:\LocalMachine\My')
    $candidates = @()
    foreach ($c in $all) {
        $san = @(Get-PSMCertSanDnsNames -Certificate $c)
        $coversAll = $true
        foreach ($v in $vips) {
            if (-not @($san | Where-Object { Test-PSMSanMatch -SanName $_ -ExpectedName $v })) { $coversAll = $false; break }
        }
        if ($coversAll) { $candidates += $c }
    }
    if ($candidates.Count -eq 0) {
        $present = @($all | Select-Object -First 10 | ForEach-Object {
            $s = @(Get-PSMCertSanDnsNames -Certificate $_)
            "$($_.Thumbprint)  $($_.Subject)  SAN=[$(if ($s) { $s -join ', ' } else { 'none' })]  expires $($_.NotAfter.ToString('yyyy-MM-dd'))"
        })
        Write-PSMAlert -Title 'RDP CERTIFICATE NOT PRESENT' -Lines (@(
            "The certificate declared in zones.psd1 for this server (zone '$zoneName', PsmVips: $vipList)",
            "is NOT present: no certificate in Cert:\LocalMachine\My carries '$vipList' in its SAN.",
            'The RDP listener keeps its current certificate (clients will get a name mismatch on the VIP).',
            "Fix: import the certificate WITH its private key (PFX) into LocalMachine\My (certlm.msc),",
            '     then relaunch .\Deploy-PSM.ps1 (this check runs on every launch).',
            "Certificates currently in LocalMachine\My ($($all.Count)):") + $(if ($present) { $present | ForEach-Object { "  $_" } } else { '  (none)' }))
        return $false
    }

    # 2. Usable = private key + valid dates + Server Authentication EKU (or no EKU).
    $now = Get-Date
    $usable = @()
    $rejected = @()
    foreach ($c in $candidates) {
        $why = @()
        if (-not $c.HasPrivateKey) { $why += 'NO private key' }
        if ($c.NotBefore -gt $now) { $why += "not valid before $($c.NotBefore.ToString('yyyy-MM-dd'))" }
        if ($c.NotAfter  -lt $now) { $why += "EXPIRED on $($c.NotAfter.ToString('yyyy-MM-dd'))" }
        $eku = $c.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } | Select-Object -First 1
        if ($eku -and -not @($eku.EnhancedKeyUsages | Where-Object { $_.Value -eq $script:ServerAuthEku })) {
            $why += 'no Server Authentication EKU'
        }
        if ($why) { $rejected += "$($c.Thumbprint)  $($c.Subject): $($why -join ', ')" }
        else      { $usable += $c }
    }
    if ($usable.Count -eq 0) {
        Write-PSMAlert -Title 'RDP CERTIFICATE NOT USABLE' -Lines (@(
            "Certificate(s) with '$vipList' in the SAN found in LocalMachine\My, but none is usable:") +
            ($rejected | ForEach-Object { "  $_" }) + @(
            'Fix: import a valid certificate WITH its private key (PFX, Server Authentication),',
            '     then relaunch .\Deploy-PSM.ps1.'))
        return $false
    }
    $cert = $usable | Sort-Object NotAfter -Descending | Select-Object -First 1
    $thumb = $cert.Thumbprint
    Write-PSMLog -Level OK -Message ("RDP certificate found: $thumb  $($cert.Subject)  SAN=[$((Get-PSMCertSanDnsNames -Certificate $cert) -join ', ')]  " +
        "expires $($cert.NotAfter.ToString('yyyy-MM-dd'))$(if ($usable.Count -gt 1) { " (latest of $($usable.Count) usable)" })")

    # 3. Private key readable by NETWORK SERVICE (TermService). Not readable =
    #    no binding: a listener on a key TermService cannot open breaks RDP.
    $keyRead = Test-PSMNetworkServiceKeyRead -Certificate $cert
    if ($keyRead.Readable -ne $true) {
        $state = if ($null -eq $keyRead.Readable) { 'could NOT be verified' } else { 'is NOT readable by NETWORK SERVICE' }
        Write-PSMAlert -Title 'RDP CERTIFICATE PRIVATE KEY' -Lines @(
            "The private key of $thumb $state ($($keyRead.Detail)).",
            "Key file: $(if ($keyRead.KeyFile) { $keyRead.KeyFile } else { 'not found' })",
            'TermService runs as NETWORK SERVICE: binding a key it cannot read would break RDP -> NOT bound.',
            'Fix: certlm.msc > Personal > Certificates > this certificate > All Tasks > Manage Private Keys',
            '     > Add NETWORK SERVICE: Read, then relaunch .\Deploy-PSM.ps1.')
        return $false
    }
    Write-PSMLog -Level OK -Message "RDP certificate: private key readable by NETWORK SERVICE ($($keyRead.KeyFile))."

    # 4. Bind to the RDP-Tcp listener.
    $wmiArgs = @{ Namespace = 'root\cimv2\TerminalServices'; Class = 'Win32_TSGeneralSetting'; Filter = "TerminalName='RDP-tcp'" }
    $manualFix = @(
        'Manual fix (elevated PowerShell):',
        "  `$ts = Get-WmiObject -Namespace root\cimv2\TerminalServices -Class Win32_TSGeneralSetting -Filter `"TerminalName='RDP-tcp'`"",
        "  Set-WmiInstance -Path `$ts.__PATH -Arguments @{ SSLCertificateSHA1Hash = '$thumb' }")
    try {
        Invoke-IdempotentStep -Name "RDP certificate (RDP-Tcp) = $thumb" `
            -Test {
                $ts = Get-WmiObject @wmiArgs
                if (-not $ts) { throw "RDP-Tcp listener not found (WMI Win32_TSGeneralSetting)." }
                Write-PSMLog -Level INFO -Message "RDP-Tcp listener: current certificate $($ts.SSLCertificateSHA1Hash)."
                [string]$ts.SSLCertificateSHA1Hash -ieq $thumb
            } `
            -Action {
                $ts = Get-WmiObject @wmiArgs
                Set-WmiInstance -Path $ts.__PATH -Arguments @{ SSLCertificateSHA1Hash = $thumb } | Out-Null
                $after = [string](Get-WmiObject @wmiArgs).SSLCertificateSHA1Hash
                if ($after -ine $thumb) {
                    throw "re-read after the change: the listener still presents $after (a GPO certificate template can override it)."
                }
                Write-PSMLog -Level INFO -Message 'RDP-Tcp listener re-read: new certificate in place (applies to new RDP connections).'
            } -WhatIf:$WhatIfPreference | Out-Null
    }
    catch {
        Write-PSMAlert -Title 'RDP CERTIFICATE BINDING FAILED' -Lines (@(
            "Certificate $thumb (SAN $vipList) is present and valid, but it could not be bound to RDP-Tcp:",
            "  $($_.Exception.Message)") + $manualFix)
        return $false
    }
    return $true
}

Export-ModuleMember -Function Invoke-PSMRdpCertificate, Get-PSMServerVips, Get-PSMCertSanDnsNames,
    Test-PSMSanMatch, Test-PSMNetworkServiceKeyRead
