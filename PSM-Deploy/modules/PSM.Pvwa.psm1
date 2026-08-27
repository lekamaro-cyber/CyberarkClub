<#
.SYNOPSIS
    Secret retrieval and Vault operations through the PVWA REST API.

.DESCRIPTION
    Replaces the CCP/AIM approach: the admin performing the installation
    authenticates themselves to the PVWA (they have access to all CyberArk
    accounts), and the script retrieves the passwords it needs on the fly
    through the REST API.

    Stable PSM/PVWA REST API from 12.6 -> 14.0:
      POST {Pvwa}/PasswordVault/API/Auth/{method}/Logon        -> session token
      GET  {Pvwa}/PasswordVault/API/Accounts?search=..&filter=safeName eq ..
      POST {Pvwa}/PasswordVault/API/Accounts/{id}/Password/Retrieve
      POST {Pvwa}/PasswordVault/API/Auth/Logoff

    No secret is written to disk; retrieved passwords are registered with
    Register-PSMSecret so they get masked in the logs.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Set-PvwaTlsBypass {
    <#
        LAB ONLY: accepts the test PVWA's self-signed certificates.
        Do NOT enable in production (set SkipCertificateCheck = $false).
    #>
    [CmdletBinding()]
    param()
    # PowerShell 5.1 cannot convert a static method (PSMethod) into a
    # RemoteCertificateValidationCallback delegate ("Cannot convert ... PSMethod").
    # The delegate assignment is therefore done INSIDE the C# itself.
    if (-not ([System.Management.Automation.PSTypeName]'PSMTlsBypass').Type) {
        Add-Type -TypeDefinition @"
using System.Net;
public static class PSMTlsBypass {
    public static void Enable()  { ServicePointManager.ServerCertificateValidationCallback = delegate { return true; }; }
    public static void Disable() { ServicePointManager.ServerCertificateValidationCallback = null; }
}
"@
    }
    [PSMTlsBypass]::Enable()
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Write-Verbose "PVWA: TLS certificate validation disabled (lab mode)."
}

function Connect-PvwaSession {
    <#
        Authenticates the admin to the PVWA and returns a session object
        (base URL + token + ready-to-use headers).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $PvwaUrl,
        [Parameter(Mandatory)] [pscredential] $Credential,
        [ValidateSet('CyberArk', 'LDAP', 'Windows', 'RADIUS')] [string] $AuthMethod = 'CyberArk',
        [switch] $ConcurrentSession,
        [switch] $SkipCertificateCheck,
        [int]    $TimeoutSec = 60
    )

    if ($SkipCertificateCheck) { Set-PvwaTlsBypass }

    $base = $PvwaUrl.TrimEnd('/')
    $body = @{
        username          = $Credential.UserName
        password          = $Credential.GetNetworkCredential().Password
        concurrentSession = [bool]$ConcurrentSession
    } | ConvertTo-Json

    $uri = "$base/PasswordVault/API/Auth/$AuthMethod/Logon"
    try {
        $token = Invoke-RestMethod -Uri $uri -Method Post -Body $body `
                    -ContentType 'application/json' -TimeoutSec $TimeoutSec -ErrorAction Stop
    }
    catch {
        throw "PVWA logon failed ($AuthMethod) on $base : $($_.Exception.Message)"
    }

    $clean = ($token | Out-String).Trim().Trim('"')
    return [pscustomobject]@{
        PvwaUrl = $base
        Token   = $clean
        Headers = @{ Authorization = $clean }
    }
}

function Connect-PvwaSessionWithRetry {
    <#
        Interactive PVWA logon with credential validation: prompts (unless a
        credential is supplied), tests the logon, and on an AUTHENTICATION
        failure re-prompts with a clear warning instead of failing the whole
        deployment. Infrastructure errors (unreachable PVWA, TLS, DNS...) are
        NOT retried: re-entering credentials would not help.
        Attempts are capped to avoid locking the account out.
        Returns [pscustomobject]@{ Session; Credential }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $PvwaUrl,
        [Parameter(Mandatory)] [string] $AuthMethod,
        [string] $ZoneName = '',
        [pscredential] $Credential,          # pre-supplied (-PvwaCredential): tried first
        [switch] $SkipCertificateCheck,
        [switch] $ConcurrentSession,
        [switch] $NonInteractive,
        [int] $MaxAttempts = 3
    )
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $cred = $Credential
        if (-not $cred) {
            if ($NonInteractive) {
                throw 'PVWA: credential required in NonInteractive mode (-PvwaCredential parameter).'
            }
            $cred = Get-Credential -Message "PVWA admin account ($AuthMethod) - zone $ZoneName [attempt $attempt/$MaxAttempts]"
            if (-not $cred) { throw 'PVWA logon canceled by the operator.' }
        }
        try {
            $session = Connect-PvwaSession -PvwaUrl $PvwaUrl -Credential $cred `
                            -AuthMethod $AuthMethod -ConcurrentSession:$ConcurrentSession `
                            -SkipCertificateCheck:$SkipCertificateCheck
            Write-PSMLog -Level OK -Message "PVWA logon OK ($($cred.UserName))."
            return [pscustomobject]@{ Session = $session; Credential = $cred }
        }
        catch {
            $msg = $_.Exception.Message
            # Only re-prompt on an AUTHENTICATION failure (401/403/PASWS codes);
            # anything else (network, TLS, DNS...) is a real error -> fail fast.
            $isAuthFailure = $msg -match '\(401\)|\(403\)|Authentication|password|PASWS'
            if (-not $isAuthFailure) { throw }
            if ($NonInteractive -or ($Credential -and $attempt -ge $MaxAttempts)) { throw }
            Write-PSMLog -Level WARN -Message ("PVWA logon REFUSED for '$($cred.UserName)': wrong account or password " +
                "- please re-enter the credentials. ($msg)")
            $Credential = $null   # force a fresh prompt on the next attempt
        }
    }
    throw "PVWA logon failed after $MaxAttempts attempts (check the account - mind a possible lockout)."
}

function Disconnect-PvwaSession {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Session)
    try {
        Invoke-RestMethod -Uri "$($Session.PvwaUrl)/PasswordVault/API/Auth/Logoff" `
            -Method Post -Headers $Session.Headers -TimeoutSec 30 -ErrorAction Stop | Out-Null
    }
    catch {
        if (Get-Command Write-PSMLog -ErrorAction SilentlyContinue) {
            Write-PSMLog -Level WARN -Message "Non-critical PVWA logoff issue: $($_.Exception.Message)"
        }
    }
}

function Find-PvwaUser {
    <# Searches the Vault USERS (v2 API). Returns { id, username, ... } objects. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory)] [string] $Search,
        [int] $TimeoutSec = 60
    )
    $uri  = "$($Session.PvwaUrl)/PasswordVault/API/Users?search=$([uri]::EscapeDataString($Search))"
    $resp = Invoke-RestMethod -Uri $uri -Method Get -Headers $Session.Headers -TimeoutSec $TimeoutSec -ErrorAction Stop
    if ($resp.PSObject.Properties.Name -contains 'Users') { return @($resp.Users) }
    return @()
}

function Rename-PvwaUser {
    <#
        Renames a Vault user through the PVWA API (PUT /API/Users/{id}):
        fetches the full object, replaces 'username', returns the updated object.
        Used to align the PSM component accounts with the naming convention.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory)] [string] $UserName,
        [Parameter(Mandatory)] [string] $NewUserName,
        [int] $TimeoutSec = 60
    )
    $match = @(Find-PvwaUser -Session $Session -Search $UserName | Where-Object { $_.username -eq $UserName })
    if ($match.Count -ne 1) {
        throw "Rename-PvwaUser: user '$UserName' not found or ambiguous ($($match.Count) result(s)) on the Vault side."
    }
    $id = $match[0].id

    if (-not $PSCmdlet.ShouldProcess($UserName, "Rename to '$NewUserName' (PVWA API)")) { return $null }

    $userUri = "$($Session.PvwaUrl)/PasswordVault/API/Users/$id"
    $user    = Invoke-RestMethod -Uri $userUri -Method Get -Headers $Session.Headers -TimeoutSec $TimeoutSec -ErrorAction Stop
    $user.username = $NewUserName
    try {
        return Invoke-RestMethod -Uri $userUri -Method Put -Headers $Session.Headers `
                -Body ($user | ConvertTo-Json -Depth 8) -ContentType 'application/json' `
                -TimeoutSec $TimeoutSec -ErrorAction Stop
    }
    catch {
        throw ("PVWA rename of '$UserName' to '$NewUserName' failed: $($_.Exception.Message). " +
               'Alternative: rename the user in PVWA (Administration > Users) then relaunch.')
    }
}

function Remove-PvwaUser {
    <#
        Deletes a Vault user through the PVWA API (DELETE /API/Users/{id}).
        Used to clean up a LEFTOVER component user (previous installation of the
        same server) when the operator chooses to overwrite it, and to remove
        the freshly generated orphan in the password-sync flow.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory)] [string] $UserName,
        [int] $TimeoutSec = 60
    )
    $match = @(Find-PvwaUser -Session $Session -Search $UserName | Where-Object { $_.username -eq $UserName })
    if ($match.Count -ne 1) {
        throw "Remove-PvwaUser: user '$UserName' not found or ambiguous ($($match.Count) result(s)) on the Vault side."
    }
    $id = $match[0].id

    if (-not $PSCmdlet.ShouldProcess($UserName, 'Delete the Vault user (PVWA API)')) { return $false }
    try {
        Invoke-RestMethod -Uri "$($Session.PvwaUrl)/PasswordVault/API/Users/$id" `
            -Method Delete -Headers $Session.Headers -TimeoutSec $TimeoutSec -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        throw ("PVWA deletion of user '$UserName' failed: $($_.Exception.Message). " +
               'Alternative: delete the user in PVWA (Administration > Users) then relaunch.')
    }
}

function Reset-PvwaUserPassword {
    <#
        Resets a Vault user's password through the PVWA API
        (POST /API/Users/{id}/ResetPassword). Used by the component-account
        password-sync flow: the existing PSM-<HOST> user gets a fresh password
        that is then written into the local cred file (CreateCredFile.exe).
        Requires the "Reset Users' Passwords" Vault authorization.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Session,
        [Parameter(Mandatory)] [string] $UserName,
        [Parameter(Mandatory)] [securestring] $NewPassword,
        [int] $TimeoutSec = 60
    )
    $match = @(Find-PvwaUser -Session $Session -Search $UserName | Where-Object { $_.username -eq $UserName })
    if ($match.Count -ne 1) {
        throw "Reset-PvwaUserPassword: user '$UserName' not found or ambiguous ($($match.Count) result(s)) on the Vault side."
    }
    $id = $match[0].id

    if (-not $PSCmdlet.ShouldProcess($UserName, 'Reset the Vault user password (PVWA API)')) { return $false }
    $plain = [System.Management.Automation.PSCredential]::new('x', $NewPassword).GetNetworkCredential().Password
    if (Get-Command Register-PSMSecret -ErrorAction SilentlyContinue) { Register-PSMSecret -Secret $plain }
    $body = @{ id = $id; newPassword = $plain } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri "$($Session.PvwaUrl)/PasswordVault/API/Users/$id/ResetPassword" `
            -Method Post -Headers $Session.Headers -Body $body -ContentType 'application/json' `
            -TimeoutSec $TimeoutSec -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '\(403\)|Forbidden|PASWS') {
            throw ("PVWA password reset of '$UserName' REFUSED ($msg): the connected admin needs the " +
                   '"Reset Users'' Passwords" Vault authorization. Grant it (or reset the password in ' +
                   'PVWA > Administration > Users) then relaunch.')
        }
        throw "PVWA password reset of '$UserName' failed: $msg"
    }
}

function Find-PvwaAccount {
    <# Account search (filter by Safe + text search on user/object/address). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Session,
        [string] $Safe,
        [string] $UserName,
        [string] $Search,
        [string] $Address,
        [int]    $TimeoutSec = 60
    )
    $q = @()
    if ($Safe) { $q += "filter=safeName eq $([uri]::EscapeDataString($Safe))" }
    $terms = @($UserName, $Search, $Address) | Where-Object { $_ }
    if ($terms) { $q += "search=$([uri]::EscapeDataString(($terms -join ' ')))" }

    $uri = "$($Session.PvwaUrl)/PasswordVault/API/Accounts"
    if ($q) { $uri += '?' + ($q -join '&') }

    $resp  = Invoke-RestMethod -Uri $uri -Method Get -Headers $Session.Headers -TimeoutSec $TimeoutSec -ErrorAction Stop
    $items = @($resp.value)
    if ($UserName) { $items = @($items | Where-Object { $_.userName -eq $UserName }) }
    return $items
}

function Get-PvwaAccountPassword {
    <#
        Retrieves an account password from the Vault through the PVWA API (admin session).
        Locates the account either by AccountId, or by Safe/UserName/Search.
        Returns an object { AccountId, UserName, Credential }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Session,
        [string] $AccountId,
        [string] $Safe,
        [string] $UserName,
        [string] $Search,
        [string] $Reason = 'PSM automated deployment',
        [int]    $TimeoutSec = 60
    )

    if (-not $AccountId) {
        $found = Find-PvwaAccount -Session $Session -Safe $Safe -UserName $UserName -Search $Search
        if (@($found).Count -eq 0) {
            throw "Account not found in the PVWA (Safe='$Safe' User='$UserName' Search='$Search')."
        }
        if (@($found).Count -gt 1) {
            $ids = ($found | Select-Object -First 5 -ExpandProperty id) -join ', '
            throw "Multiple matching accounts ($(@($found).Count)). Narrow down Safe/UserName. Ids: $ids"
        }
        $AccountId = $found[0].id
        if (-not $UserName) { $UserName = $found[0].userName }
    }

    $body = @{ reason = $Reason } | ConvertTo-Json
    $uri  = "$($Session.PvwaUrl)/PasswordVault/API/Accounts/$AccountId/Password/Retrieve"
    try {
        $pw = Invoke-RestMethod -Uri $uri -Method Post -Headers $Session.Headers `
                -Body $body -ContentType 'application/json' -TimeoutSec $TimeoutSec -ErrorAction Stop
    }
    catch {
        throw "Password retrieval failed (AccountId '$AccountId') via PVWA: $($_.Exception.Message)"
    }

    $plain = ($pw | Out-String).Trim().Trim('"')
    if (Get-Command Register-PSMSecret -ErrorAction SilentlyContinue) { Register-PSMSecret -Secret $plain }

    if (-not $UserName) { $UserName = 'vaultuser' }
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    return [pscustomobject]@{
        AccountId  = $AccountId
        UserName   = $UserName
        Credential = [System.Management.Automation.PSCredential]::new($UserName, $secure)
    }
}

Export-ModuleMember -Function Set-PvwaTlsBypass, Connect-PvwaSession, Connect-PvwaSessionWithRetry, `
                              Disconnect-PvwaSession, Find-PvwaAccount, Get-PvwaAccountPassword, `
                              Find-PvwaUser, Rename-PvwaUser, Remove-PvwaUser, Reset-PvwaUserPassword
