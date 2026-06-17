<#
.SYNOPSIS
    Recuperation de secrets via le Central Credential Provider (CCP / AIMWebService).

.DESCRIPTION
    API REST stable entre PSM 12.6 et 14.0 :
        GET {CcpUrl}/AIMWebService/api/Accounts?AppID=..&Safe=..&Object=..

    Deux modes d'authentification supportes, choisis par zone :
      - Certificat client (TLS mutuel) si un thumbprint est fourni  -> endpoint "Require"
      - Authentification par IP/OS autorisee si aucun thumbprint     -> endpoint legacy

    Reco securite : a terme, faire pointer les zones sensibles vers un endpoint
    IIS dedie configure en "Require client certificate".
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CcpCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $CcpUrl,         # ex: https://ccp.example.local
        [Parameter(Mandatory)] [string] $AppId,
        [Parameter(Mandatory)] [string] $Safe,
        [Parameter(Mandatory)] [string] $ObjectName,
        [string] $ClientCertThumbprint,                  # optionnel -> mode certificat
        [int]    $TimeoutSec = 30
    )

    $base = $CcpUrl.TrimEnd('/')
    $query = @(
        "AppID=$([uri]::EscapeDataString($AppId))"
        "Safe=$([uri]::EscapeDataString($Safe))"
        "Object=$([uri]::EscapeDataString($ObjectName))"
    ) -join '&'
    $uri = "$base/AIMWebService/api/Accounts?$query"

    $params = @{
        Uri         = $uri
        Method      = 'Get'
        TimeoutSec  = $TimeoutSec
        ErrorAction = 'Stop'
    }

    if ($ClientCertThumbprint) {
        $cert = Get-Item "Cert:\LocalMachine\My\$ClientCertThumbprint" -ErrorAction SilentlyContinue
        if (-not $cert) {
            $cert = Get-Item "Cert:\CurrentUser\My\$ClientCertThumbprint" -ErrorAction SilentlyContinue
        }
        if (-not $cert) {
            throw "Certificat client introuvable (thumbprint $ClientCertThumbprint)."
        }
        $params.Certificate = $cert
        Write-Verbose "CCP : authentification par certificat client ($ClientCertThumbprint)."
    }
    else {
        Write-Verbose "CCP : authentification par IP/OS autorisee (sans certificat)."
    }

    try {
        $resp = Invoke-RestMethod @params
    }
    catch {
        throw "Echec recuperation CCP pour Object '$ObjectName' (Safe '$Safe') : $($_.Exception.Message)"
    }

    if (-not $resp.Content) {
        throw "Reponse CCP sans champ 'Content' pour Object '$ObjectName'."
    }

    # Enregistre le secret pour masquage dans les logs, puis renvoie un PSCredential.
    if (Get-Command Register-PSMSecret -ErrorAction SilentlyContinue) {
        Register-PSMSecret -Secret $resp.Content
    }
    $secure = ConvertTo-SecureString $resp.Content -AsPlainText -Force
    $userName = if ($resp.PSObject.Properties.Name -contains 'UserName') { $resp.UserName } else { $ObjectName }

    return [pscustomobject]@{
        UserName   = $userName
        Credential = [System.Management.Automation.PSCredential]::new($userName, $secure)
        Address    = if ($resp.PSObject.Properties.Name -contains 'Address') { $resp.Address } else { $null }
        Raw        = $resp
    }
}

Export-ModuleMember -Function Get-CcpCredential
