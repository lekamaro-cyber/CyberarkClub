<#
.SYNOPSIS
    Phase "Enregistrement Vault" : stage CyberArk "Registration" via Execute-Stage.ps1,
    avec l'adresse Vault (cluster,DR) injectee depuis zones.psd1.

.DESCRIPTION
    Objectif : pouvoir deposer une NOUVELLE source CyberArk sans jamais editer son
    RegistrationConfig.xml a la main. L'adresse du Vault (format "ipCluster,ipDr")
    vient de zones.psd1 ; le script en fait une COPIE patchee (dans state\) et lance
    Execute-Stage dessus - le media reste intact.

    - Le mot de passe du compte d'install/admin Vault est fourni via -spwdObj
      (SecureString), recupere en amont via l'API PVWA.
    - L'emplacement du champ adresse Vault dans le XML est configurable
      (settings.psd1 Registration.VaultAddressXPath / VaultAddressAttribute), pour
      s'adapter au schema du media sans toucher au code.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Update-PSMRegistrationConfig {
    <#
        Charge le RegistrationConfig.xml du media, y injecte l'adresse Vault
        (cluster,DR) issue de la zone, et enregistre une COPIE patchee dans state\.
        Renvoie le chemin de la copie a passer a Execute-Stage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourceConfigPath,
        [Parameter(Mandatory)] [string] $VaultAddress,     # "ipCluster,ipDr"
        [Parameter(Mandatory)] [string] $StateDir
    )
    if (-not (Test-Path $SourceConfigPath)) {
        throw "RegistrationConfig.xml introuvable : $SourceConfigPath (verifier le media)."
    }

    [xml]$doc = Get-Content -Path $SourceConfigPath -Raw

    $xpath = $Settings.Registration.VaultAddressXPath
    $attr  = $Settings.Registration.VaultAddressAttribute
    if (-not $xpath) {
        throw "settings.psd1 : Registration.VaultAddressXPath non defini."
    }

    $node = $doc.SelectSingleNode($xpath)
    if (-not $node) {
        # Aide au diagnostic : liste les Parameter disponibles pour ajuster le XPath.
        $names = ($doc.SelectNodes('//Parameter') | ForEach-Object { $_.Name }) -join ', '
        throw ("Adresse Vault introuvable dans RegistrationConfig.xml (XPath: $xpath). " +
               "Parametres disponibles : $names. Ajuster settings.psd1 Registration.VaultAddressXPath.")
    }

    if ($attr) { [void]$node.SetAttribute($attr, $VaultAddress) }
    else       { $node.InnerText = $VaultAddress }

    $outDir = Join-Path $StateDir 'registration'
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $outXml = Join-Path $outDir 'RegistrationConfig.xml'
    $doc.Save($outXml)

    Write-PSMLog -Level INFO -Message "RegistrationConfig patche (Vault='$VaultAddress') -> $outXml"
    return $outXml
}

function Invoke-PSMRegister {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        [pscredential] $InstallCredential,   # mot de passe injecte via -spwdObj
        [string] $VaultAddress,              # "ipCluster,ipDr" (depuis zones.psd1)
        [string] $StateDir
    )
    $paths      = Get-PSMStagePaths -Settings $Settings -SourcesRoot $SourcesRoot -StageKey 'Registration'
    $configPath = $paths.Config

    # Adresse Vault pilotee par la zone -> copie patchee (media intact).
    if ($VaultAddress) {
        if (-not $StateDir) { throw "Invoke-PSMRegister : -StateDir requis quand -VaultAddress est fourni." }
        $configPath = Update-PSMRegistrationConfig -Settings $Settings `
                        -SourceConfigPath $paths.Config -VaultAddress $VaultAddress -StateDir $StateDir
    }
    else {
        Write-PSMLog -Level WARN -Message "Aucune adresse Vault de zone (VaultAddress) : utilisation du RegistrationConfig.xml du media tel quel."
    }

    $securePwd = if ($InstallCredential) { $InstallCredential.Password } else { $null }

    return Invoke-PSMStage -StageName 'Registration' `
                           -ExecuteStagePath $paths.ExecuteStage `
                           -ConfigFilePath   $configPath `
                           -VaultPassword    $securePwd
}

Export-ModuleMember -Function Invoke-PSMRegister, Update-PSMRegistrationConfig
