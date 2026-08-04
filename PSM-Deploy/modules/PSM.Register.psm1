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

function Invoke-PSMRegister {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        [pscredential] $InstallCredential,   # mot de passe injecte via -spwdObj
        [string] $VaultAddress               # "ipCluster,ipDr" (depuis zones.psd1)
    )
    # Adresse Vault pilotee par la zone : injection DYNAMIQUE dans une copie patchee
    # du RegistrationConfig.xml (media intact), via le moteur generique de stages.
    # L'emplacement du champ dans le XML est configurable (settings.psd1 Registration.*).
    $extra = $null
    if ($VaultAddress) {
        $xpath = $Settings.Registration.VaultAddressXPath
        $attr  = $Settings.Registration.VaultAddressAttribute
        if (-not $xpath) {
            throw "settings.psd1 : Registration.VaultAddressXPath non defini."
        }
        $extra = @{ $xpath = @{ Attribute = $attr; Value = $VaultAddress } }
    }
    else {
        Write-PSMLog -Level WARN -Message "Aucune adresse Vault de zone (VaultAddress) : utilisation du RegistrationConfig.xml du media tel quel."
    }

    $stage = Resolve-PSMStageConfig -Settings $Settings -SourcesRoot $SourcesRoot `
                -StageKey 'Registration' -ExtraInjections $extra

    $securePwd = if ($InstallCredential) { $InstallCredential.Password } else { $null }

    return Invoke-PSMStage -StageName 'Registration' `
                           -ExecuteStagePath $stage.ExecuteStage `
                           -ConfigFilePath   $stage.ConfigFilePath `
                           -VaultPassword    $securePwd
}

Export-ModuleMember -Function Invoke-PSMRegister
