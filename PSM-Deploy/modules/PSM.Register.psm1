<#
.SYNOPSIS
    Phase "Enregistrement Vault" : stage CyberArk "Registration" via Execute-Stage.ps1.

.DESCRIPTION
    - Le stage Registration (InvokeRegistrationTool -> RegisterComponent.exe) lit
      le fichier RegistrationConfig.xml (rempli par l'equipe : PVWA, Vault, compte
      composant, etc.). Le mot de passe du compte d'install/admin Vault est fourni
      a Execute-Stage via -spwdObj (SecureString), recupere en amont via l'API PVWA.
    - Les comptes de connexion PSMConnect/PSMAdminConnect ne sont pas manipules ici :
      le service PSM recupere leurs mots de passe a l'execution.
    - L'idempotence est geree par le PreCheck du stage CyberArk + notre suivi de phase.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-PSMRegister {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        [pscredential] $InstallCredential   # mot de passe injecte via -spwdObj
    )
    $paths = Get-PSMStagePaths -Settings $Settings -SourcesRoot $SourcesRoot -StageKey 'Registration'
    $securePwd = if ($InstallCredential) { $InstallCredential.Password } else { $null }

    return Invoke-PSMStage -StageName 'Registration' `
                           -ExecuteStagePath $paths.ExecuteStage `
                           -ConfigFilePath   $paths.Config `
                           -VaultPassword    $securePwd
}

Export-ModuleMember -Function Invoke-PSMRegister
