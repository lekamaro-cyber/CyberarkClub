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

function Rename-PSMComponentAccounts {
    <#
        Aligne les comptes composants PSM sur la convention de nommage de l'equipe
        (procedure appliquee a la main sur les PSM existants, ici automatisee) :
          - user "App" PSMApp_<hex>  -> PSM-<HOSTNAME>   (pattern configurable)
          - user "Gw"  PSMGw_<hex>   -> PSMA<HOSTNAME>
        RegisterComponent.exe n'offre AUCUN parametre de nommage pour PSM : le
        renommage se fait donc APRES l'enregistrement, en 4 temps :
          1. rename des users cote Vault (API PVWA, session admin reutilisee) ;
          2. mise a jour de la ligne Username= des cred files (le mot de passe ne
             change pas, le Secret chiffre reste valide ; sauvegarde .orig) ;
          3. mise a jour de basic_psm.ini (PSMServerId / PSMServerAdminId) ;
          4. service PSM arrete pendant l'operation puis relance s'il tournait.

        Pilote par settings.psd1 Registration.RenameComponents ($true/$false).
        Idempotent : si les cred files portent deja les noms cibles, ne fait rien.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] $Session      # session PVWA ouverte (Connect-PvwaSession)
    )
    $regCfg = Get-PSMConfigValue -Config $Settings -Key 'Registration'
    if (-not $regCfg -or -not (Get-PSMConfigValue -Config $regCfg -Key 'RenameComponents')) { return $false }

    $hostName   = $env:COMPUTERNAME.ToUpper()
    $appPattern = Get-PSMConfigValue -Config $regCfg -Key 'AppUserPattern'
    $gwPattern  = Get-PSMConfigValue -Config $regCfg -Key 'GwUserPattern'
    if (-not $appPattern) { $appPattern = 'PSM-{HOSTNAME}' }
    if (-not $gwPattern)  { $gwPattern  = 'PSMA{HOSTNAME}' }
    $appNew = $appPattern.Replace('{HOSTNAME}', $hostName)
    $gwNew  = $gwPattern.Replace('{HOSTNAME}', $hostName)

    # basic_psm.ini -> chemins des cred files + IDs a mettre a jour.
    $iniPath = Join-Path (Get-PSMInstallPaths -Settings $Settings).PsmDir 'basic_psm.ini'
    if (-not (Test-Path $iniPath)) {
        throw "Rename-PSMComponentAccounts : basic_psm.ini introuvable ($iniPath) - PSM installe ?"
    }
    $ini = Get-Content -Path $iniPath -Raw
    $credPaths = @{}
    foreach ($k in 'PSMAppCredFile', 'PSMGWCredFile') {
        $m = [regex]::Match($ini, '(?im)^\s*' + $k + '\s*=\s*"?([^"\r\n]+?)"?\s*$')
        if (-not $m.Success) { throw "Rename-PSMComponentAccounts : cle '$k' introuvable dans $iniPath." }
        $credPaths[$k] = $m.Groups[1].Value
    }

    # Noms actuels lus dans les cred files (source de verite locale).
    $targets = @(
        @{ CredPath = $credPaths['PSMAppCredFile']; NewName = $appNew; IniKey = 'PSMServerId' }
        @{ CredPath = $credPaths['PSMGWCredFile'];  NewName = $gwNew;  IniKey = 'PSMServerAdminId' }
    )
    foreach ($t in $targets) {
        if (-not (Test-Path $t.CredPath)) { throw "Cred file introuvable : $($t.CredPath) (enregistrement termine ?)" }
        $m = [regex]::Match((Get-Content -Path $t.CredPath -Raw), '(?im)^\s*Username\s*=\s*(.+?)\s*$')
        if (-not $m.Success) { throw "Ligne 'Username=' introuvable dans $($t.CredPath)." }
        $t.OldName = $m.Groups[1].Value
    }

    if (-not (@($targets | Where-Object { $_.OldName -cne $_.NewName }))) {
        Write-PSMLog -Level OK -Message "Comptes composants deja conformes a la convention ($appNew / $gwNew)."
        return $false
    }
    if (-not $PSCmdlet.ShouldProcess("$($targets[0].OldName) -> $appNew ; $($targets[1].OldName) -> $gwNew",
                                     'Renommer les comptes composants PSM')) { return $false }

    # Service arrete pendant l'operation (il s'authentifie avec les cred files).
    $svc = Get-Service -Name 'Cyberark Privileged Session Manager' -ErrorAction SilentlyContinue
    $wasRunning = $svc -and $svc.Status -eq 'Running'
    if ($wasRunning) {
        Write-PSMLog -Level INFO -Message 'Arret du service PSM pour le renommage des comptes composants...'
        Stop-Service -Name 'Cyberark Privileged Session Manager' -Force
    }

    foreach ($t in $targets) {
        if ($t.OldName -cne $t.NewName) {
            # 1) Cote Vault (API PVWA).
            Rename-PvwaUser -Session $Session -UserName $t.OldName -NewUserName $t.NewName | Out-Null
            Write-PSMLog -Level INFO -Message "Vault : user '$($t.OldName)' renomme en '$($t.NewName)'."
            # 2) Cred file : ligne Username= (mot de passe inchange), sauvegarde .orig.
            $backup = "$($t.CredPath).orig"
            if (-not (Test-Path $backup)) { Copy-Item -Path $t.CredPath -Destination $backup -Force }
            $raw = Get-Content -Path $t.CredPath -Raw
            $raw = ([regex]'(?im)^(\s*Username\s*=\s*).+?\s*$').Replace($raw, ('${1}' + $t.NewName), 1)
            Set-Content -Path $t.CredPath -Value $raw -NoNewline
            Write-PSMLog -Level INFO -Message "Cred file mis a jour : $($t.CredPath) (Username=$($t.NewName))."
        }
        # 3) basic_psm.ini : ID correspondant.
        if ($ini -notmatch ('(?im)^\s*' + $t.IniKey + '\s*=\s*"')) {
            throw "Rename-PSMComponentAccounts : cle '$($t.IniKey)' introuvable dans $iniPath."
        }
        $ini = ([regex]('(?im)^(\s*' + $t.IniKey + '\s*=\s*")[^"]*(")')).Replace($ini, ('${1}' + $t.NewName + '${2}'), 1)
    }
    $iniBackup = "$iniPath.orig"
    if (-not (Test-Path $iniBackup)) { Copy-Item -Path $iniPath -Destination $iniBackup -Force }
    Set-Content -Path $iniPath -Value $ini -NoNewline
    Write-PSMLog -Level INFO -Message "basic_psm.ini mis a jour (PSMServerId=$appNew, PSMServerAdminId=$gwNew)."

    if ($wasRunning) {
        Start-Service -Name 'Cyberark Privileged Session Manager'
        Write-PSMLog -Level INFO -Message 'Service PSM relance.'
    }
    Write-PSMLog -Level OK -Message "Comptes composants renommes : $appNew / $gwNew."
    return $true
}

Export-ModuleMember -Function Invoke-PSMRegister, Rename-PSMComponentAccounts
