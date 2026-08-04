<#
.SYNOPSIS
    Phase "Hardening" : stage CyberArk "Hardening" via Execute-Stage.ps1.

.DESCRIPTION
    Le stage Hardening applique le durcissement CyberArk et les regles AppLocker
    (RunTheHardeningScript, SetupAppLockerRules...). La personnalisation "maison"
    se fait dans HardeningConfig.xml et les CSV du dossier Hardening du media
    (PSMConfigureRemoteSessionControl.csv, PSMHideDrives.csv, etc.), remplis par
    l'equipe - pas de politique AppLocker separee a maintenir de notre cote.

    Renvoie l'objet resultat de Invoke-PSMStage ; l'orchestrateur gere le reboot.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Set-PSMConnectAccounts {
    <#
        Injecte les comptes de DOMAINE PSMConnect / PSMAdminConnect de la zone dans
        PSMConfigureAppLocker.xml. Ce fichier est GENERE A L'INSTALLATION dans le
        dossier installe (pas le media) et lu par le step Hardening RunApplocker
        depuis un emplacement FIXE : on le patche donc EN PLACE, avec une sauvegarde
        '.orig' faite une seule fois (on repart toujours de l'original -> re-jeu
        idempotent). Les mots de passe ne sont PAS touches (Safe PSM cote Vault).

        INACTIF si la zone ne fournit aucun compte : ne fait rien et renvoie $false.
        Renvoie $true si un patch a ete applique.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        $ZoneConfig
    )
    if (-not $ZoneConfig) { return $false }

    $h = Get-PSMConfigValue -Config $Settings -Key 'Hardening'
    $psmConnect = Get-PSMConfigValue -Config $ZoneConfig -Key 'PSMConnectUserName'
    $psmAdmin   = Get-PSMConfigValue -Config $ZoneConfig -Key 'PSMAdminConnectUserName'
    if (-not $psmConnect -and -not $psmAdmin) { return $false }   # rien a injecter

    if (-not $h) { throw "settings.psd1 : bloc 'Hardening' absent (comptes de zone fournis)." }
    # Chemin explicite si fourni, sinon DERIVE de la source unique Install.InstallDir.
    $path = Get-PSMConfigValue -Config $h -Key 'AppLockerConfigPath'
    if (-not $path) { $path = (Get-PSMInstallPaths -Settings $Settings).AppLockerConfigPath }

    # Couples (XPath, valeur) a ecrire.
    $pairs = @()
    if ($psmConnect) { $pairs += ,@((Get-PSMConfigValue -Config $h -Key 'PSMConnectXPath'),      $psmConnect) }
    if ($psmAdmin)   { $pairs += ,@((Get-PSMConfigValue -Config $h -Key 'PSMAdminConnectXPath'), $psmAdmin) }

    if (-not $PSCmdlet.ShouldProcess($path, 'Patcher PSMConfigureAppLocker.xml (comptes de domaine)')) {
        Write-PSMLog -Level INFO -Message "WhatIf : PSMConfigureAppLocker.xml serait patche (comptes de domaine)."
        return $false
    }

    if (-not (Test-Path $path)) {
        throw "PSMConfigureAppLocker.xml introuvable : $path (genere a l'INSTALLATION ; verifier Hardening.AppLockerConfigPath / dossier d'install)."
    }

    # Sauvegarde de l'original une seule fois ; on repart TOUJOURS de l'original.
    $backup = "$path.orig"
    if (-not (Test-Path $backup)) { Copy-Item -Path $path -Destination $backup -Force }
    [xml]$doc = Get-Content -Path $backup -Raw

    $attr = Get-PSMConfigValue -Config $h -Key 'AccountAttribute'
    foreach ($p in $pairs) {
        $xpath = $p[0]; $value = [string]$p[1]
        if (-not $xpath) {
            throw "settings.psd1 : Hardening XPath manquant pour le compte '$value' (renseigner Hardening.PSMConnectXPath / PSMAdminConnectXPath)."
        }
        $node = $doc.SelectSingleNode($xpath)
        if (-not $node) {
            throw "PSMConfigureAppLocker.xml : noeud introuvable (XPath: $xpath). Ajuster settings.psd1 Hardening.* selon le fichier genere."
        }
        if ($attr) { [void]$node.SetAttribute($attr, $value) }
        else       { $node.InnerText = $value }
        Write-PSMLog -Level INFO -Message "AppLocker : '$xpath' <- '$value'"
    }

    $doc.Save($path)
    Write-PSMLog -Level INFO -Message "PSMConfigureAppLocker.xml patche (comptes de domaine) -> $path"
    return $true
}

function Invoke-PSMHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        $ZoneConfig     # comptes PSMConnect/PSMAdminConnect de la zone (facultatif)
    )
    # Comptes de session de DOMAINE : patch en place de PSMConfigureAppLocker.xml
    # AVANT de lancer le stage (le step RunApplocker le relit ensuite).
    Set-PSMConnectAccounts -Settings $Settings -ZoneConfig $ZoneConfig | Out-Null

    $stage = Resolve-PSMStageConfig -Settings $Settings -SourcesRoot $SourcesRoot -StageKey 'Hardening'
    return Invoke-PSMStage -StageName 'Hardening' `
                           -ExecuteStagePath $stage.ExecuteStage `
                           -ConfigFilePath   $stage.ConfigFilePath
}

Export-ModuleMember -Function Invoke-PSMHardening, Set-PSMConnectAccounts
