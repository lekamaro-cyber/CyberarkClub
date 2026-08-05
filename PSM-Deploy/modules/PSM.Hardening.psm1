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
        les VARIABLES en tete des scripts de hardening CyberArk (fichiers GENERES A
        L'INSTALLATION dans <InstallDir>\PSM\Hardening, PAS dans le media) :
          - PSMHardening.ps1          : $PSM_CONNECT_USER / $PSM_ADMIN_CONNECT_USER
          - PSMConfigureAppLocker.ps1 : $PSM_CONNECT      / $PSM_ADMIN_CONNECT
        (mapping configurable : settings.psd1 Hardening.ScriptAccountVariables).

        Patch EN PLACE avec sauvegarde '.orig' faite une seule fois ; on repart
        TOUJOURS de l'original -> re-jeu idempotent, pas de cumul. Les mots de
        passe ne sont PAS touches (Safe PSM cote Vault).

        INACTIF si la zone ne fournit aucun compte : ne fait rien et renvoie $false.
        Renvoie $true si au moins un fichier a ete patche.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        $ZoneConfig
    )
    if (-not $ZoneConfig) { return $false }

    $psmConnect = Get-PSMConfigValue -Config $ZoneConfig -Key 'PSMConnectUserName'
    $psmAdmin   = Get-PSMConfigValue -Config $ZoneConfig -Key 'PSMAdminConnectUserName'
    if (-not $psmConnect -and -not $psmAdmin) { return $false }   # rien a injecter

    $h = Get-PSMConfigValue -Config $Settings -Key 'Hardening'
    if (-not $h) { throw "settings.psd1 : bloc 'Hardening' absent (comptes de zone fournis)." }
    $varMap = Get-PSMConfigValue -Config $h -Key 'ScriptAccountVariables'
    if (-not $varMap) { throw "settings.psd1 : Hardening.ScriptAccountVariables non defini (comptes de zone fournis)." }

    # Dossier Hardening explicite si fourni, sinon DERIVE de Install.InstallDir.
    $hardDir = Get-PSMConfigValue -Config $h -Key 'HardeningDir'
    if (-not $hardDir) { $hardDir = (Get-PSMInstallPaths -Settings $Settings).HardeningDir }

    $patched = $false
    foreach ($fileName in $varMap.Keys) {
        $filePath = Join-Path $hardDir $fileName
        $map      = $varMap[$fileName]

        # Variables a ecrire dans CE fichier (seulement les comptes fournis).
        $todo = @()
        $vConnect = Get-PSMConfigValue -Config $map -Key 'Connect'
        $vAdmin   = Get-PSMConfigValue -Config $map -Key 'AdminConnect'
        if ($psmConnect -and $vConnect) { $todo += ,@($vConnect, $psmConnect) }
        if ($psmAdmin   -and $vAdmin)   { $todo += ,@($vAdmin,   $psmAdmin) }
        if (-not $todo) { continue }

        if (-not $PSCmdlet.ShouldProcess($filePath, 'Patcher les variables de comptes PSM (domaine)')) {
            Write-PSMLog -Level INFO -Message "WhatIf : '$fileName' serait patche (comptes de domaine)."
            continue
        }
        if (-not (Test-Path $filePath)) {
            throw "'$fileName' introuvable : $filePath (genere a l'INSTALLATION ; verifier Install.InstallDir / Hardening.HardeningDir)."
        }

        # Sauvegarde de l'original une seule fois ; on repart TOUJOURS de l'original.
        $backup = "$filePath.orig"
        if (-not (Test-Path $backup)) { Copy-Item -Path $filePath -Destination $backup -Force }
        $content = Get-Content -Path $backup -Raw

        foreach ($t in $todo) {
            $varName = $t[0]; $value = [string]$t[1]
            # Premiere affectation de la variable : $VAR = "..." ou '...' (quote preservee).
            $pattern = '(?m)^(\s*\$' + [regex]::Escape($varName) + '\s*=\s*)(["''])(.*?)\2'
            $rx = [regex]$pattern
            if (-not $rx.IsMatch($content)) {
                # Aide au diagnostic : liste les affectations candidates du fichier.
                $cands = ([regex]::Matches($content, '(?m)^\s*\$(\w*PSM\w*)\s*=') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique) -join ', '
                throw ("'$fileName' : variable `$$varName introuvable. Variables candidates : $cands. " +
                       'Ajuster settings.psd1 Hardening.ScriptAccountVariables.')
            }
            $safeValue = $value.Replace('$', '$$')   # neutralise les substitutions regex
            $content   = $rx.Replace($content, ('${1}${2}' + $safeValue + '${2}'), 1)
            Write-PSMLog -Level INFO -Message "'$fileName' : `$$varName <- '$value'"
        }

        Set-Content -Path $filePath -Value $content -NoNewline
        Write-PSMLog -Level INFO -Message "'$fileName' patche (comptes de domaine) -> $filePath"
        $patched = $true
    }
    return $patched
}

function Invoke-PSMHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        $ZoneConfig     # comptes PSMConnect/PSMAdminConnect de la zone (facultatif)
    )
    # Comptes de session de DOMAINE : patch en place des variables de
    # PSMHardening.ps1 / PSMConfigureAppLocker.ps1 AVANT de lancer le stage
    # (les steps RunHardening / RunApplocker relisent ces scripts ensuite).
    Set-PSMConnectAccounts -Settings $Settings -ZoneConfig $ZoneConfig | Out-Null

    $stage = Resolve-PSMStageConfig -Settings $Settings -SourcesRoot $SourcesRoot -StageKey 'Hardening'
    return Invoke-PSMStage -StageName 'Hardening' `
                           -ExecuteStagePath $stage.ExecuteStage `
                           -ConfigFilePath   $stage.ConfigFilePath
}

Export-ModuleMember -Function Invoke-PSMHardening, Set-PSMConnectAccounts
