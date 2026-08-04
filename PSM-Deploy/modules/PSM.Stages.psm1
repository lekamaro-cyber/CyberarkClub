<#
.SYNOPSIS
    Pilotage "etape par etape" du framework d'automatisation CyberArk
    (InstallationAutomation\Execute-Stage.ps1).

.DESCRIPTION
    Notre orchestrateur appelle CyberArk stage par stage (Installation,
    PostInstallation, Registration, Hardening...). Chaque stage est decrit par
    son fichier de config XML (rempli par l'equipe). Execute-Stage.ps1 :
      - s'appelle avec  -configFilePath <xml> -silentMode Silent -displayJson
      - accepte le mot de passe Vault via -spwdObj (SecureString) [Registration]
      - renvoie un JSON : { isSucceeded (0=OK,1=Warn,2=Err), errorData, logPath,
        restartRequired }
      - gere sa PROPRE reprise par etape (registre Recovery) ; c'est a l'APPELANT
        de rebooter quand restartRequired = $true (repris ensuite via notre tache
        AtLogOn qui relance le meme stage).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PSMStagePaths {
    <#
        Construit les chemins du framework CyberArk pour un stage donne
        (racine media -> InstallationAutomation -> Execute-Stage.ps1 + config XML).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        [Parameter(Mandatory)] [string] $StageKey
    )
    $mediaPsm = Join-Path $SourcesRoot $Settings.Install.MediaRelativePath
    $iaRoot   = Join-Path $mediaPsm  $Settings.Install.InstallationAutomationSubPath
    $execute  = Join-Path $iaRoot    'Execute-Stage.ps1'

    $rel = $Settings.Install.Stages[$StageKey]
    if (-not $rel) {
        throw "Aucun fichier de config declare pour le stage '$StageKey' (settings.psd1 Install.Stages)."
    }
    $config = Join-Path $iaRoot $rel

    return [pscustomobject]@{
        MediaPsm     = $mediaPsm
        IaRoot       = $iaRoot
        ExecuteStage = $execute
        Config       = $config
    }
}

function Update-PSMStageXml {
    <#
        Injecte des valeurs (depuis notre config) dans un *Config.xml de stage
        CyberArk et enregistre une COPIE patchee dans state\config\<Stage>\.
        Le media reste intact -> deposer une nouvelle source ne demande aucune
        edition manuelle des XML.

        -Injections : table @{ '<xpath>' = @{ Attribute='Value'; Value='...' } }
                      (Attribute vide => on ecrit l'InnerText du noeud).
        Renvoie le chemin de la copie patchee a passer a Execute-Stage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]    $SourceConfigPath,
        [Parameter(Mandatory)] [hashtable] $Injections,
        [Parameter(Mandatory)] [string]    $StateDir,
        [Parameter(Mandatory)] [string]    $StageName
    )
    if (-not (Test-Path $SourceConfigPath)) {
        throw "Config '$StageName' introuvable : $SourceConfigPath (verifier le media)."
    }

    [xml]$doc = Get-Content -Path $SourceConfigPath -Raw

    foreach ($xpath in $Injections.Keys) {
        $spec  = $Injections[$xpath]
        $value = [string]$spec.Value
        $node  = $doc.SelectSingleNode($xpath)
        if (-not $node) {
            # Aide au diagnostic : liste les Parameter disponibles pour ajuster le XPath.
            $names = ($doc.SelectNodes('//Parameter') | ForEach-Object { $_.Name }) -join ', '
            throw ("Config '$StageName' : noeud introuvable (XPath: $xpath). " +
                   "Parametres disponibles : $names. Ajuster settings.psd1.")
        }
        if ($spec.Attribute) { [void]$node.SetAttribute($spec.Attribute, $value) }
        else                 { $node.InnerText = $value }
        Write-PSMLog -Level INFO -Message "Config '$StageName' : '$xpath' <- '$value'"
    }

    $outDir = Join-Path $StateDir (Join-Path 'config' $StageName)
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $outXml = Join-Path $outDir (Split-Path $SourceConfigPath -Leaf)
    $doc.Save($outXml)
    Write-PSMLog -Level INFO -Message "Config '$StageName' patchee -> $outXml"
    return $outXml
}

function Resolve-PSMStageConfig {
    <#
        Point d'entree unique pour obtenir les chemins d'un stage CyberArk PRETS a
        etre passes a Invoke-PSMStage :
          - resout Execute-Stage.ps1 + le *Config.xml du media (Get-PSMStagePaths) ;
          - si des injections sont definies pour ce stage (valeurs STATIQUES depuis
            settings.psd1 Install.Injections[<StageKey>], fusionnees avec les valeurs
            DYNAMIQUES passees via -ExtraInjections), patche une COPIE dans
            state\config\<Stage>\ (media intact) via Update-PSMStageXml ;
          - sinon renvoie le XML du media tel quel (comportement historique).

        -ExtraInjections : injections dynamiques (ex. adresse Vault de la zone),
                           meme forme que Update-PSMStageXml (@{ '<xpath>' = @{ Attribute; Value } }).
                           Elles priment sur les injections statiques en cas de meme XPath.
        Renvoie [pscustomobject]@{ ExecuteStage; ConfigFilePath }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [string] $SourcesRoot,
        [Parameter(Mandatory)] [string] $StageKey,
        [hashtable] $ExtraInjections
    )
    $paths      = Get-PSMStagePaths -Settings $Settings -SourcesRoot $SourcesRoot -StageKey $StageKey
    $configPath = $paths.Config

    # Injections statiques (optionnelles) declarees dans settings.psd1.
    $injections = @{}
    $staticSet = $null
    if ($Settings.Install.PSObject.Properties.Name -contains 'Injections') {
        $staticSet = $Settings.Install.Injections
    }
    elseif ($Settings.Install -is [hashtable] -and $Settings.Install.ContainsKey('Injections')) {
        $staticSet = $Settings.Install.Injections
    }
    if ($staticSet -and $staticSet[$StageKey]) {
        foreach ($xpath in $staticSet[$StageKey].Keys) {
            $injections[$xpath] = $staticSet[$StageKey][$xpath]
        }
    }

    # Injections dynamiques (priment en cas de conflit de XPath).
    if ($ExtraInjections) {
        foreach ($xpath in $ExtraInjections.Keys) {
            $injections[$xpath] = $ExtraInjections[$xpath]
        }
    }

    if ($injections.Count -gt 0) {
        $configPath = Update-PSMStageXml -SourceConfigPath $paths.Config `
                        -Injections $injections `
                        -StateDir   (Get-PSMStateDir) `
                        -StageName  $StageKey
    }

    return [pscustomobject]@{
        ExecuteStage   = $paths.ExecuteStage
        ConfigFilePath = $configPath
    }
}

function Invoke-PSMStage {
    <#
        Execute un stage CyberArk via Execute-Stage.ps1 et renvoie un objet :
          { StageName, Succeeded, RestartRequired, LogPath, ErrorData, Raw }
        Respecte -WhatIf (ne lance rien, renvoie un resultat neutre).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $StageName,
        [Parameter(Mandatory)] [string] $ExecuteStagePath,
        [Parameter(Mandatory)] [string] $ConfigFilePath,
        [securestring] $VaultPassword
    )

    if (-not (Test-Path $ExecuteStagePath)) {
        throw "Execute-Stage.ps1 introuvable : $ExecuteStagePath (verifier le media dans media\PSM)."
    }
    if (-not (Test-Path $ConfigFilePath)) {
        throw "Config du stage '$StageName' introuvable : $ConfigFilePath (a remplir par l'equipe)."
    }

    if (-not $PSCmdlet.ShouldProcess("Stage CyberArk '$StageName'", 'Executer Execute-Stage.ps1')) {
        return [pscustomobject]@{
            StageName = $StageName; Succeeded = $true; RestartRequired = $false
            LogPath = $null; ErrorData = $null; Raw = $null; WhatIf = $true
        }
    }

    Write-PSMLog -Level INFO -Message "Stage CyberArk '$StageName' : execution (Execute-Stage.ps1)..."

    $params = @{
        configFilePath = $ConfigFilePath
        silentMode     = 'Silent'
        displayJson    = $true
    }
    if ($VaultPassword) { $params['spwdObj'] = $VaultPassword }

    # Execute-Stage.ps1 s'appuie sur son propre dossier (modules de stage).
    $iaDir = Split-Path $ExecuteStagePath -Parent
    Push-Location $iaDir
    try {
        # IMPORTANT : les scripts CyberArk ne sont PAS ecrits pour StrictMode.
        # Nos modules l'activent (Latest) et le script enfant en heriterait, ce qui
        # provoque des erreurs (NullReference / proprietes absentes). On le desactive
        # pour l'appel enfant (portee locale a cette fonction).
        Set-StrictMode -Off
        $raw = & $ExecuteStagePath @params
    }
    catch {
        $cyberLog = Get-ChildItem "$env:windir\Temp\PSM$StageName-*.log" -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $hint = if ($cyberLog) { " Log CyberArk : $($cyberLog.FullName)" } else { '' }
        throw "Stage '$StageName' : Execute-Stage.ps1 a leve une exception : $($_.Exception.Message).$hint"
    }
    finally {
        Pop-Location
    }

    # Execute-Stage renvoie le resultat en JSON (via 'return ... | ConvertTo-Json').
    $text   = ($raw | Out-String).Trim()
    $result = $null
    try {
        $result = $text | ConvertFrom-Json
    }
    catch {
        $m = [regex]::Match($text, '(?s)\{.*\}')
        if ($m.Success) { $result = $m.Value | ConvertFrom-Json }
    }
    if (-not $result) {
        throw "Stage '$StageName' : resultat JSON illisible depuis Execute-Stage. Sortie brute : $text"
    }

    # isSucceeded : 0=Success, 1=Warning, 2=Error
    $succeeded = ($result.isSucceeded -eq 0) -or ($result.isSucceeded -eq 1)

    if ($result.logPath) {
        Write-PSMLog -Level INFO -Message "Stage '$StageName' - log CyberArk : $($result.logPath)"
    }
    if ($result.isSucceeded -eq 1) {
        Write-PSMLog -Level WARN -Message "Stage '$StageName' termine avec avertissement(s) - voir le log CyberArk."
    }
    if (-not $succeeded) {
        Write-PSMLog -Level ERROR -Message "Stage '$StageName' en echec : $($result.errorData)"
    }

    return [pscustomobject]@{
        StageName       = $StageName
        Succeeded       = $succeeded
        RestartRequired = [bool]$result.restartRequired
        LogPath         = $result.logPath
        ErrorData       = $result.errorData
        Raw             = $result
    }
}

Export-ModuleMember -Function Get-PSMStagePaths, Resolve-PSMStageConfig, Invoke-PSMStage, Update-PSMStageXml
