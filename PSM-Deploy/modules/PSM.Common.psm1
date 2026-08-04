<#
.SYNOPSIS
    Fonctions communes du deploiement PSM : idempotence, journalisation,
    masquage des secrets, machine a etats / reprise apres reboot, confirmations.

.NOTES
    Module socle reutilise par toutes les phases.
    Modele d'idempotence facon Ansible : chaque action = Test -> Set,
    avec restitution OK / CHANGED / FAILED.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Etat interne du module (scope module)
# ---------------------------------------------------------------------------
$script:Secrets       = New-Object System.Collections.Generic.List[string]
$script:StepResults   = New-Object System.Collections.Generic.List[object]
$script:LogTextPath   = $null
$script:LogJsonPath   = $null
$script:StatePath     = $null

# ---------------------------------------------------------------------------
# Journalisation + masquage des secrets
# ---------------------------------------------------------------------------

function Initialize-PSMLogging {
    <#
        Prepare les fichiers de log (transcript texte + log structure JSON).
        A appeler une fois au demarrage de l'orchestrateur.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $LogDirectory
    )
    if (-not (Test-Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:LogTextPath = Join-Path $LogDirectory "deploy-$stamp.log"
    $script:LogJsonPath = Join-Path $LogDirectory "deploy-$stamp.jsonl"
    Write-PSMLog -Level INFO -Message "Journalisation initialisee ($script:LogTextPath)"
}

function Register-PSMSecret {
    <#
        Enregistre une valeur sensible afin qu'elle soit masquee dans les logs.
        Accepte string ou SecureString.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Secret)

    $plain = $null
    if ($Secret -is [securestring]) {
        $plain = [System.Net.NetworkCredential]::new('', $Secret).Password
    }
    else {
        $plain = [string]$Secret
    }
    if (-not [string]::IsNullOrEmpty($plain) -and -not $script:Secrets.Contains($plain)) {
        $script:Secrets.Add($plain)
    }
}

function Protect-PSMMessage {
    # Remplace toute valeur enregistree comme secret par des asterisques.
    param([string] $Message)
    foreach ($s in $script:Secrets) {
        if ($s) { $Message = $Message.Replace($s, '********') }
    }
    return $Message
}

function Write-PSMLog {
    [CmdletBinding()]
    param(
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR', 'OK', 'CHANGED')]
        [string] $Level = 'INFO',
        [Parameter(Mandatory)] [string] $Message
    )
    $safe = Protect-PSMMessage -Message $Message
    $ts   = Get-Date -Format 'o'
    $line = "[{0}] [{1,-7}] {2}" -f $ts, $Level, $safe

    switch ($Level) {
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'WARN'    { Write-Host $line -ForegroundColor Yellow }
        'OK'      { Write-Host $line -ForegroundColor Green }
        'CHANGED' { Write-Host $line -ForegroundColor Cyan }
        'DEBUG'   { Write-Verbose $line }
        default   { Write-Host $line }
    }

    if ($script:LogTextPath) { Add-Content -Path $script:LogTextPath -Value $line }
    if ($script:LogJsonPath) {
        $obj = [ordered]@{ ts = $ts; level = $Level; message = $safe }
        Add-Content -Path $script:LogJsonPath -Value ($obj | ConvertTo-Json -Compress)
    }
}

# ---------------------------------------------------------------------------
# Elevation
# ---------------------------------------------------------------------------

function Test-PSMElevation {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [Security.Principal.WindowsPrincipal]::new($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-PSMElevation {
    if (-not (Test-PSMElevation)) {
        throw "Le script doit etre execute avec des droits administrateur (eleve)."
    }
    Write-PSMLog -Level OK -Message "Contexte administrateur confirme."
}

# ---------------------------------------------------------------------------
# Coeur d'idempotence : Test -> Set
# ---------------------------------------------------------------------------

function Invoke-IdempotentStep {
    <#
        Execute une etape idempotente.
        -Test   : scriptblock renvoyant $true si l'etat cible est deja atteint.
        -Action : scriptblock appliquant l'etat cible (uniquement si Test = $false).
        Respecte -WhatIf / -Confirm via ShouldProcess.
        Renvoie : 'OK' (deja conforme), 'CHANGED' (applique), 'WHATIF', 'FAILED'.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [string]      $Name,
        [Parameter(Mandatory)] [scriptblock] $Test,
        [Parameter(Mandatory)] [scriptblock] $Action
    )

    $status = 'OK'
    try {
        if (& $Test) {
            Write-PSMLog -Level OK -Message "[$Name] deja conforme."
            $status = 'OK'
        }
        elseif ($PSCmdlet.ShouldProcess($Name, 'Appliquer')) {
            & $Action
            Write-PSMLog -Level CHANGED -Message "[$Name] applique."
            $status = 'CHANGED'
        }
        else {
            Write-PSMLog -Level INFO -Message "[$Name] non conforme -> serait modifie (WhatIf)."
            $status = 'WHATIF'
        }
    }
    catch {
        Write-PSMLog -Level ERROR -Message "[$Name] echec : $($_.Exception.Message)"
        $status = 'FAILED'
        $script:StepResults.Add([pscustomobject]@{ Step = $Name; Status = $status })
        throw   # fail-fast (cf. spec)
    }

    $script:StepResults.Add([pscustomobject]@{ Step = $Name; Status = $status })
    return $status
}

function Write-PSMSummary {
    # Recapitulatif final facon Ansible (Etape | Statut).
    Write-Host ''
    Write-Host '==================== RECAPITULATIF ====================' -ForegroundColor White
    foreach ($r in $script:StepResults) {
        $color = switch ($r.Status) {
            'OK'      { 'Green' }
            'CHANGED' { 'Cyan' }
            'WHATIF'  { 'Yellow' }
            'FAILED'  { 'Red' }
            default   { 'Gray' }
        }
        Write-Host ("  {0,-40} {1}" -f $r.Step, $r.Status) -ForegroundColor $color
    }
    Write-Host '=======================================================' -ForegroundColor White
}

# ---------------------------------------------------------------------------
# Machine a etats / reprise apres reboot
# ---------------------------------------------------------------------------

function Initialize-PSMState {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $StateDirectory)
    if (-not (Test-Path $StateDirectory)) {
        New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
    }
    $script:StatePath = Join-Path $StateDirectory 'progress.json'
    if (-not (Test-Path $script:StatePath)) {
        @{ completedPhases = @() } | ConvertTo-Json | Set-Content -Path $script:StatePath
    }
}

function Get-PSMConfigValue {
    <#
        Lit une cle FACULTATIVE d'une table de config (hashtable psd1 ou
        pscustomobject) de facon sure sous StrictMode ; renvoie $null si absente.
        Utile pour des cles optionnelles (ex. comptes PSMConnect d'une zone).
    #>
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [string] $Key
    )
    if ($null -eq $Config) { return $null }
    if ($Config -is [System.Collections.IDictionary]) {
        if ($Config.Contains($Key)) { return $Config[$Key] }
        return $null
    }
    $prop = $Config.PSObject.Properties[$Key]
    if ($prop) { return $prop.Value }
    return $null
}

function Get-PSMInstallPaths {
    <#
        Derive les chemins d'installation depuis la SOURCE UNIQUE Install.InstallDir
        (settings.psd1). Evite de repeter le dossier d'install a plusieurs endroits :
          - InstallDir           : dossier d'installation (injecte dans InstallationConfig.xml)
          - PsmDir               : <InstallDir>\PSM
          - RecordingDir         : Install.RecordingDir si defini, sinon <PsmDir>\Recordings
          - AppLockerConfigPath  : <PsmDir>\Hardening\PSMConfigureAppLocker.xml
        Un seul changement de InstallDir suffit a tout aligner.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Settings)

    $install    = Get-PSMConfigValue -Config $Settings -Key 'Install'
    $installDir = Get-PSMConfigValue -Config $install  -Key 'InstallDir'
    if (-not $installDir) { throw "settings.psd1 : Install.InstallDir non defini (source unique du dossier d'installation)." }

    $psmDir = Join-Path $installDir 'PSM'
    $rec    = Get-PSMConfigValue -Config $install -Key 'RecordingDir'
    if (-not $rec) { $rec = Join-Path $psmDir 'Recordings' }

    return [pscustomobject]@{
        InstallDir          = $installDir
        PsmDir              = $psmDir
        RecordingDir        = $rec
        AppLockerConfigPath = Join-Path $psmDir 'Hardening\PSMConfigureAppLocker.xml'
    }
}

function Get-PSMStateDir {
    # Renvoie le dossier d'etat (parent de progress.json), fixe par Initialize-PSMState.
    # Utilise par le moteur de stages pour ecrire les copies patchees des *Config.xml.
    if (-not $script:StatePath) {
        throw "Etat non initialise : appeler Initialize-PSMState avant Get-PSMStateDir."
    }
    return Split-Path $script:StatePath -Parent
}

function Reset-PSMState {
    <#
        Remet l'etat de deploiement a zero : progress.json vide (aucune phase
        terminee) + purge des copies patchees des *Config.xml (regenerees au
        prochain passage). Ne touche NI au media, NI aux logs, NI a la machine.
        Sert a "repartir de zero" apres avoir desinstalle/nettoye le PSM, sans
        laisser un etat perime faire sauter des phases (ex. l'Installation reelle).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not $script:StatePath) {
        throw "Etat non initialise : appeler Initialize-PSMState avant Reset-PSMState."
    }
    if ($PSCmdlet.ShouldProcess($script:StatePath, "Reinitialiser l'etat (progress.json)")) {
        @{ completedPhases = @() } | ConvertTo-Json | Set-Content -Path $script:StatePath
        $configDir = Join-Path (Split-Path $script:StatePath -Parent) 'config'
        if (Test-Path $configDir) { Remove-Item -Path $configDir -Recurse -Force }
        Write-PSMLog -Level WARN -Message "Etat reinitialise : le deploiement repartira de la premiere phase (PreVol)."
    }
}

function Test-PSMPhaseComplete {
    param([Parameter(Mandatory)] [string] $Phase)
    $state = Get-Content $script:StatePath -Raw | ConvertFrom-Json
    return ($state.completedPhases -contains $Phase)
}

function Set-PSMPhaseComplete {
    param([Parameter(Mandatory)] [string] $Phase)
    $state = Get-Content $script:StatePath -Raw | ConvertFrom-Json
    $list  = @($state.completedPhases) + $Phase | Select-Object -Unique
    $state.completedPhases = $list
    $state | ConvertTo-Json | Set-Content -Path $script:StatePath
    Write-PSMLog -Level INFO -Message "Phase '$Phase' marquee comme terminee."
}

function Get-PSMStateValue {
    # Lit une valeur libre de l'etat (progress.json) ; $null si absente.
    param([Parameter(Mandatory)] [string] $Name)
    $state = Get-Content $script:StatePath -Raw | ConvertFrom-Json
    if ($state.PSObject.Properties.Name -contains $Name) { return $state.$Name }
    return $null
}

function Set-PSMStateValue {
    # Persiste une valeur libre dans l'etat (progress.json), sans toucher aux autres cles.
    param([Parameter(Mandatory)] [string] $Name, $Value)
    $state = Get-Content $script:StatePath -Raw | ConvertFrom-Json
    if ($state.PSObject.Properties.Name -contains $Name) {
        $state.$Name = $Value
    }
    else {
        $state | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
    $state | ConvertTo-Json | Set-Content -Path $script:StatePath
}

function Register-PSMResumeTask {
    <#
        Cree une tache planifiee qui relance l'orchestrateur A L'OUVERTURE DE SESSION
        de l'admin installateur (reprise supervisee), dans SA session interactive :
        les prompts (Get-Credential PVWA) fonctionnent et aucun secret n'est stocke.
        Reprend automatiquement a la premiere phase non terminee.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $ScriptPath,
        [Parameter(Mandatory)] [string] $Zone,
        [string] $User     = [Security.Principal.WindowsIdentity]::GetCurrent().Name,
        [string] $TaskName = 'PSM-Deploy-Resume'
    )
    if ($PSCmdlet.ShouldProcess($TaskName, 'Creer tache de reprise (AtLogOn)')) {
        # -Zone est transmis explicitement (sinon parametre obligatoire bloquant au reboot).
        $argument  = "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$ScriptPath`" -Resume -Zone $Zone"
        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argument
        $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $User
        $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Principal $principal -Force | Out-Null
        Write-PSMLog -Level INFO -Message "Tache de reprise '$TaskName' enregistree (AtLogOn, utilisateur $User, zone $Zone)."
    }
}

function Unregister-PSMResumeTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([string] $TaskName = 'PSM-Deploy-Resume')
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        if ($PSCmdlet.ShouldProcess($TaskName, 'Supprimer tache de reprise')) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-PSMLog -Level INFO -Message "Tache de reprise '$TaskName' supprimee."
        }
    }
}

# ---------------------------------------------------------------------------
# Confirmation interactive de la zone (anti-bourde : mauvaise zone = mauvais Vault)
# ---------------------------------------------------------------------------

function Confirm-PSMZone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $ZoneConfig,
        [switch] $NonInteractive
    )
    Write-Host ''
    Write-Host "Zone ciblee : $($ZoneConfig.Name)"        -ForegroundColor Yellow
    Write-Host "  PVWA     : $($ZoneConfig.PvwaUrl)"
    Write-Host "  Auth     : $($ZoneConfig.PvwaAuthMethod)"
    Write-Host "  Hostname : $env:COMPUTERNAME"
    if ($NonInteractive) {
        Write-PSMLog -Level WARN -Message "Mode non interactif : zone '$($ZoneConfig.Name)' acceptee sans confirmation."
        return
    }
    $answer = Read-Host "Confirmer le deploiement sur cette zone ? (taper OUI)"
    if ($answer -ne 'OUI') {
        throw "Zone non confirmee par l'operateur. Abandon."
    }
    Write-PSMLog -Level OK -Message "Zone '$($ZoneConfig.Name)' confirmee."
}

Export-ModuleMember -Function *-PSM*, Invoke-IdempotentStep
