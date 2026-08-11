<#
    Tests Pester du squelette de deploiement PSM.
    But : verifier la coherence structurelle et le contrat d'idempotence
    (un 2e passage d'une etape deja conforme = aucun changement).

    Lancer :  Invoke-Pester -Path .\tests\Deploy-PSM.Tests.ps1
#>

$root = Split-Path $PSScriptRoot -Parent

Describe 'Structure du dossier sources' {
    It 'Contient l orchestrateur' {
        Test-Path (Join-Path $root 'Deploy-PSM.ps1') | Should -BeTrue
    }
    It 'Contient les fichiers de config attendus' {
        foreach ($f in 'settings.psd1', 'zones.psd1', 'software.psd1') {
            Test-Path (Join-Path $root "config\$f") | Should -BeTrue
        }
    }
    It 'Charge les modules sans erreur' {
        { Get-ChildItem (Join-Path $root 'modules') -Filter '*.psm1' |
            ForEach-Object { Import-Module $_.FullName -Force } } | Should -Not -Throw
    }
}

Describe 'Contrat d idempotence (Invoke-IdempotentStep)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')
    }
    It 'Renvoie OK quand l etat cible est deja atteint' {
        $r = Invoke-IdempotentStep -Name 'deja-conforme' -Test { $true } -Action { throw 'ne doit pas etre appele' }
        $r | Should -Be 'OK'
    }
    It 'Renvoie CHANGED quand l action est appliquee' {
        $script:flag = $false
        $r = Invoke-IdempotentStep -Name 'a-appliquer' -Test { $script:flag } -Action { $script:flag = $true } -Confirm:$false
        $r | Should -Be 'CHANGED'
    }
    It 'Est idempotent au 2e passage (CHANGED puis OK)' {
        $script:flag = $false
        $test   = { $script:flag }
        $action = { $script:flag = $true }
        Invoke-IdempotentStep -Name 'idem' -Test $test -Action $action -Confirm:$false | Should -Be 'CHANGED'
        Invoke-IdempotentStep -Name 'idem' -Test $test -Action $action -Confirm:$false | Should -Be 'OK'
    }
}

Describe 'Reinitialisation de l etat (-Reset / partir de zero)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')
        Initialize-PSMState   -StateDirectory (Join-Path $TestDrive 'state-reset')
    }
    It 'Vide les phases terminees' {
        Set-PSMPhaseComplete 'PreVol'
        Set-PSMPhaseComplete 'Installation'
        Test-PSMPhaseComplete 'Installation' | Should -BeTrue

        Reset-PSMState -Confirm:$false

        Test-PSMPhaseComplete 'PreVol'       | Should -BeFalse
        Test-PSMPhaseComplete 'Installation' | Should -BeFalse
    }
}

Describe 'Config zones' {
    It 'Definit au moins 2 zones avec les cles PVWA requises' {
        $z = Import-PowerShellDataFile (Join-Path $root 'config\zones.psd1')
        $z.Keys.Count | Should -BeGreaterOrEqual 2
        foreach ($k in $z.Keys) {
            foreach ($req in 'PvwaUrl','PvwaAuthMethod','SkipCertificateCheck') {
                $z[$k].ContainsKey($req) | Should -BeTrue
            }
        }
    }
}

Describe 'Module Stages (pilotage Execute-Stage.ps1 de CyberArk)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
        Import-Module (Join-Path $root 'modules\PSM.Stages.psm1') -Force
    }
    It 'Expose le moteur de stage, le calcul de chemins et l injection' {
        foreach ($fn in 'Invoke-PSMStage','Get-PSMStagePaths','Resolve-PSMStageConfig','Update-PSMStageXml') {
            Get-Command $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    It 'Calcule les chemins de stage depuis settings.psd1' {
        $s = Import-PowerShellDataFile (Join-Path $root 'config\settings.psd1')
        $p = Get-PSMStagePaths -Settings $s -SourcesRoot $root -StageKey 'Installation'
        $p.ExecuteStage | Should -Match 'InstallationAutomation'
        $p.Config       | Should -Match 'InstallationConfig\.xml'
    }
}

Describe 'Injection XML des stages (config pilotee, media intact)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1')  -Force
        Import-Module (Join-Path $root 'modules\PSM.Stages.psm1')  -Force
        Import-Module (Join-Path $root 'modules\PSM.Install.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')

        # Media factice : layout media\PSM\InstallationAutomation\<Stage>\...
        $script:src   = Join-Path $TestDrive 'sources'
        $script:iaDir = Join-Path $script:src 'media\PSM\InstallationAutomation'
        $regDir       = Join-Path $script:iaDir 'Registration'
        $hardDir      = Join-Path $script:iaDir 'Hardening'
        $postDir      = Join-Path $script:iaDir 'PostInstallation'
        $instDir      = Join-Path $script:iaDir 'Installation'
        New-Item -ItemType Directory -Path $regDir, $hardDir, $postDir, $instDir -Force | Out-Null
        # Stub Execute-Stage.ps1 : renvoie un JSON de succes (isSucceeded=0).
        Set-Content -Path (Join-Path $script:iaDir 'Execute-Stage.ps1') -Value @'
param($configFilePath, $silentMode, $displayJson, $spwdObj)
'{"isSucceeded":0,"restartRequired":false,"logPath":null,"errorData":null}'
'@
        $script:regXml  = Join-Path $regDir  'RegistrationConfig.xml'
        $script:hardXml = Join-Path $hardDir 'HardeningConfig.xml'
        $script:postXml = Join-Path $postDir 'PostInstallationConfig.xml'
        $script:instXml = Join-Path $instDir 'InstallationConfig.xml'
        Set-Content -Path $script:regXml  -Value '<Configuration><Parameter Name="VaultIP" Value="" /></Configuration>'
        Set-Content -Path $script:hardXml -Value '<Configuration><Parameter Name="Foo" Value="bar" /></Configuration>'
        Set-Content -Path $script:postXml -Value '<Configuration><Parameter Name="PSMConnectUserName" Value="" /><Parameter Name="PSMAdminConnectUserName" Value="" /></Configuration>'
        Set-Content -Path $script:instXml -Value '<Configuration><Parameter Name="InstallationDirectory" Value="C:\Program Files (x86)\CyberArk" /><Parameter Name="RecordingDirectory" Value="C:\rec" /></Configuration>'

        $script:stateDir = Join-Path $TestDrive 'state'
        Initialize-PSMState -StateDirectory $script:stateDir

        $script:settings = @{
            Install = @{
                MediaRelativePath             = 'media\PSM'
                InstallationAutomationSubPath = 'InstallationAutomation'
                InstallDir                    = 'D:\CyberArk'
                RecordingDir                  = ''
                Stages = @{
                    Installation     = 'Installation\InstallationConfig.xml'
                    Registration     = 'Registration\RegistrationConfig.xml'
                    Hardening        = 'Hardening\HardeningConfig.xml'
                    PostInstallation = 'PostInstallation\PostInstallationConfig.xml'
                }
                Injections = @{}
            }
        }
    }

    It 'Injecte le dossier d install derive de Install.InstallDir (source unique)' {
        $r = Invoke-PSMInstall -Settings $script:settings -SourcesRoot $script:src
        $r.Succeeded | Should -BeTrue

        $copy = Join-Path $script:stateDir 'config\Installation\InstallationConfig.xml'
        $doc  = [xml](Get-Content $copy -Raw)
        $doc.SelectSingleNode("//Parameter[@Name='InstallationDirectory']").Value | Should -Be 'D:\CyberArk'
        $doc.SelectSingleNode("//Parameter[@Name='RecordingDirectory']").Value    | Should -Be 'D:\CyberArk\PSM\Recordings'
        # Media inchange.
        ([xml](Get-Content $script:instXml -Raw)).SelectSingleNode("//Parameter[@Name='InstallationDirectory']").Value |
            Should -Be 'C:\Program Files (x86)\CyberArk'
    }

    It 'Patche une COPIE (adresse Vault) sans toucher au media' {
        $extra = @{ "//Parameter[@Name='VaultIP']" = @{ Attribute = 'Value'; Value = '10.0.0.1,10.0.0.2' } }
        $stage = Resolve-PSMStageConfig -Settings $script:settings -SourcesRoot $script:src `
                    -StageKey 'Registration' -ExtraInjections $extra

        # La copie patchee est sous state\config\Registration\, pas dans le media.
        $stage.ConfigFilePath | Should -Match 'state.config.Registration'
        ([xml](Get-Content $stage.ConfigFilePath -Raw)).SelectSingleNode("//Parameter[@Name='VaultIP']").Value |
            Should -Be '10.0.0.1,10.0.0.2'
        # Media inchange.
        ([xml](Get-Content $script:regXml -Raw)).SelectSingleNode("//Parameter[@Name='VaultIP']").Value |
            Should -Be ''
    }

    It 'Renvoie le XML du media quand aucune injection n est definie' {
        $stage = Resolve-PSMStageConfig -Settings $script:settings -SourcesRoot $script:src -StageKey 'Hardening'
        $stage.ConfigFilePath | Should -Be $script:hardXml
    }

    It 'Applique les injections STATIQUES de settings.psd1' {
        $s = @{
            Install = @{
                MediaRelativePath             = 'media\PSM'
                InstallationAutomationSubPath = 'InstallationAutomation'
                Stages     = @{ Hardening = 'Hardening\HardeningConfig.xml' }
                Injections = @{
                    Hardening = @{ "//Parameter[@Name='Foo']" = @{ Attribute = 'Value'; Value = 'baz' } }
                }
            }
        }
        $stage = Resolve-PSMStageConfig -Settings $s -SourcesRoot $script:src -StageKey 'Hardening'
        $stage.ConfigFilePath | Should -Match 'state.config.Hardening'
        ([xml](Get-Content $stage.ConfigFilePath -Raw)).SelectSingleNode("//Parameter[@Name='Foo']").Value |
            Should -Be 'baz'
    }

    It 'Sans ZoneConfig, PostInstallation utilise le XML du media tel quel' {
        $stage = Resolve-PSMStageConfig -Settings $script:settings -SourcesRoot $script:src -StageKey 'PostInstallation'
        $stage.ConfigFilePath | Should -Be $script:postXml
    }
}

Describe 'Comptes de domaine PSMConnect/PSMAdminConnect (variables scripts Hardening)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1')    -Force
        Import-Module (Join-Path $root 'modules\PSM.Hardening.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')

        # Scripts de hardening "generes a l'installation" (extraits simplifies).
        $script:hardDir = Join-Path $TestDrive 'Hardening'
        New-Item -ItemType Directory -Path $script:hardDir -Force | Out-Null
        function Reset-HardeningScripts {
            Set-Content -Path (Join-Path $script:hardDir 'PSMHardening.ps1') -Value @'
# extrait
$PSM_CONNECT_USER       = "PSMConnect"
$PSM_ADMIN_CONNECT_USER = "PSMAdminConnect"
$SUPPORT_WEB_APPLICATIONS = $true
'@
            Set-Content -Path (Join-Path $script:hardDir 'PSMConfigureAppLocker.ps1') -Value @'
# extrait
$PSM_CONNECT       = 'PSMConnect'
$PSM_ADMIN_CONNECT = 'PSMAdminConnect'
'@
            Remove-Item (Join-Path $script:hardDir '*.orig') -ErrorAction SilentlyContinue
        }
        function Get-HardVar([string]$File, [string]$Var) {
            $m = [regex]::Match((Get-Content (Join-Path $script:hardDir $File) -Raw),
                                '(?m)^\s*\$' + $Var + '\s*=\s*(["''])(.*?)\1')
            return $m.Groups[2].Value
        }

        $script:hSettings = @{
            Hardening = @{
                HardeningDir = $script:hardDir
                ScriptAccountVariables = @{
                    'PSMHardening.ps1'          = @{ Connect = 'PSM_CONNECT_USER'; AdminConnect = 'PSM_ADMIN_CONNECT_USER' }
                    'PSMConfigureAppLocker.ps1' = @{ Connect = 'PSM_CONNECT';      AdminConnect = 'PSM_ADMIN_CONNECT' }
                }
            }
        }
    }

    It 'Patche les variables des DEUX scripts avec les comptes de domaine' {
        Reset-HardeningScripts
        $zone = @{ PSMConnectUserName = 'CONTOSO\PSMConnect'; PSMAdminConnectUserName = 'CONTOSO\PSMAdminConnect' }
        $done = Set-PSMConnectAccounts -Settings $script:hSettings -ZoneConfig $zone -Confirm:$false
        $done | Should -BeTrue

        Get-HardVar 'PSMHardening.ps1'          'PSM_CONNECT_USER'       | Should -Be 'CONTOSO\PSMConnect'
        Get-HardVar 'PSMHardening.ps1'          'PSM_ADMIN_CONNECT_USER' | Should -Be 'CONTOSO\PSMAdminConnect'
        Get-HardVar 'PSMConfigureAppLocker.ps1' 'PSM_CONNECT'            | Should -Be 'CONTOSO\PSMConnect'
        Get-HardVar 'PSMConfigureAppLocker.ps1' 'PSM_ADMIN_CONNECT'      | Should -Be 'CONTOSO\PSMAdminConnect'
        # Les autres variables ne sont pas touchees ; sauvegarde .orig intacte.
        (Get-Content (Join-Path $script:hardDir 'PSMHardening.ps1') -Raw) | Should -Match 'SUPPORT_WEB_APPLICATIONS'
        Test-Path (Join-Path $script:hardDir 'PSMHardening.ps1.orig') | Should -BeTrue
        Get-Content (Join-Path $script:hardDir 'PSMHardening.ps1.orig') -Raw | Should -Match '"PSMConnect"'
    }

    It 'Est re-jouable (repart de .orig, pas de double application)' {
        Reset-HardeningScripts
        Set-PSMConnectAccounts -Settings $script:hSettings -ZoneConfig @{ PSMConnectUserName = 'CONTOSO\PSMConnect' } -Confirm:$false | Out-Null
        # 2e passage avec un autre compte : doit refleter le dernier, pas cumuler.
        Set-PSMConnectAccounts -Settings $script:hSettings -ZoneConfig @{ PSMConnectUserName = 'CONTOSO\Autre' } -Confirm:$false | Out-Null
        Get-HardVar 'PSMHardening.ps1' 'PSM_CONNECT_USER' | Should -Be 'CONTOSO\Autre'
    }

    It 'Inactif quand la zone ne fournit aucun compte' {
        Reset-HardeningScripts
        $done = Set-PSMConnectAccounts -Settings $script:hSettings -ZoneConfig @{ } -Confirm:$false
        $done | Should -BeFalse
        Get-HardVar 'PSMHardening.ps1' 'PSM_CONNECT_USER' | Should -Be 'PSMConnect'
        Test-Path (Join-Path $script:hardDir 'PSMHardening.ps1.orig') | Should -BeFalse
    }

    It 'Erreur explicite (avec variables candidates) si la variable est introuvable' {
        Reset-HardeningScripts
        $bad = @{
            Hardening = @{
                HardeningDir = $script:hardDir
                ScriptAccountVariables = @{
                    'PSMHardening.ps1' = @{ Connect = 'VARIABLE_INEXISTANTE' }
                }
            }
        }
        { Set-PSMConnectAccounts -Settings $bad -ZoneConfig @{ PSMConnectUserName = 'CONTOSO\X' } -Confirm:$false } |
            Should -Throw '*candidates*'
    }
}

Describe 'Set-PSMAutomationConsts (Consts.ps1 du framework CyberArk)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
        Import-Module (Join-Path $root 'modules\PSM.Stages.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')

        $script:cSrc   = Join-Path $TestDrive 'sources-consts'
        $script:cIa    = Join-Path $script:cSrc 'media\PSM\InstallationAutomation'
        New-Item -ItemType Directory -Path $script:cIa -Force | Out-Null
        $script:consts = Join-Path $script:cIa 'Consts.ps1'
        function Reset-Consts {
            Set-Content -Path $script:consts -Value @'
Set-Variable PSM_CONNECT -value "PSMConnect"
Set-Variable PSM_ADMIN_CONNECT -value "PSMAdminConnect"
Set-Variable AUTRE_CONSTANTE -value "inchangee"
'@
            Remove-Item "$script:consts.orig" -ErrorAction SilentlyContinue
        }
        $script:cSettings = @{
            Install = @{ MediaRelativePath = 'media\PSM'; InstallationAutomationSubPath = 'InstallationAutomation' }
        }
    }

    It 'Patche PSM_CONNECT / PSM_ADMIN_CONNECT avec les comptes de la zone' {
        Reset-Consts
        $zone = @{ PSMConnectUserName = 'CONTOSO\PSMConnect'; PSMAdminConnectUserName = 'CONTOSO\PSMAdminConnect' }
        $done = Set-PSMAutomationConsts -Settings $script:cSettings -SourcesRoot $script:cSrc -ZoneConfig $zone -Confirm:$false
        $done | Should -BeTrue
        $c = Get-Content $script:consts -Raw
        $c | Should -Match ([regex]::Escape('Set-Variable PSM_CONNECT -value "CONTOSO\PSMConnect"'))
        $c | Should -Match ([regex]::Escape('Set-Variable PSM_ADMIN_CONNECT -value "CONTOSO\PSMAdminConnect"'))
        $c | Should -Match 'AUTRE_CONSTANTE -value "inchangee"'
        Get-Content "$script:consts.orig" -Raw | Should -Match 'PSM_CONNECT -value "PSMConnect"'
    }

    It 'Est re-jouable (repart de .orig)' {
        Reset-Consts
        Set-PSMAutomationConsts -Settings $script:cSettings -SourcesRoot $script:cSrc -ZoneConfig @{ PSMConnectUserName = 'CONTOSO\A' } -Confirm:$false | Out-Null
        Set-PSMAutomationConsts -Settings $script:cSettings -SourcesRoot $script:cSrc -ZoneConfig @{ PSMConnectUserName = 'CONTOSO\B' } -Confirm:$false | Out-Null
        Get-Content $script:consts -Raw | Should -Match ([regex]::Escape('"CONTOSO\B"'))
    }

    It 'Inactif quand la zone ne fournit aucun compte' {
        Reset-Consts
        Set-PSMAutomationConsts -Settings $script:cSettings -SourcesRoot $script:cSrc -ZoneConfig @{ } -Confirm:$false |
            Should -BeFalse
        Test-Path "$script:consts.orig" | Should -BeFalse
    }
}

Describe 'Get-PSMInstallPaths (source unique du dossier d install)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
    }
    It 'Derive PSM, enregistrements et Hardening depuis InstallDir' {
        $s = @{ Install = @{ InstallDir = 'D:\CyberArk'; RecordingDir = '' } }
        $p = Get-PSMInstallPaths -Settings $s
        $p.InstallDir   | Should -Be 'D:\CyberArk'
        $p.PsmDir       | Should -Be 'D:\CyberArk\PSM'
        $p.RecordingDir | Should -Be 'D:\CyberArk\PSM\Recordings'
        $p.HardeningDir | Should -Be 'D:\CyberArk\PSM\Hardening'
    }
    It 'RecordingDir explicite prime sur la valeur derivee' {
        $s = @{ Install = @{ InstallDir = 'D:\CyberArk'; RecordingDir = 'E:\Records' } }
        (Get-PSMInstallPaths -Settings $s).RecordingDir | Should -Be 'E:\Records'
    }
    It 'Erreur explicite si InstallDir manque' {
        { Get-PSMInstallPaths -Settings @{ Install = @{ InstallDir = '' } } } | Should -Throw
    }
}

Describe 'Test-PSMDomainAccount (resolution SID des comptes de zone)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
    }
    It 'Resout un compte connu' {
        Test-PSMDomainAccount -Account 'NT AUTHORITY\SYSTEM' | Should -BeTrue
    }
    It 'Refuse un compte inexistant (sans lever d exception)' {
        Test-PSMDomainAccount -Account 'DOMAINEBIDON\CompteInexistant42' | Should -BeFalse
    }
}

Describe 'Get-PSMConfigValue (lecture sure de cles facultatives)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
    }
    It 'Renvoie la valeur quand la cle existe (hashtable)' {
        Get-PSMConfigValue -Config @{ A = 'x' } -Key 'A' | Should -Be 'x'
    }
    It 'Renvoie null quand la cle est absente (sans erreur sous StrictMode)' {
        Get-PSMConfigValue -Config @{ A = 'x' } -Key 'Absent' | Should -BeNullOrEmpty
    }
    It 'Renvoie null quand la config est null' {
        Get-PSMConfigValue -Config $null -Key 'A' | Should -BeNullOrEmpty
    }
}

Describe 'Module PVWA (recuperation des secrets via API REST)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
        Import-Module (Join-Path $root 'modules\PSM.Pvwa.psm1')   -Force
    }
    It 'Expose les fonctions attendues' {
        foreach ($fn in 'Connect-PvwaSession','Disconnect-PvwaSession','Get-PvwaAccountPassword','Find-PvwaAccount',
                        'Find-PvwaUser','Rename-PvwaUser') {
            Get-Command $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    It 'N a plus de dependance au CCP/AIM' {
        Get-Command 'Get-CcpCredential' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Test-Path (Join-Path $root 'modules\PSM.Ccp.psm1') | Should -BeFalse
    }
    It 'Set-PvwaTlsBypass fonctionne sous PowerShell 5.1 (delegue TLS)' {
        # Regression : "Cannot convert ... PSMethod to RemoteCertificateValidationCallback"
        { Set-PvwaTlsBypass } | Should -Not -Throw
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback | Should -Not -BeNullOrEmpty
        [PSMTlsBypass]::Disable()   # nettoyage : revalide les certificats dans la session de test
    }
}
