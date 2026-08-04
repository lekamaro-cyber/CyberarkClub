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
        New-Item -ItemType Directory -Path $regDir, $hardDir, $postDir -Force | Out-Null
        # Stub Execute-Stage.ps1 : renvoie un JSON de succes (isSucceeded=0).
        Set-Content -Path (Join-Path $script:iaDir 'Execute-Stage.ps1') -Value @'
param($configFilePath, $silentMode, $displayJson, $spwdObj)
'{"isSucceeded":0,"restartRequired":false,"logPath":null,"errorData":null}'
'@
        $script:regXml  = Join-Path $regDir  'RegistrationConfig.xml'
        $script:hardXml = Join-Path $hardDir 'HardeningConfig.xml'
        $script:postXml = Join-Path $postDir 'PostInstallationConfig.xml'
        Set-Content -Path $script:regXml  -Value '<Configuration><Parameter Name="VaultIP" Value="" /></Configuration>'
        Set-Content -Path $script:hardXml -Value '<Configuration><Parameter Name="Foo" Value="bar" /></Configuration>'
        Set-Content -Path $script:postXml -Value '<Configuration><Parameter Name="PSMConnectUserName" Value="" /><Parameter Name="PSMAdminConnectUserName" Value="" /></Configuration>'

        $script:stateDir = Join-Path $TestDrive 'state'
        Initialize-PSMState -StateDirectory $script:stateDir

        $script:settings = @{
            Install = @{
                MediaRelativePath             = 'media\PSM'
                InstallationAutomationSubPath = 'InstallationAutomation'
                Stages = @{
                    Registration     = 'Registration\RegistrationConfig.xml'
                    Hardening        = 'Hardening\HardeningConfig.xml'
                    PostInstallation = 'PostInstallation\PostInstallationConfig.xml'
                }
                Injections = @{}
            }
            PostInstallation = @{
                PSMConnectXPath      = "//Parameter[@Name='PSMConnectUserName']"
                PSMAdminConnectXPath = "//Parameter[@Name='PSMAdminConnectUserName']"
                UserNameAttribute    = 'Value'
            }
        }
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

    It 'Injecte les comptes PSMConnect/PSMAdminConnect de la zone en PostInstallation' {
        $zone = @{
            PSMConnectUserName      = 'CONTOSO\PSMConnect'
            PSMAdminConnectUserName = 'CONTOSO\PSMAdminConnect'
        }
        $r = Invoke-PSMPostInstall -Settings $script:settings -SourcesRoot $script:src -ZoneConfig $zone
        $r.Succeeded | Should -BeTrue

        $copy = Join-Path $script:stateDir 'config\PostInstallation\PostInstallationConfig.xml'
        $doc  = [xml](Get-Content $copy -Raw)
        $doc.SelectSingleNode("//Parameter[@Name='PSMConnectUserName']").Value      | Should -Be 'CONTOSO\PSMConnect'
        $doc.SelectSingleNode("//Parameter[@Name='PSMAdminConnectUserName']").Value | Should -Be 'CONTOSO\PSMAdminConnect'
        # Media inchange.
        ([xml](Get-Content $script:postXml -Raw)).SelectSingleNode("//Parameter[@Name='PSMConnectUserName']").Value |
            Should -Be ''
    }

    It 'Sans ZoneConfig, PostInstallation utilise le XML du media tel quel' {
        $stage = Resolve-PSMStageConfig -Settings $script:settings -SourcesRoot $script:src -StageKey 'PostInstallation'
        $stage.ConfigFilePath | Should -Be $script:postXml
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
        foreach ($fn in 'Connect-PvwaSession','Disconnect-PvwaSession','Get-PvwaAccountPassword','Find-PvwaAccount') {
            Get-Command $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    It 'N a plus de dependance au CCP/AIM' {
        Get-Command 'Get-CcpCredential' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Test-Path (Join-Path $root 'modules\PSM.Ccp.psm1') | Should -BeFalse
    }
}
