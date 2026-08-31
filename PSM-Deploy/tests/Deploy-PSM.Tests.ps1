<#
    Pester tests for the PSM deployment skeleton.
    Goal: check the structural consistency and the idempotency contract
    (a 2nd run of an already-compliant step = no change).

    Run:  Invoke-Pester -Path .\tests\Deploy-PSM.Tests.ps1
#>

$root = Split-Path $PSScriptRoot -Parent

Describe 'Sources folder structure' {
    It 'Contains the orchestrator' {
        Test-Path (Join-Path $root 'Deploy-PSM.ps1') | Should -BeTrue
    }
    It 'Contains the expected config files' {
        foreach ($f in 'settings.psd1', 'zones.psd1', 'software.psd1') {
            Test-Path (Join-Path $root "config\$f") | Should -BeTrue
        }
    }
    It 'Loads the modules without error' {
        { Get-ChildItem (Join-Path $root 'modules') -Filter '*.psm1' |
            ForEach-Object { Import-Module $_.FullName -Force } } | Should -Not -Throw
    }
}

Describe 'Idempotency contract (Invoke-IdempotentStep)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')
    }
    It 'Returns OK when the target state is already met' {
        $r = Invoke-IdempotentStep -Name 'already-compliant' -Test { $true } -Action { throw 'must not be called' }
        $r | Should -Be 'OK'
    }
    It 'Returns CHANGED when the action is applied' {
        $script:flag = $false
        $r = Invoke-IdempotentStep -Name 'to-apply' -Test { $script:flag } -Action { $script:flag = $true } -Confirm:$false
        $r | Should -Be 'CHANGED'
    }
    It 'Is idempotent on the 2nd run (CHANGED then OK)' {
        $script:flag = $false
        $test   = { $script:flag }
        $action = { $script:flag = $true }
        Invoke-IdempotentStep -Name 'idem' -Test $test -Action $action -Confirm:$false | Should -Be 'CHANGED'
        Invoke-IdempotentStep -Name 'idem' -Test $test -Action $action -Confirm:$false | Should -Be 'OK'
    }
}

Describe 'State reset (-Reset / start from scratch)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')
        Initialize-PSMState   -StateDirectory (Join-Path $TestDrive 'state-reset')
    }
    It 'Clears the completed phases' {
        Set-PSMPhaseComplete 'PreFlight'
        Set-PSMPhaseComplete 'Installation'
        Test-PSMPhaseComplete 'Installation' | Should -BeTrue

        Reset-PSMState -Confirm:$false

        Test-PSMPhaseComplete 'PreFlight'    | Should -BeFalse
        Test-PSMPhaseComplete 'Installation' | Should -BeFalse
    }
}

Describe 'Zones config' {
    It 'Defines at least 2 zones with the required PVWA keys' {
        $z = Import-PowerShellDataFile (Join-Path $root 'config\zones.psd1')
        $z.Keys.Count | Should -BeGreaterOrEqual 2
        foreach ($k in $z.Keys) {
            foreach ($req in 'PvwaUrl','PvwaAuthMethod','SkipCertificateCheck') {
                $z[$k].ContainsKey($req) | Should -BeTrue
            }
        }
    }
}

Describe 'Stages module (driving CyberArk Execute-Stage.ps1)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
        Import-Module (Join-Path $root 'modules\PSM.Stages.psm1') -Force
    }
    It 'Exposes the stage engine, path resolution and injection' {
        foreach ($fn in 'Invoke-PSMStage','Get-PSMStagePaths','Resolve-PSMStageConfig','Update-PSMStageXml') {
            Get-Command $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    It 'Computes the stage paths from settings.psd1' {
        $s = Import-PowerShellDataFile (Join-Path $root 'config\settings.psd1')
        $p = Get-PSMStagePaths -Settings $s -SourcesRoot $root -StageKey 'Installation'
        $p.ExecuteStage | Should -Match 'InstallationAutomation'
        $p.Config       | Should -Match 'InstallationConfig\.xml'
    }
}

Describe 'Stage XML injection (config-driven, media intact)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1')  -Force
        Import-Module (Join-Path $root 'modules\PSM.Stages.psm1')  -Force
        Import-Module (Join-Path $root 'modules\PSM.Install.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')

        # Fake media: media\PSM\InstallationAutomation\<Stage>\... layout
        $script:src   = Join-Path $TestDrive 'sources'
        $script:iaDir = Join-Path $script:src 'media\PSM\InstallationAutomation'
        $regDir       = Join-Path $script:iaDir 'Registration'
        $hardDir      = Join-Path $script:iaDir 'Hardening'
        $postDir      = Join-Path $script:iaDir 'PostInstallation'
        $instDir      = Join-Path $script:iaDir 'Installation'
        New-Item -ItemType Directory -Path $regDir, $hardDir, $postDir, $instDir -Force | Out-Null
        # Execute-Stage.ps1 stub: returns a success JSON (isSucceeded=0).
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

    It 'Injects the install folder derived from Install.InstallDir (single source)' {
        $r = Invoke-PSMInstall -Settings $script:settings -SourcesRoot $script:src
        $r.Succeeded | Should -BeTrue

        $copy = Join-Path $script:stateDir 'config\Installation\InstallationConfig.xml'
        $doc  = [xml](Get-Content $copy -Raw)
        $doc.SelectSingleNode("//Parameter[@Name='InstallationDirectory']").Value | Should -Be 'D:\CyberArk'
        $doc.SelectSingleNode("//Parameter[@Name='RecordingDirectory']").Value    | Should -Be 'D:\CyberArk\PSM\Recordings'
        # Media unchanged.
        ([xml](Get-Content $script:instXml -Raw)).SelectSingleNode("//Parameter[@Name='InstallationDirectory']").Value |
            Should -Be 'C:\Program Files (x86)\CyberArk'
    }

    It 'Patches a COPY (Vault address) without touching the media' {
        $extra = @{ "//Parameter[@Name='VaultIP']" = @{ Attribute = 'Value'; Value = '10.0.0.1,10.0.0.2' } }
        $stage = Resolve-PSMStageConfig -Settings $script:settings -SourcesRoot $script:src `
                    -StageKey 'Registration' -ExtraInjections $extra

        # The patched copy lives under state\config\Registration\, not in the media.
        $stage.ConfigFilePath | Should -Match 'state.config.Registration'
        ([xml](Get-Content $stage.ConfigFilePath -Raw)).SelectSingleNode("//Parameter[@Name='VaultIP']").Value |
            Should -Be '10.0.0.1,10.0.0.2'
        # Media unchanged.
        ([xml](Get-Content $script:regXml -Raw)).SelectSingleNode("//Parameter[@Name='VaultIP']").Value |
            Should -Be ''
    }

    It 'Returns the media XML when no injection is defined' {
        $stage = Resolve-PSMStageConfig -Settings $script:settings -SourcesRoot $script:src -StageKey 'Hardening'
        $stage.ConfigFilePath | Should -Be $script:hardXml
    }

    It 'Applies the STATIC injections from settings.psd1' {
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

    It 'Without ZoneConfig, PostInstallation uses the media XML as-is' {
        $stage = Resolve-PSMStageConfig -Settings $script:settings -SourcesRoot $script:src -StageKey 'PostInstallation'
        $stage.ConfigFilePath | Should -Be $script:postXml
    }
}

Describe 'PSMConnect/PSMAdminConnect domain accounts (Hardening script variables)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1')    -Force
        Import-Module (Join-Path $root 'modules\PSM.Hardening.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')

        # "Generated at install time" hardening scripts (simplified excerpts).
        $script:hardDir = Join-Path $TestDrive 'Hardening'
        New-Item -ItemType Directory -Path $script:hardDir -Force | Out-Null
        function Reset-HardeningScripts {
            Set-Content -Path (Join-Path $script:hardDir 'PSMHardening.ps1') -Value @'
# excerpt
$PSM_CONNECT_USER       = "PSMConnect"
$PSM_ADMIN_CONNECT_USER = "PSMAdminConnect"
$SUPPORT_WEB_APPLICATIONS = $true
'@
            Set-Content -Path (Join-Path $script:hardDir 'PSMConfigureAppLocker.ps1') -Value @'
# excerpt
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

    It 'Patches BOTH scripts'' variables with the domain accounts' {
        Reset-HardeningScripts
        $zone = @{ PSMConnectUserName = 'CONTOSO\PSMConnect'; PSMAdminConnectUserName = 'CONTOSO\PSMAdminConnect' }
        $done = Set-PSMConnectAccounts -Settings $script:hSettings -ZoneConfig $zone -Confirm:$false
        $done | Should -BeTrue

        Get-HardVar 'PSMHardening.ps1'          'PSM_CONNECT_USER'       | Should -Be 'CONTOSO\PSMConnect'
        Get-HardVar 'PSMHardening.ps1'          'PSM_ADMIN_CONNECT_USER' | Should -Be 'CONTOSO\PSMAdminConnect'
        Get-HardVar 'PSMConfigureAppLocker.ps1' 'PSM_CONNECT'            | Should -Be 'CONTOSO\PSMConnect'
        Get-HardVar 'PSMConfigureAppLocker.ps1' 'PSM_ADMIN_CONNECT'      | Should -Be 'CONTOSO\PSMAdminConnect'
        # Other variables untouched; .orig backup intact.
        (Get-Content (Join-Path $script:hardDir 'PSMHardening.ps1') -Raw) | Should -Match 'SUPPORT_WEB_APPLICATIONS'
        Test-Path (Join-Path $script:hardDir 'PSMHardening.ps1.orig') | Should -BeTrue
        Get-Content (Join-Path $script:hardDir 'PSMHardening.ps1.orig') -Raw | Should -Match '"PSMConnect"'
    }

    It 'Is replayable (starts over from .orig, no double application)' {
        Reset-HardeningScripts
        Set-PSMConnectAccounts -Settings $script:hSettings -ZoneConfig @{ PSMConnectUserName = 'CONTOSO\PSMConnect' } -Confirm:$false | Out-Null
        # 2nd run with another account: must reflect the latest, not stack.
        Set-PSMConnectAccounts -Settings $script:hSettings -ZoneConfig @{ PSMConnectUserName = 'CONTOSO\Other' } -Confirm:$false | Out-Null
        Get-HardVar 'PSMHardening.ps1' 'PSM_CONNECT_USER' | Should -Be 'CONTOSO\Other'
    }

    It 'Inactive when the zone provides no account' {
        Reset-HardeningScripts
        $done = Set-PSMConnectAccounts -Settings $script:hSettings -ZoneConfig @{ } -Confirm:$false
        $done | Should -BeFalse
        Get-HardVar 'PSMHardening.ps1' 'PSM_CONNECT_USER' | Should -Be 'PSMConnect'
        Test-Path (Join-Path $script:hardDir 'PSMHardening.ps1.orig') | Should -BeFalse
    }

    It 'Empty mapping = deliberate no-op (14.0 flow: accounts come from Consts.ps1)' {
        Reset-HardeningScripts
        $empty = @{ Hardening = @{ HardeningDir = $script:hardDir; ScriptAccountVariables = @{} } }
        Set-PSMConnectAccounts -Settings $empty -ZoneConfig @{ PSMConnectUserName = 'CONTOSO\X' } -Confirm:$false |
            Should -BeFalse
        # Scripts untouched, no backup created.
        Get-HardVar 'PSMHardening.ps1' 'PSM_CONNECT_USER' | Should -Be 'PSMConnect'
        Test-Path (Join-Path $script:hardDir 'PSMHardening.ps1.orig') | Should -BeFalse
    }

    It 'Explicit error (with candidate variables) when the variable is not found' {
        Reset-HardeningScripts
        $bad = @{
            Hardening = @{
                HardeningDir = $script:hardDir
                ScriptAccountVariables = @{
                    'PSMHardening.ps1' = @{ Connect = 'NONEXISTENT_VARIABLE' }
                }
            }
        }
        { Set-PSMConnectAccounts -Settings $bad -ZoneConfig @{ PSMConnectUserName = 'CONTOSO\X' } -Confirm:$false } |
            Should -Throw '*Candidate variables*'
    }
}

Describe 'Set-PSMAutomationConsts (CyberArk framework Consts.ps1)' {
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
Set-Variable OTHER_CONSTANT -value "unchanged"
'@
            Remove-Item "$script:consts.orig" -ErrorAction SilentlyContinue
        }
        $script:cSettings = @{
            Install = @{ MediaRelativePath = 'media\PSM'; InstallationAutomationSubPath = 'InstallationAutomation' }
        }
    }

    It 'Patches PSM_CONNECT / PSM_ADMIN_CONNECT with the zone accounts' {
        Reset-Consts
        $zone = @{ PSMConnectUserName = 'CONTOSO\PSMConnect'; PSMAdminConnectUserName = 'CONTOSO\PSMAdminConnect' }
        $done = Set-PSMAutomationConsts -Settings $script:cSettings -SourcesRoot $script:cSrc -ZoneConfig $zone -Confirm:$false
        $done | Should -BeTrue
        $c = Get-Content $script:consts -Raw
        $c | Should -Match ([regex]::Escape('Set-Variable PSM_CONNECT -value "CONTOSO\PSMConnect"'))
        $c | Should -Match ([regex]::Escape('Set-Variable PSM_ADMIN_CONNECT -value "CONTOSO\PSMAdminConnect"'))
        $c | Should -Match 'OTHER_CONSTANT -value "unchanged"'
        Get-Content "$script:consts.orig" -Raw | Should -Match 'PSM_CONNECT -value "PSMConnect"'
    }

    It 'Is replayable (starts over from .orig)' {
        Reset-Consts
        Set-PSMAutomationConsts -Settings $script:cSettings -SourcesRoot $script:cSrc -ZoneConfig @{ PSMConnectUserName = 'CONTOSO\A' } -Confirm:$false | Out-Null
        Set-PSMAutomationConsts -Settings $script:cSettings -SourcesRoot $script:cSrc -ZoneConfig @{ PSMConnectUserName = 'CONTOSO\B' } -Confirm:$false | Out-Null
        Get-Content $script:consts -Raw | Should -Match ([regex]::Escape('"CONTOSO\B"'))
    }

    It 'Inactive when the zone provides no account' {
        Reset-Consts
        Set-PSMAutomationConsts -Settings $script:cSettings -SourcesRoot $script:cSrc -ZoneConfig @{ } -Confirm:$false |
            Should -BeFalse
        Test-Path "$script:consts.orig" | Should -BeFalse
    }
}

Describe 'Get-PSMInstallPaths (single source of the install folder)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
    }
    It 'Derives PSM, recordings and Hardening from InstallDir' {
        $s = @{ Install = @{ InstallDir = 'D:\CyberArk'; RecordingDir = '' } }
        $p = Get-PSMInstallPaths -Settings $s
        $p.InstallDir   | Should -Be 'D:\CyberArk'
        $p.PsmDir       | Should -Be 'D:\CyberArk\PSM'
        $p.RecordingDir | Should -Be 'D:\CyberArk\PSM\Recordings'
        $p.HardeningDir | Should -Be 'D:\CyberArk\PSM\Hardening'
    }
    It 'An explicit RecordingDir wins over the derived value' {
        $s = @{ Install = @{ InstallDir = 'D:\CyberArk'; RecordingDir = 'E:\Records' } }
        (Get-PSMInstallPaths -Settings $s).RecordingDir | Should -Be 'E:\Records'
    }
    It 'Explicit error when InstallDir is missing' {
        { Get-PSMInstallPaths -Settings @{ Install = @{ InstallDir = '' } } } | Should -Throw
    }
}

Describe 'Test-PSMSettingsDrift (config drift vs script version)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')
    }
    It 'The repository reference config is complete (no missing key)' {
        $s = Import-PowerShellDataFile (Join-Path $root 'config\settings.psd1')
        Test-PSMSettingsDrift -Settings $s | Should -BeNullOrEmpty
    }
    It 'Detects the missing keys on a partial config' {
        $partial = @{ PsmVersion = '12.6'; Rds = @{ LicenseMode = 'PerUser' } }
        $missing = Test-PSMSettingsDrift -Settings $partial
        $missing | Should -Contain 'Registration.RenameComponents'
        $missing | Should -Contain 'Registration.ExistingAccountAction'
        $missing | Should -Contain 'Install.InstallDir'
        $missing | Should -Contain 'Rds.LicenseServers'
    }
}

Describe 'Software phase (optional entries)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1')   -Force
        Import-Module (Join-Path $root 'modules\PSM.Software.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')
    }
    It 'Chrome and PrivateArk Client entries are active and Optional (never break a media-less deployment)' {
        $s = Import-PowerShellDataFile (Join-Path $root 'config\software.psd1')
        $names = @($s.Applications | ForEach-Object { $_.Name })
        $names | Should -Contain 'Google Chrome Enterprise (x64)'
        $names | Should -Contain 'PrivateArk Client (test tooling)'
        foreach ($app in $s.Applications) { [bool]$app['Optional'] | Should -BeTrue }
    }
    It 'An optional entry whose installer is not staged is skipped without error' {
        $list = @(@{
            Name = 'Fake optional'; Installer = 'installers\nope\missing.msi'
            Arguments = '/qn'; SuccessExitCodes = @(0)
            DetectTest = '$false'; Optional = $true
        })
        { Invoke-PSMSoftware -SoftwareList $list -SourcesRoot $env:TEMP } | Should -Not -Throw
    }
    It 'A NON-optional entry whose installer is missing still fails fast' {
        $list = @(@{
            Name = 'Fake mandatory'; Installer = 'installers\nope\missing.msi'
            Arguments = '/qn'; SuccessExitCodes = @(0)
            DetectTest = '$false'
        })
        { Invoke-PSMSoftware -SoftwareList $list -SourcesRoot $env:TEMP } | Should -Throw '*Installer not found*'
    }
    It 'An optional entry already installed is reported OK without needing the installer' {
        $list = @(@{
            Name = 'Fake already there'; Installer = 'installers\nope\missing.msi'
            Arguments = '/qn'; SuccessExitCodes = @(0)
            DetectTest = '$true'; Optional = $true
        })
        { Invoke-PSMSoftware -SoftwareList $list -SourcesRoot $env:TEMP } | Should -Not -Throw
    }
    It 'COPY mode: copies a folder content and is idempotent on the second run' {
        $src = Join-Path $env:TEMP 'psm-test-copy-src'
        $dst = Join-Path $env:TEMP 'psm-test-copy-dst'
        Remove-Item $src, $dst -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path (Join-Path $src 'mytool') -Force | Out-Null
        Set-Content -Path (Join-Path $src 'mytool\mytool.exe') -Value 'fake'
        $list = @(@{
            Name = 'Fake portable'; Source = 'mytool'; Destination = $dst
            DetectTest = "(Test-Path '" + (Join-Path $dst 'mytool.exe') + "')"
        })
        (Invoke-PSMSoftware -SoftwareList $list -SourcesRoot $src) | Should -Be 'CHANGED'
        Test-Path (Join-Path $dst 'mytool.exe') | Should -BeTrue
        (Invoke-PSMSoftware -SoftwareList $list -SourcesRoot $src) | Should -Be 'OK'
    }
    It 'COPY mode without DetectTest defaults to Test-Path Destination' {
        $src = Join-Path $env:TEMP 'psm-test-copy2-src'
        $dst = Join-Path $env:TEMP 'psm-test-copy2-dst'
        Remove-Item $src, $dst -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $src -Force | Out-Null
        Set-Content -Path (Join-Path $src 'readme.txt') -Value 'x'
        $list = @(@{ Name = 'Fake portable file'; Source = 'readme.txt'; Destination = $dst })
        (Invoke-PSMSoftware -SoftwareList $list -SourcesRoot $src) | Should -Be 'CHANGED'
        Test-Path (Join-Path $dst 'readme.txt') | Should -BeTrue
        (Invoke-PSMSoftware -SoftwareList $list -SourcesRoot $src) | Should -Be 'OK'
    }
    It 'An optional COPY entry whose source is not staged is skipped without error' {
        $list = @(@{
            Name = 'Fake portable missing'; Source = 'nope\missing'
            Destination = (Join-Path $env:TEMP 'psm-test-copy-never'); Optional = $true
        })
        { Invoke-PSMSoftware -SoftwareList $list -SourcesRoot $env:TEMP } | Should -Not -Throw
    }
    It 'An entry declaring both Installer and Source is rejected' {
        $list = @(@{
            Name = 'Bad entry'; Installer = 'a.msi'; Source = 'b'
            Destination = 'C:\x'; DetectTest = '$false'
        })
        { Invoke-PSMSoftware -SoftwareList $list -SourcesRoot $env:TEMP } | Should -Throw '*EITHER*'
    }
}

Describe 'Existing component Vault user (Overwrite / password-sync policy)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1')   -Force
        Import-Module (Join-Path $root 'modules\PSM.Pvwa.psm1')     -Force
        Import-Module (Join-Path $root 'modules\PSM.Register.psm1') -Force
    }
    It 'Exposes the collision-handling functions' {
        foreach ($fn in 'Resolve-PSMExistingComponentUser','New-PSMComponentPassword','Update-PSMCredFile') {
            Get-Command $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    It 'settings.psd1 carries a valid ExistingAccountAction policy' {
        $s = Import-PowerShellDataFile (Join-Path $root 'config\settings.psd1')
        $s.Registration.ExistingAccountAction | Should -BeIn @('Ask','Overwrite','ResetPassword','Fail')
    }
    It 'New-PSMComponentPassword: length and CLI-safe charset (no quote/space/&)' {
        $generated = New-PSMComponentPassword
        $generated.Length | Should -Be 32
        $generated | Should -MatchExactly '^[A-Za-z0-9_-]+$'
    }
    It 'New-PSMComponentPassword: two calls do not collide' {
        New-PSMComponentPassword | Should -Not -Be (New-PSMComponentPassword)
    }
}

Describe 'Test-PSMDomainAccount (SID resolution of the zone accounts)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
    }
    It 'Resolves a known account' {
        Test-PSMDomainAccount -Account 'NT AUTHORITY\SYSTEM' | Should -BeTrue
    }
    It 'Rejects a nonexistent account (without throwing)' {
        Test-PSMDomainAccount -Account 'FAKEDOMAIN\NonexistentAccount42' | Should -BeFalse
    }
}

Describe 'Test-PSMLocalAdminMember (local Administrators membership)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
    }
    It 'Never throws and returns $true/$false/$null' {
        { $script:res = Test-PSMLocalAdminMember -Account 'FAKEDOMAIN\NonexistentAccount42' } | Should -Not -Throw
        @($true, $false, $null) | Should -Contain $script:res
    }
}

Describe 'Get-PSMConfigValue (safe read of optional keys)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
    }
    It 'Returns the value when the key exists (hashtable)' {
        Get-PSMConfigValue -Config @{ A = 'x' } -Key 'A' | Should -Be 'x'
    }
    It 'Returns null when the key is absent (no StrictMode error)' {
        Get-PSMConfigValue -Config @{ A = 'x' } -Key 'Absent' | Should -BeNullOrEmpty
    }
    It 'Returns null when the config is null' {
        Get-PSMConfigValue -Config $null -Key 'A' | Should -BeNullOrEmpty
    }
}

Describe 'PVWA module (secret retrieval through the REST API)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
        Import-Module (Join-Path $root 'modules\PSM.Pvwa.psm1')   -Force
    }
    It 'Exposes the expected functions' {
        foreach ($fn in 'Connect-PvwaSession','Connect-PvwaSessionWithRetry','Disconnect-PvwaSession',
                        'Get-PvwaAccountPassword','Find-PvwaAccount','Find-PvwaUser','Rename-PvwaUser',
                        'Remove-PvwaUser','Reset-PvwaUserPassword') {
            Get-Command $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    It 'No longer depends on CCP/AIM' {
        Get-Command 'Get-CcpCredential' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Test-Path (Join-Path $root 'modules\PSM.Ccp.psm1') | Should -BeFalse
    }
    It 'Set-PvwaTlsBypass works on PowerShell 5.1 (TLS delegate)' {
        # Regression: "Cannot convert ... PSMethod to RemoteCertificateValidationCallback"
        { Set-PvwaTlsBypass } | Should -Not -Throw
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback | Should -Not -BeNullOrEmpty
        [PSMTlsBypass]::Disable()   # cleanup: re-validate certificates in the test session
    }
}
