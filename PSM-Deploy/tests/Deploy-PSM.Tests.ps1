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

Describe 'Installed PSM version guard (install, never upgrade)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Install.psm1') -Force
    }
    It 'Get-PSMInstalledVersion returns $null, a [version] or Unreadable' {
        $v = Get-PSMInstalledVersion
        ($null -eq $v -or $v -is [version] -or $v -eq 'Unreadable') | Should -BeTrue
    }
    It 'settings.psd1 PsmVersion is a major.minor the guard can compare' {
        $s = Import-PowerShellDataFile (Join-Path $root 'config\settings.psd1')
        $s.PsmVersion | Should -Match '^\d+\.\d+$'
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

Describe 'Software list: common software.psd1 + per-type software.extra.psd1' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1')   -Force
        Import-Module (Join-Path $root 'modules\PSM.Software.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')
        $script:newSources = {
            param([string] $Extra)
            $src = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path (Join-Path $src 'config') -Force | Out-Null
            Set-Content -Path (Join-Path $src 'config\software.psd1') -Value @'
@{ Applications = @(
    @{ Name = 'Chrome'; Installer = 'installers\chrome\chrome-v1.msi'; DetectTest = '$true' }
    @{ Name = 'Tool';   Installer = 'installers\tool\tool.msi';        DetectTest = '$true' }
) }
'@
            if ($Extra) { Set-Content -Path (Join-Path $src 'config\software.extra.psd1') -Value $Extra }
            return $src
        }
    }
    It 'Without software.extra.psd1: the common list only' {
        $list = Get-PSMSoftwareList -SourcesRoot (& $script:newSources $null)
        @($list | ForEach-Object { $_.Name }) | Should -Be @('Chrome', 'Tool')
    }
    It 'Extra entries are ADDED to the common list (Chrome stays)' {
        $src  = & $script:newSources "@{ Applications = @( @{ Name = 'SQLDev'; Installer = 'installers\sqldev\setup.msi'; DetectTest = '`$true' } ) }"
        $list = Get-PSMSoftwareList -SourcesRoot $src
        @($list | ForEach-Object { $_.Name }) | Should -Be @('Chrome', 'Tool', 'SQLDev')
    }
    It 'An extra entry with the same Name REPLACES the common one in place' {
        $src  = & $script:newSources "@{ Applications = @( @{ Name = 'Chrome'; Installer = 'installers\chrome\chrome-v2.msi'; DetectTest = '`$true' } ) }"
        $list = Get-PSMSoftwareList -SourcesRoot $src
        $list.Count          | Should -Be 2
        $list[0].Installer   | Should -Be 'installers\chrome\chrome-v2.msi'
    }
}

Describe 'RDS license servers (reachable ones written first)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1')  -Force
        Import-Module (Join-Path $root 'modules\PSM.Prereqs.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')
        # Reachable server = a local listener; unreachable = a name that never resolves.
        $script:listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $script:listener.Start()
        $script:port = $script:listener.LocalEndpoint.Port
    }
    AfterAll { $script:listener.Stop() }
    It 'Puts the reachable server first, keeps the unreachable one after it' {
        @(Get-PSMLicenseServerOrder -Servers 'lic-otherdc.invalid', '127.0.0.1' -Port $script:port -TimeoutMs 1000) |
            Should -Be @('127.0.0.1', 'lic-otherdc.invalid')
    }
    It 'Keeps the config order when all or none are reachable, and for a single server' {
        @(Get-PSMLicenseServerOrder -Servers '127.0.0.1', 'localhost' -Port $script:port -TimeoutMs 1000) |
            Should -Be @('127.0.0.1', 'localhost')
        @(Get-PSMLicenseServerOrder -Servers 'a.invalid', 'b.invalid' -Port $script:port -TimeoutMs 1000) |
            Should -Be @('a.invalid', 'b.invalid')
        @(Get-PSMLicenseServerOrder -Servers 'only.invalid' -Port $script:port) | Should -Be @('only.invalid')
    }
}

Describe 'RDP certificate (PSM behind a VIP, zones.psd1 PsmVips)' {
    BeforeAll {
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1')       -Force
        Import-Module (Join-Path $root 'modules\PSM.Certificates.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')
        $script:vipZone = @{ Name = 'TEST'; PsmVips = @{
            'psm-vip.test.corp' = @{ Members = @('PSM01', 'PSM02.test.corp') }
            'other.test.corp'   = @{ Members = @('PSM02') }
            'broken.test.corp'  = @{ }
        } }
    }
    It 'Every zone carries a PsmVips table whose entries all have Members' {
        $z = Import-PowerShellDataFile (Join-Path $root 'config\zones.psd1')
        foreach ($k in $z.Keys) {
            $z[$k]['PsmVips'] | Should -BeOfType [System.Collections.IDictionary]
            foreach ($vip in $z[$k].PsmVips.Keys) { $z[$k].PsmVips[$vip]['Members'] | Should -Not -BeNullOrEmpty }
        }
    }
    It 'SAN match: exact and case-insensitive, a wildcard does NOT match' {
        Test-PSMSanMatch -SanName 'PSM-VIP.test.corp'  -ExpectedName 'psm-vip.test.corp' | Should -BeTrue
        Test-PSMSanMatch -SanName 'psm-vip.test.corp.' -ExpectedName 'psm-vip.test.corp' | Should -BeTrue
        Test-PSMSanMatch -SanName '*.test.corp'        -ExpectedName 'psm-vip.test.corp' | Should -BeFalse
        Test-PSMSanMatch -SanName ''                   -ExpectedName 'psm-vip.test.corp' | Should -BeFalse
    }
    It 'VIPs of a server: short name or FQDN member, case-insensitive; malformed entry skipped' {
        @(Get-PSMServerVips -ZoneConfig $script:vipZone -ComputerName 'psm01') | Should -Be @('psm-vip.test.corp')
        @(Get-PSMServerVips -ZoneConfig $script:vipZone -ComputerName 'PSM02' | Sort-Object) |
            Should -Be @('other.test.corp', 'psm-vip.test.corp')
        @(Get-PSMServerVips -ZoneConfig $script:vipZone -ComputerName 'PSM99').Count | Should -Be 0
        @(Get-PSMServerVips -ZoneConfig @{ Name = 'X' } -ComputerName 'PSM01').Count | Should -Be 0
    }
    It 'Not behind a VIP / no PsmVips key: nothing to do, no alert' {
        Invoke-PSMRdpCertificate -ZoneConfig $script:vipZone -ComputerName 'PSM99' | Should -BeTrue
        Invoke-PSMRdpCertificate -ZoneConfig @{ Name = 'X' } -ComputerName 'PSM01' | Should -BeTrue
    }
    It 'Reads the SAN DNS names from the raw extension (IP / e-mail entries ignored)' -Skip:(-not ('System.Security.Cryptography.X509Certificates.CertificateRequest' -as [type])) {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=test', $rsa, 'SHA256',
                   [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $san.AddIpAddress([System.Net.IPAddress]::Parse('10.1.2.3'))
        $san.AddDnsName('psm-vip.test.corp')
        $san.AddEmailAddress('a@test.corp')
        $san.AddDnsName('psm01.test.corp')
        $req.CertificateExtensions.Add($san.Build())
        $cert = $req.CreateSelfSigned([datetimeoffset]::Now.AddDays(-1), [datetimeoffset]::Now.AddDays(1))
        @(Get-PSMCertSanDnsNames -Certificate $cert) | Should -Be @('psm-vip.test.corp', 'psm01.test.corp')
        $noSan = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=nosan', $rsa, 'SHA256',
                   [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        @(Get-PSMCertSanDnsNames -Certificate $noSan.CreateSelfSigned([datetimeoffset]::Now, [datetimeoffset]::Now.AddDays(1))).Count |
            Should -Be 0
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

Describe 'PSM-Distribute (source distribution from the CPM)' {
    BeforeAll {
        $distRoot = Join-Path (Split-Path $root -Parent) 'PSM-Distribute'
        Import-Module (Join-Path $root 'modules\PSM.Common.psm1') -Force
        Import-Module (Join-Path $distRoot 'modules\PSM.Distribute.psm1') -Force
        Initialize-PSMLogging -LogDirectory (Join-Path $env:TEMP 'psm-test-logs')
    }
    It 'Contains the orchestrator, config and module' {
        Test-Path (Join-Path $distRoot 'Distribute-PSMSources.ps1')          | Should -BeTrue
        Test-Path (Join-Path $distRoot 'config\distribution.psd1')          | Should -BeTrue
        Test-Path (Join-Path $distRoot 'modules\PSM.Distribute.psm1')       | Should -BeTrue
    }
    It 'The repository distribution.psd1 carries every key the drift check expects' {
        $c = Import-PowerShellDataFile (Join-Path $distRoot 'config\distribution.psd1')
        foreach ($k in 'SourceRoot', 'OverlayRoot', 'StagingRoot', 'TargetPath', 'ServerTypes', 'Servers',
                       'Pvwa', 'PushAccounts', 'LocalAdminUserName', 'TryCurrentSession') {
            $c.Keys | Should -Contain $k
        }
    }
    It 'distribution.psd1 parses and every server entry is complete' {
        $c = Import-PowerShellDataFile (Join-Path $distRoot 'config\distribution.psd1')
        $c.ServerTypes | Should -Not -BeNullOrEmpty
        $c.Servers     | Should -Not -BeNullOrEmpty
        foreach ($s in $c.Servers) {
            $s['Name'] | Should -Not -BeNullOrEmpty
            $s['Type'] | Should -BeIn $c.ServerTypes
        }
    }
    It 'Build-PSMStagingTree: overlay wins, base extras survive, state\ is never shipped' {
        $base = Join-Path $env:TEMP 'psm-test-dist-base'
        $ovl  = Join-Path $env:TEMP 'psm-test-dist-ovl'
        $stg  = Join-Path $env:TEMP 'psm-test-dist-stg'
        Remove-Item $base, $ovl, $stg -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path (Join-Path $base 'config'), (Join-Path $base 'state'), (Join-Path $ovl 'config') | Out-Null
        Set-Content -Path (Join-Path $base 'config\software.psd1') -Value 'base'
        Set-Content -Path (Join-Path $base 'config\settings.psd1') -Value 'common'
        Set-Content -Path (Join-Path $base 'state\progress.json')  -Value 'local'
        Set-Content -Path (Join-Path $ovl  'config\software.psd1') -Value 'overlay'
        Build-PSMStagingTree -BaseRoot $base -OverlayPath $ovl -StagingPath $stg | Out-Null
        Get-Content (Join-Path $stg 'config\software.psd1') | Should -Be 'overlay'   # overlay wins
        Get-Content (Join-Path $stg 'config\settings.psd1') | Should -Be 'common'    # base extras survive
        Test-Path   (Join-Path $stg 'state')                | Should -BeFalse        # local state never shipped
    }
    It 'A base-only recompose is convergent (second run reports nothing to copy)' {
        $base = Join-Path $env:TEMP 'psm-test-dist-base2'
        $stg  = Join-Path $env:TEMP 'psm-test-dist-stg2'
        Remove-Item $base, $stg -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $base | Out-Null
        Set-Content -Path (Join-Path $base 'file.txt') -Value 'x'
        Build-PSMStagingTree -BaseRoot $base -StagingPath $stg | Out-Null
        Build-PSMStagingTree -BaseRoot $base -StagingPath $stg | Should -Be 0
    }
    It 'Carries the CyberArk credential-cascade settings (PVWA, push account, local fallback)' {
        $c = Import-PowerShellDataFile (Join-Path $distRoot 'config\distribution.psd1')
        $c.Keys            | Should -Contain 'LocalAdminUserName'
        $c.Pvwa.Url        | Should -Not -BeNullOrEmpty
        $c.Pvwa.AuthMethod | Should -BeIn @('CyberArk', 'LDAP', 'Windows', 'RADIUS')
        $c.Keys | Should -Contain 'PushAccounts'
        foreach ($lot in @($c.PushAccounts.Keys)) {
            foreach ($k in 'UserName', 'Address', 'Safe', 'LogonName') {
                $c.PushAccounts[$lot].Keys | Should -Contain $k
            }
        }
        foreach ($s in $c.Servers) {
            if ($s['Push']) { $c.PushAccounts.Keys | Should -Contain $s['Push'] }
        }
        $c.TryCurrentSession | Should -BeOfType [bool]
    }
    It 'Get-PvwaAccountPassword accepts an -Address (exact machine match, cross-Safe)' {
        Import-Module (Join-Path $root 'modules\PSM.Pvwa.psm1') -Force
        (Get-Command Get-PvwaAccountPassword).Parameters.Keys | Should -Contain 'Address'
        (Get-Command Find-PvwaAccount).Parameters.Keys        | Should -Contain 'Address'
    }
    It 'Authenticated push does not die on the 1219 pre-cleanup (PS 5.1 stderr trap regression)' {
        # Regression for 662c3d7: 'net use /delete' on a non-existent connection
        # writes "The network connection could not be found." to stderr; under
        # EAP=Stop + 2>&1 that became a terminating error killing every
        # credentialed push BEFORE New-PSDrive. The failure below must come
        # from the unreachable share, never from the cleanup itself.
        $stg = Join-Path $env:TEMP 'psm-test-push-stg'
        New-Item -ItemType Directory -Path $stg -Force | Out-Null
        $dummy = [System.Management.Automation.PSCredential]::new(
                     'x\dummy', (ConvertTo-SecureString 'x' -AsPlainText -Force))
        $err = $null
        try {
            Push-PSMSourcesToServer -ServerName 'localhost' -StagingPath $stg `
                -TargetUnc '\\localhost\psmtest-nonexistent$\x' -Credential $dummy | Out-Null
        }
        catch { $err = $_.Exception.Message }
        $err | Should -Not -BeNullOrEmpty
        $err | Should -Not -Match 'network connection could not be found'
    }
    It 'overlays-example folders map 1:1 to the declared ServerTypes (Type = folder name)' {
        $c = Import-PowerShellDataFile (Join-Path $distRoot 'config\distribution.psd1')
        $examples = Get-ChildItem (Join-Path $distRoot 'overlays-example') -Directory
        $examples | Should -Not -BeNullOrEmpty
        foreach ($d in $examples) { $d.Name | Should -BeIn $c.ServerTypes }
    }
    It 'Every example overlay software.psd1 parses and its entries are named' {
        foreach ($f in Get-ChildItem (Join-Path $distRoot 'overlays-example') -Recurse -Filter 'software.psd1') {
            $s = Import-PowerShellDataFile $f.FullName
            $s.Applications | Should -Not -BeNullOrEmpty
            foreach ($app in $s.Applications) { $app['Name'] | Should -Not -BeNullOrEmpty }
        }
    }
}

Describe 'Show-PSMConfig (read-only configuration view)' {
    BeforeAll {
        $script:showConfig = Join-Path (Split-Path $root -Parent) 'PSM-Distribute\Show-PSMConfig.ps1'
        # Fake CPM: base + overlays STD (none) / MDW (missing installer) / ARK (replaces
        # a common entry), an undeclared overlay folder, a VIP member outside the inventory.
        $cpm = Join-Path $TestDrive 'cpm'
        foreach ($d in 'PSM-Deploy\config', 'Overlays\MDW\config', 'Overlays\ARK\config', 'Overlays\ARK\installers\pa', 'Overlays\OLD') {
            New-Item -ItemType Directory -Path (Join-Path $cpm $d) -Force | Out-Null
        }
        Set-Content -Path (Join-Path $cpm 'PSM-Deploy\config\settings.psd1') -Value "@{ PsmVersion = '14.0'; Install = @{ InstallDir = 'D:\CyberArk'; RecordingDir = '' } }"
        Set-Content -Path (Join-Path $cpm 'PSM-Deploy\config\zones.psd1') -Value "@{ PRE = @{ Name = 'PRE'; PvwaUrl = 'https://pvwa'; PsmVips = @{ 'vip.test.corp' = @{ Members = @('SRV1', 'SRV9') } } } }"
        Set-Content -Path (Join-Path $cpm 'PSM-Deploy\config\software.psd1') -Value "@{ Applications = @( @{ Name = 'Tool'; Installer = 'installers\tool.msi'; Optional = `$true } ) }"
        Set-Content -Path (Join-Path $cpm 'Overlays\MDW\config\software.extra.psd1') -Value "@{ Applications = @( @{ Name = 'SSMS'; Installer = 'installers\ssms.exe' } ) }"
        Set-Content -Path (Join-Path $cpm 'Overlays\ARK\config\software.extra.psd1') -Value "@{ Applications = @( @{ Name = 'Tool'; Installer = 'installers\pa\pa.msi' } ) }"
        Set-Content -Path (Join-Path $cpm 'Overlays\ARK\installers\pa\pa.msi') -Value 'x'
        $script:distCfg = Join-Path $cpm 'distribution.psd1'
        Set-Content -Path $script:distCfg -Value @"
@{
    SourceRoot = '$cpm\PSM-Deploy'; OverlayRoot = '$cpm\Overlays'
    ServerTypes = @('STD', 'MDW', 'ARK')
    PushAccounts = @{ LOT = @{ Match = 'SRV*'; UserName = 'svc'; Address = 'corp'; LogonName = '' } }
    Servers = @( @{ Name = 'SRV1'; Type = 'STD' }, @{ Name = 'SRV2'; Type = 'MDW'; Zone = 'PRE' }, @{ Name = 'SRV3'; Type = 'ARK' } )
}
"@
        $script:model = & $script:showConfig -ConfigPath $script:distCfg -PassThru
    }
    It 'Lists the profiles with their servers' {
        @($script:model.Profiles | ForEach-Object { $_.Name }) | Should -Be @('STD', 'MDW', 'ARK')
        @($script:model.Profiles | Where-Object Name -eq 'STD').Servers | Should -Be @('SRV1')
    }
    It 'Shows the effective software list (common + profile, same Name = replaced)' {
        $mdw = ($script:model.Profiles | Where-Object Name -eq 'MDW').Software
        @($mdw | ForEach-Object { $_.Software }) | Should -Be @('Tool', 'SSMS')
        $ark = ($script:model.Profiles | Where-Object Name -eq 'ARK').Software
        @($ark).Count     | Should -Be 1
        $ark[0].Origin    | Should -Be 'Profile (replaces common)'
        $ark[0].Staged    | Should -Be 'Profile'
    }
    It 'Resolves zone (declared or from the VIP) and push lot per server' {
        $srv1 = $script:model.Servers | Where-Object Server -eq 'SRV1'
        $srv1.Zone    | Should -Be 'PRE (from VIP)'
        $srv1.VIP     | Should -Be 'vip.test.corp'
        $srv1.PushLot | Should -Be 'LOT (svc)'
        ($script:model.Servers | Where-Object Server -eq 'SRV2').Zone | Should -Be 'PRE'
    }
    It 'Flags the configuration mistakes' {
        $text = @($script:model.Checks | ForEach-Object { "$($_.Level)|$($_.Topic)|$($_.Detail)" }) -join "`n"
        $text | Should -Match "Error\|Profile MDW\|'SSMS': file not found"
        $text | Should -Match "Warning\|Overlays\|Folder 'OLD' is not a declared profile"
        $text | Should -Match "Warning\|VIP vip.test.corp\|Member 'SRV9' is not in the server inventory"
        $script:model.Errors | Should -Be 1
    }
}
