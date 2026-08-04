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
        Import-Module (Join-Path $root 'modules\PSM.Stages.psm1') -Force
    }
    It 'Expose le moteur de stage et le calcul de chemins' {
        foreach ($fn in 'Invoke-PSMStage','Get-PSMStagePaths') {
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
