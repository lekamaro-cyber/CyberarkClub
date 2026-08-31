@{
    # =====================================================================
    # OVERLAY for type PREPRD (separate test/PRE infrastructure).
    # This file REPLACES the base config\software.psd1 ENTIRELY on the
    # PREPRD servers. Test infra: Chrome + the PrivateArk Client (direct
    # Vault admin from the PSM during test cycles) - the client must NEVER
    # appear in the PRD/DRP/PRDNPR overlays.
    # MSIs go next to this overlay: overlays\PREPRD\installers\chrome\ and
    # overlays\PREPRD\installers\privateark\.
    # =====================================================================

    Applications = @(
        @{
            Name             = 'Google Chrome Enterprise (x64)'
            Installer        = 'installers\chrome\googlechromestandaloneenterprise64.msi'
            Arguments        = '/qn /norestart'
            SuccessExitCodes = @(0, 3010)                                # 3010 = reboot required
            DetectTest       = '(Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe")'
            Optional         = $true   # skipped with a WARN if the MSI is not staged
        }
        @{
            Name             = 'PrivateArk Client (test tooling)'
            Installer        = 'installers\privateark\PrivateArk Client.msi'
            Arguments        = '/qn /norestart'
            SuccessExitCodes = @(0, 3010)
            DetectTest       = '(Test-Path "C:\Program Files (x86)\PrivateArk\Client\PrivateArk.exe")'
            Optional         = $true
        }
    )
}
