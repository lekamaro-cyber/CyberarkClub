@{
    # =====================================================================
    # OVERLAY for type PRD (pure production, main datacenter).
    # This file REPLACES the base config\software.psd1 ENTIRELY on the PRD
    # servers (an overlay file at the same relative path always wins): list
    # here the FULL software set of this type, not a delta of the file.
    # Production: Chrome only - NO test tooling (no PrivateArk Client).
    # The MSI goes next to this overlay: overlays\PRD\installers\chrome\.
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
    )
}
