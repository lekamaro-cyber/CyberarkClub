@{
    # =====================================================================
    # OVERLAY for type DRP (pure production, disaster-recovery datacenter).
    # This file REPLACES the base config\software.psd1 ENTIRELY on the DRP
    # servers. Same software set as PRD today - each type still has its OWN
    # overlay folder, so DRP can diverge later (e.g. a different Chrome
    # version) without touching PRD.
    # The MSI goes next to this overlay: overlays\DRP\installers\chrome\.
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
