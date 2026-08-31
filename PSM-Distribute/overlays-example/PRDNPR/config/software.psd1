@{
    # =====================================================================
    # OVERLAY for type PRDNPR (hosted in the DRP datacenter, serves
    # NON-production accounts). This file REPLACES the base
    # config\software.psd1 ENTIRELY on the PRDNPR servers.
    # Prod-grade tooling: Chrome only, NO test tooling (these machines are
    # production infrastructure even though the accounts are non-prod).
    # The MSI goes next to this overlay: overlays\PRDNPR\installers\chrome\.
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
