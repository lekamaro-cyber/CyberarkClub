@{
    # =====================================================================
    # Additional software / clients installed AFTER the PSM.
    # Config-driven list: each entry describes how to install the application
    # silently + how to detect that it is already there (idempotency).
    # Installers are to be dropped under sources\installers\.
    #
    # IMPORTANT: any binary added here must also be allowed in the controlled
    # AppLocker policy (applocker\PSMConfigureAppLocker.xml).
    # =====================================================================

    Applications = @(

        # ---- Google Chrome Enterprise x64 (PSM web connectors) -----------
        # Drop the MSI under installers\chrome\ then uncomment. Installed during
        # the Software phase, i.e. BEFORE the PSM installation: the CyberArk
        # WebApplications step and the AppLocker script then pick Chrome up
        # automatically. Remember to disable Chrome auto-update on a PSM
        # (GPO/registry), otherwise the version drifts under AppLocker.
        # @{
        #     Name             = 'Google Chrome Enterprise (x64)'
        #     Installer        = 'installers\chrome\googlechromestandaloneenterprise64.msi'
        #     Arguments        = '/qn /norestart'
        #     SuccessExitCodes = @(0, 3010)                                # 3010 = reboot required
        #     DetectTest       = '(Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe")'
        # }

        # ---- Example (adapt / duplicate) ---------------------------------
        # @{
        #     Name             = 'Example - SSH client'
        #     Installer        = 'installers\putty\putty-installer.msi'   # relative to the sources
        #     Arguments        = '/qn /norestart'
        #     SuccessExitCodes = @(0, 3010)                                # 3010 = reboot required
        #     DetectTest       = '(Test-Path "C:\Program Files\PuTTY\putty.exe")'
        # }

    )
}
