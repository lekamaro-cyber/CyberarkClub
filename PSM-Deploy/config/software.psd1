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
