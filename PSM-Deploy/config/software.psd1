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
        # Drop the MSI under installers\chrome\. Installed during the Software
        # phase, i.e. BEFORE the PSM installation: the CyberArk WebApplications
        # step and the AppLocker script then pick Chrome up automatically.
        # Remember to disable Chrome auto-update on a PSM (GPO/registry),
        # otherwise the version drifts under AppLocker.
        # Optional: skipped with a WARN when the MSI is not staged.
        @{
            Name             = 'Google Chrome Enterprise (x64)'
            Installer        = 'installers\chrome\googlechromestandaloneenterprise64.msi'
            Arguments        = '/qn /norestart'
            SuccessExitCodes = @(0, 3010)                                # 3010 = reboot required
            DetectTest       = '(Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe")'
            Optional         = $true
        }

        # ---- PrivateArk Client (TEST tooling: direct Vault admin from the PSM) --
        # Lets the operator inspect/delete Vault users (component leftovers,
        # Safes) during test cycles without hopping to another admin machine.
        # Drop the MSI from the EPV media ("PrivateArk Client" folder) under
        # installers\privateark\ (if your media ships a setup.exe instead,
        # point Installer at it and adapt Arguments - the engine handles both).
        # Optional: skipped with a WARN when the installer is not staged.
        # TEST ONLY - do NOT stage it on the DC1/DC2 production PSMs (and on a
        # hardened PSM, PrivateArk.exe must be allowed in
        # applocker\PSMConfigureAppLocker.xml).
        # The Vault definition is created at first launch (address =
        # zones.psd1 VaultAddress, e.g. 10.176.202.17 for PRE).
        @{
            Name             = 'PrivateArk Client (test tooling)'
            Installer        = 'installers\privateark\PrivateArk Client.msi'
            Arguments        = '/qn /norestart'
            SuccessExitCodes = @(0, 3010)                                # 3010 = reboot required
            DetectTest       = '(Test-Path "C:\Program Files (x86)\PrivateArk\Client\PrivateArk.exe")'
            Optional         = $true
        }

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
