@{
    # =====================================================================
    # Additional software / clients installed AFTER the PSM.
    # Config-driven list, two entry shapes (see modules\PSM.Software.psm1):
    #   - INSTALLER mode: Installer + Arguments (silent MSI/EXE)
    #   - COPY mode     : Source + Destination (PORTABLE app: no installer,
    #                     the file/folder is simply copied onto the server)
    # plus DetectTest (idempotency; optional in copy mode - defaults to the
    # destination existing) and Optional ($true = skipped with a WARN when the
    # installer/source is not staged, instead of failing the deployment).
    # Installers/sources are to be dropped under sources\installers\.
    #
    # IMPORTANT: any binary added here (installed OR copied) must also be
    # allowed in the controlled AppLocker policy
    # (applocker\PSMConfigureAppLocker.xml).
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

        # ---- Example, INSTALLER mode (adapt / duplicate) -----------------
        # @{
        #     Name             = 'Example - SSH client'
        #     Installer        = 'installers\putty\putty-installer.msi'   # relative to the sources
        #     Arguments        = '/qn /norestart'
        #     SuccessExitCodes = @(0, 3010)                                # 3010 = reboot required
        #     DetectTest       = '(Test-Path "C:\Program Files\PuTTY\putty.exe")'
        # }

        # ---- Example, COPY mode: PORTABLE app, no installer --------------
        # The folder's CONTENT is copied into Destination (created if needed);
        # a file Source is copied INTO Destination. DetectTest is optional here
        # (defaults to Test-Path Destination) - give a finer test (e.g. on the
        # copied .exe) when the destination folder can pre-exist. The copied
        # binaries must be allowed in the AppLocker policy like any other.
        # @{
        #     Name        = 'Example - portable tool'
        #     Source      = 'installers\tools\mytool'          # file OR folder, relative to the sources
        #     Destination = 'D:\Tools\MyTool'                  # absolute path on the server
        #     DetectTest  = '(Test-Path "D:\Tools\MyTool\mytool.exe")'
        #     Optional    = $true
        # }

    )
}
