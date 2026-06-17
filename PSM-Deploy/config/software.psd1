@{
    # =====================================================================
    # Logiciels / clients additionnels installes APRES le PSM.
    # Liste pilotee par config : chaque entree decrit comment installer
    # l'application en silencieux + comment detecter qu'elle est deja la
    # (idempotence). Les installeurs sont a deposer sous sources\installers\.
    #
    # IMPORTANT : tout binaire ajoute ici doit aussi etre autorise dans la
    # politique AppLocker controlee (applocker\PSMConfigureAppLocker.xml).
    # =====================================================================

    Applications = @(

        # ---- Exemple (a adapter / dupliquer) -----------------------------
        # @{
        #     Name             = 'Exemple - Client SSH'
        #     Installer        = 'installers\putty\putty-installer.msi'   # relatif aux sources
        #     Arguments        = '/qn /norestart'
        #     SuccessExitCodes = @(0, 3010)                                # 3010 = reboot requis
        #     DetectTest       = '(Test-Path "C:\Program Files\PuTTY\putty.exe")'
        # }

    )
}
