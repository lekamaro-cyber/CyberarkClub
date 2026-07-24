@{
    # =====================================================================
    # Mapping ZONE (datacenter) -> parametres Vault / PVWA.
    # Les 2 datacenters ont des flux fermes entre eux : on selectionne la
    # zone au lancement (-Zone) puis on confirme interactivement.
    #
    # Recuperation des secrets : via l'API REST du PVWA (PAS de CCP/AIM).
    #   -> L'admin qui realise l'installation s'authentifie sur le PVWA
    #      (il a acces a tous les comptes CyberArk) ; le script recupere a la
    #      volee le mot de passe du compte d'install/admin Vault.
    #
    # InstallAccountSafe / InstallAccountUserName :
    #   - renseignes -> le script recupere ce compte via l'API PVWA et l'utilise
    #                   pour l'enregistrement (registration automation du media).
    #   - vides      -> le script reutilise directement le compte de l'admin
    #                   connecte au PVWA comme compte d'install.
    #
    # SkipCertificateCheck : $true UNIQUEMENT en lab (PVWA a certificat auto-signe).
    # =====================================================================

    # --- Bac a sable / demo (PVWA de test) ------------------------------
    LAB = @{
        Name                   = 'LAB'
        PvwaUrl                = 'https://<PVWA-LAB>'      # TODO : URL PVWA du bac a sable
        PvwaAuthMethod         = 'CyberArk'                # CyberArk | LDAP | Windows | RADIUS
        SkipCertificateCheck   = $true                     # lab : certificat auto-signe tolere
        InstallAccountSafe     = ''                        # vide -> utilise le compte admin connecte
        InstallAccountUserName = ''
    }

    DC1 = @{
        Name                   = 'DC1'
        PvwaUrl                = 'https://<PVWA-DC1>'      # TODO (deploiement)
        PvwaAuthMethod         = 'LDAP'                     # admin de domaine -> LDAP en general
        SkipCertificateCheck   = $false
        InstallAccountSafe     = '<SAFE-INSTALL-DC1>'      # Safe du compte d'install Vault
        InstallAccountUserName = '<USER-INSTALL-DC1>'      # nom du compte d'install a recuperer
    }

    DC2 = @{
        Name                   = 'DC2'
        PvwaUrl                = 'https://<PVWA-DC2>'      # TODO (deploiement)
        PvwaAuthMethod         = 'LDAP'
        SkipCertificateCheck   = $false
        InstallAccountSafe     = '<SAFE-INSTALL-DC2>'
        InstallAccountUserName = '<USER-INSTALL-DC2>'
    }
}
