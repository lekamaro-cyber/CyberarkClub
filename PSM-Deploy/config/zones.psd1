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
    #
    # VaultAddress : adresse(s) du Vault pour l'ENREGISTREMENT, format "ipCluster,ipDr"
    #   (cluster/primaire en premier, DR ensuite). Injectee au runtime dans une copie
    #   de RegistrationConfig.xml -> une nouvelle source CyberArk ne demande aucune
    #   edition manuelle du XML.
    #
    # PSMConnectUserName / PSMAdminConnectUserName : comptes de session PSM, comptes
    #   de DOMAINE deja crees (format "DOMAINE\utilisateur"). Les MOTS DE PASSE ne
    #   sont PAS ici : ils sont geres dans le Safe PSM cote Vault.
    #   Ces comptes ne sont PAS des parametres de stage : ils sont ecrits dans
    #   PSMConfigureAppLocker.xml (genere a l'installation), patche EN PLACE au debut
    #   de la phase Hardening (cf. settings.psd1 Hardening.*). VIDES par defaut =
    #   injection INACTIVE. Les renseigner ET definir les XPath Hardening.* (a
    #   confirmer sur le fichier genere) pour activer.
    # =====================================================================

    # --- Bac a sable / PRE (PVWA de test) -------------------------------
    PRE = @{
        Name                   = 'PRE'
        PvwaUrl                = 'https://<PVWA-PRE>'      # TODO : URL PVWA du bac a sable
        PvwaAuthMethod         = 'CyberArk'                # CyberArk | LDAP | Windows | RADIUS
        SkipCertificateCheck   = $true                     # lab : certificat auto-signe tolere
        VaultAddress           = '<IP-CLUSTER-PRE>,<IP-DR-PRE>'  # cluster,DR
        InstallAccountSafe     = ''                        # vide -> utilise le compte admin connecte
        InstallAccountUserName = ''
        PSMConnectUserName      = ''   # vide = pas d'injection (cf. note en tete)
        PSMAdminConnectUserName = ''
    }

    DC1 = @{
        Name                   = 'DC1'
        PvwaUrl                = 'https://<PVWA-DC1>'      # TODO (deploiement)
        PvwaAuthMethod         = 'LDAP'                     # admin de domaine -> LDAP en general
        SkipCertificateCheck   = $false
        VaultAddress           = '<IP-CLUSTER-DC1>,<IP-DR-DC1>'  # cluster,DR
        InstallAccountSafe     = '<SAFE-INSTALL-DC1>'      # Safe du compte d'install Vault
        InstallAccountUserName = '<USER-INSTALL-DC1>'      # nom du compte d'install a recuperer
        PSMConnectUserName      = ''   # vide = pas d'injection (cf. note en tete)
        PSMAdminConnectUserName = ''
    }

    DC2 = @{
        Name                   = 'DC2'
        PvwaUrl                = 'https://<PVWA-DC2>'      # TODO (deploiement)
        PvwaAuthMethod         = 'LDAP'
        SkipCertificateCheck   = $false
        VaultAddress           = '<IP-CLUSTER-DC2>,<IP-DR-DC2>'  # cluster,DR
        InstallAccountSafe     = '<SAFE-INSTALL-DC2>'
        InstallAccountUserName = '<USER-INSTALL-DC2>'
        PSMConnectUserName      = ''   # vide = pas d'injection (cf. note en tete)
        PSMAdminConnectUserName = ''
    }
}
