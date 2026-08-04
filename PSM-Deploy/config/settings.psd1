@{
    # =====================================================================
    # Parametres GLOBAUX non sensibles du deploiement PSM.
    # Aucune valeur sensible ici (les secrets sont recuperes via l'API PVWA au runtime).
    # =====================================================================

    # Version cible : '12.6' ou '14.0'. Pilote les chemins/branches version-specifiques.
    PsmVersion = '12.6'

    # --- Licences RD Session Host ---------------------------------------
    Rds = @{
        LicenseMode    = 'PerUser'                 # 'PerUser' | 'PerDevice'
        # Un OU plusieurs serveurs de licence, dans l'ordre de preference.
        # Ecrits dans la valeur registre 'LicenseServers' (liste separee par des virgules).
        LicenseServers = @(
            '<RDS-LICENSE-SERVER-1>'               # TODO (deploiement) : FQDN du/des serveur(s)
            # '<RDS-LICENSE-SERVER-2>'
        )
    }

    # --- Installation PSM : pilotage du framework CyberArk (Execute-Stage.ps1) -
    # On pilote CyberArk "etape par etape". Chaque stage a son XML de config
    # (rempli par l'equipe, cf. dossiers Templates du media).
    Install = @{
        MediaRelativePath             = 'media\PSM'              # sous-dossier du media dans les sources
        InstallationAutomationSubPath = 'InstallationAutomation' # dossier du framework CyberArk
        Stages = @{
            Readiness        = 'Readiness\ReadinessConfig.xml'
            Prerequisites    = 'Prerequisites\PrerequisitesConfig.xml'
            Installation     = 'Installation\InstallationConfig.xml'
            PostInstallation = 'PostInstallation\PostInstallationConfig.xml'
            Registration     = 'Registration\RegistrationConfig.xml'
            Hardening        = 'Hardening\HardeningConfig.xml'
        }

        # ================== DOSSIER D'INSTALLATION : source UNIQUE ==================
        # >>> UN SEUL endroit a changer pour deplacer toute l'install. <<<
        # A partir de cette valeur, le code DERIVE automatiquement :
        #   - InstallationDirectory injecte dans InstallationConfig.xml
        #   - le dossier PSM (<InstallDir>\PSM)
        #   - le dossier d'enregistrements (RecordingDir ci-dessous, sinon
        #     <InstallDir>\PSM\Recordings)
        #   - le chemin PSMConfigureAppLocker.xml (Hardening) => rien a resaisir.
        # Defaut CyberArk : 'C:\Program Files (x86)\CyberArk'.
        InstallDir   = 'D:\CyberArk'
        RecordingDir = ''            # vide -> <InstallDir>\PSM\Recordings (sinon chemin absolu)

        # --- Injections STATIQUES supplementaires dans les *Config.xml (optionnel) --
        # InstallationDirectory / RecordingDirectory sont DEJA derives de InstallDir /
        # RecordingDir ci-dessus : inutile de les remettre ici. N'ajouter ici que
        # d'autres champs a forcer (ceux-ci PRIMENT). Forme :
        #   @{ <StageKey> = @{ '<xpath>' = @{ Attribute='Value'; Value='...' } } }
        # Ex. Installation = @{ "//Parameter[@Name='Company']" = @{ Attribute='Value'; Value='Ma Societe' } }
        # Si un noeud est introuvable, le script liste les Parameter disponibles.
        Injections = @{}
    }

    # --- Enregistrement : injection de l'adresse Vault depuis zones.psd1 --------
    # Le script ecrit l'adresse Vault (cluster,DR) de la zone dans une COPIE de
    # RegistrationConfig.xml -> deposer une nouvelle source CyberArk ne demande
    # AUCUNE edition manuelle du XML. Le champ confirme dans RegistrationConfig.xml
    # est 'vaultip' (step RegisterPsm) ; le port est un champ separe 'vaultport'.
    Registration = @{
        VaultAddressXPath     = "//Step[@Name='RegisterPsm']/Parameters/Parameter[@Name='vaultip']"
        VaultAddressAttribute = 'Value'                          # attribut a ecrire (vide = InnerText du noeud)
    }

    # --- Hardening : comptes de session PSM de DOMAINE (PSMConnect/PSMAdminConnect) --
    # Ces comptes NE sont PAS des parametres de stage (ni PostInstallation, ni
    # HardeningConfig.xml). Ils sont references dans PSMConfigureAppLocker.xml, un
    # fichier GENERE A L'INSTALLATION dans le dossier installe (PAS le media), que le
    # step RunApplocker lit depuis un emplacement FIXE ("Remember to edit
    # PSMConfigureApplocker.XML before running the script"). On le patche donc EN PLACE
    # (avec sauvegarde .orig, re-jouable) au debut de la phase Hardening, avec les
    # comptes de la zone (zones.psd1 PSMConnectUserName / PSMAdminConnectUserName).
    # Les mots de passe restent geres dans le Safe PSM cote Vault.
    #
    # INACTIF par defaut : ne fait rien tant que les comptes de zone ET les XPath
    # ci-dessous ne sont pas renseignes. Confirmer les XPath sur le fichier REEL
    # genere apres une premiere Installation (si un noeud est introuvable, le script
    # liste les noeuds candidats).
    Hardening = @{
        AppLockerConfigPath  = ''   # vide -> derive de Install.InstallDir (<InstallDir>\PSM\Hardening\PSMConfigureAppLocker.xml)
        PSMConnectXPath      = ''   # TODO : a confirmer sur le PSMConfigureAppLocker.xml genere
        PSMAdminConnectXPath = ''   # TODO : a confirmer sur le PSMConfigureAppLocker.xml genere
        AccountAttribute     = ''   # vide = on ecrit l'InnerText du noeud ; sinon nom d'attribut
    }

    # --- Dossiers de travail (relatifs a la racine des sources) ----------
    Paths = @{
        State = 'state'
        Logs  = 'logs'
    }
}
