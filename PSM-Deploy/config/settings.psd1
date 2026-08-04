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

        # --- Injections STATIQUES dans les *Config.xml de stage (optionnel) --------
        # Permet d'adapter la config d'un stage a notre environnement SANS editer les
        # XML du media : chaque valeur est ecrite dans une COPIE patchee sous
        # state\config\<Stage>\ (media intact). Cle = nom du stage (cf. Stages),
        # valeur = table @{ '<xpath>' = @{ Attribute='Value'; Value='...' } }
        # (Attribute vide => on ecrit l'InnerText du noeud). Les valeurs DYNAMIQUES
        # (ex. adresse Vault de la zone) restent injectees par le code, pas ici.
        # Si un noeud est introuvable, le script liste les Parameter disponibles.
        # Exemple PRET A L'EMPLOI pour InstallationConfig.xml (champs reels confirmes) :
        # decommenter/adapter et deplacer hors du commentaire pour activer.
        # Injections = @{
        #     Installation = @{
        #         "//Parameter[@Name='InstallationDirectory']" = @{ Attribute = 'Value'; Value = 'D:\Program Files (x86)\CyberArk' }
        #         "//Parameter[@Name='RecordingDirectory']"    = @{ Attribute = 'Value'; Value = 'D:\PSM\Recordings' }
        #         "//Parameter[@Name='Company']"               = @{ Attribute = 'Value'; Value = 'Ma Societe' }
        #         "//Parameter[@Name='Name']"                  = @{ Attribute = 'Value'; Value = 'Compte installation' }
        #     }
        # }
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

    # --- PostInstallation : comptes de session PSM (PSMConnect/PSMAdminConnect) --
    # ATTENTION : le PostInstallationConfig.xml STANDARD (step ConfigurePSMUsers ->
    # ConfigureUsersForPSMSessions.psm1) NE PREND AUCUN parametre pour ces comptes.
    # Il n'y a donc PAS de champ XML a injecter ici tel quel. Les comptes de DOMAINE
    # PSMConnect / PSMAdminConnect se configurent cote Hardening (variables des
    # scripts PSMHardening.ps1 / PSMConfigureAppLocker.ps1), pas via ce XML.
    # -> XPath laisses VIDES : l'injection est INACTIVE tant que la cible reelle
    #    n'est pas confirmee (voir zones.psd1 PSMConnectUserName/*). Renseigner les
    #    XPath ici seulement si votre PostInstallationConfig.xml expose ces champs.
    PostInstallation = @{
        PSMConnectXPath      = ''   # a confirmer : absent du PostInstallationConfig.xml standard
        PSMAdminConnectXPath = ''   # a confirmer : absent du PostInstallationConfig.xml standard
        UserNameAttribute    = 'Value'
    }

    # --- Dossiers de travail (relatifs a la racine des sources) ----------
    Paths = @{
        State = 'state'
        Logs  = 'logs'
    }
}
