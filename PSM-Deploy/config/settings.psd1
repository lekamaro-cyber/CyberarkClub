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
        # Exemple (a decommenter/adapter selon le schema du media) :
        # Injections = @{
        #     Installation = @{
        #         "//Parameter[@Name='InstallationFolder']" = @{ Attribute = 'Value'; Value = 'D:\CyberArk\PSM' }
        #     }
        # }
        Injections = @{}
    }

    # --- Enregistrement : injection de l'adresse Vault depuis zones.psd1 --------
    # Le script ecrit l'adresse Vault (cluster,DR) de la zone dans une COPIE de
    # RegistrationConfig.xml -> deposer une nouvelle source CyberArk ne demande
    # AUCUNE edition manuelle du XML. Adapter le XPath au schema du media si besoin
    # (si le noeud est introuvable, le script liste les Parameter disponibles).
    Registration = @{
        VaultAddressXPath     = "//Parameter[@Name='VaultIP']"  # TODO : confirmer selon RegistrationConfig.xml
        VaultAddressAttribute = 'Value'                          # attribut a ecrire (vide = InnerText du noeud)
    }

    # --- PostInstallation : comptes de session PSM (PSMConnect/PSMAdminConnect) --
    # Les comptes de DOMAINE sont definis PAR ZONE (zones.psd1 :
    # PSMConnectUserName / PSMAdminConnectUserName). Ici on decrit seulement OU les
    # ecrire dans PostInstallationConfig.xml -> deposer une nouvelle source ne demande
    # aucune edition manuelle du XML. Adapter les XPath au schema du media (si un
    # noeud est introuvable, le script liste les Parameter disponibles). Les mots de
    # passe ne sont PAS injectes : ils sont geres dans le Safe PSM cote Vault.
    PostInstallation = @{
        PSMConnectXPath      = "//Parameter[@Name='PSMConnectUserName']"       # TODO : confirmer selon PostInstallationConfig.xml
        PSMAdminConnectXPath = "//Parameter[@Name='PSMAdminConnectUserName']"  # TODO : confirmer selon PostInstallationConfig.xml
        UserNameAttribute    = 'Value'                                          # attribut a ecrire (vide = InnerText du noeud)
    }

    # --- Dossiers de travail (relatifs a la racine des sources) ----------
    Paths = @{
        State = 'state'
        Logs  = 'logs'
    }
}
