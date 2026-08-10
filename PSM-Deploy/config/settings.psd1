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
        # ATTENTION : XPath sensible a la casse ('Step'/'Parameter', pas 'step').
        # Si un noeud est introuvable, le script liste les Steps/Parameters disponibles.
        Injections = @{
            # Comptes de session PSM en DOMAINE (zones.psd1) : ces 2 steps ne
            # configurent que des utilisateurs LOCAUX (screensaver, proprietes de
            # session) et echouent avec des comptes de domaine -> desactives.
            # CONTREPARTIE : l'equivalent doit etre porte par l'AD/GPO pour les
            # comptes de la zone (comme sur les PSM existants).
            PostInstallation = @{
                "//Step[@Name='DisableScreenSaver']" = @{ Attribute = 'Enable'; Value = 'No' }
                "//Step[@Name='ConfigurePSMUsers']"  = @{ Attribute = 'Enable'; Value = 'No' }
            }
        }
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
    # Ces comptes NE sont PAS des parametres de stage : ils sont declares comme
    # VARIABLES en tete des scripts de hardening CyberArk, GENERES A L'INSTALLATION
    # dans <InstallDir>\PSM\Hardening (PAS dans le media) :
    #   - PSMHardening.ps1          : $PSM_CONNECT_USER / $PSM_ADMIN_CONNECT_USER
    #   - PSMConfigureAppLocker.ps1 : $PSM_CONNECT      / $PSM_ADMIN_CONNECT
    # (constate sur un PSM en service ; si le nom differe sur votre version, le
    # script s'arrete en listant les variables candidates du fichier).
    # Le patch se fait EN PLACE (sauvegarde .orig, re-jouable) au debut de la phase
    # Hardening, avec les comptes de la zone (zones.psd1 PSMConnectUserName /
    # PSMAdminConnectUserName). INACTIF si les comptes de zone sont vides.
    # Les mots de passe restent geres dans le Safe PSM cote Vault.
    Hardening = @{
        # Echec du stage Hardening TOLERE (WARN au lieu d'un arret fail-fast) : le
        # deploiement se termine meme si des steps de durcissement echouent (cas
        # rencontre : EDR bloquant les modifications d'ACL systeme, meme takeown).
        # Les steps en echec restent A REPRENDRE : corriger la cause (exclusion EDR),
        # retirer 'Hardening' de state\progress.json et relancer. Remettre a $false
        # une fois l'environnement corrige pour retrouver le comportement strict.
        NonBlocking  = $true
        HardeningDir = ''   # vide -> derive de Install.InstallDir (<InstallDir>\PSM\Hardening)
        # fichier -> nom des variables a patcher (Connect / AdminConnect)
        ScriptAccountVariables = @{
            'PSMHardening.ps1'          = @{ Connect = 'PSM_CONNECT_USER'; AdminConnect = 'PSM_ADMIN_CONNECT_USER' }
            'PSMConfigureAppLocker.ps1' = @{ Connect = 'PSM_CONNECT';      AdminConnect = 'PSM_ADMIN_CONNECT' }
        }
    }

    # --- Dossiers de travail (relatifs a la racine des sources) ----------
    Paths = @{
        State = 'state'
        Logs  = 'logs'
    }
}
