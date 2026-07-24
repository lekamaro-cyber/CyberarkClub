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

    # --- Installation du binaire PSM (scripts d'automatisation CyberArk) -
    Install = @{
        MediaRelativePath = 'media\PSM'           # sous-dossier du media dans les sources
        AutomationScript  = 'InstallationAutomation.ps1'  # TODO : nom reel selon le media
        ResponseFile      = ''                    # TODO : fichier de reponse silencieux si requis
        AutomationArgs    = @()                   # TODO : arguments passes au script CyberArk
    }

    # --- Hardening -------------------------------------------------------
    Hardening = @{
        ScriptsRelativePath = 'media\PSM\Hardening'   # emplacement des scripts CyberArk dans le media
    }

    # --- Dossiers de travail (relatifs a la racine des sources) ----------
    Paths = @{
        State = 'state'
        Logs  = 'logs'
    }
}
