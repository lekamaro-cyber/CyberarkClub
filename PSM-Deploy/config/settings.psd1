@{
    # =====================================================================
    # GLOBAL non-sensitive parameters of the PSM deployment.
    # No sensitive value here (secrets are retrieved through the PVWA API at runtime).
    # =====================================================================

    # Target version: '12.6' or '14.0'. Drives the version-specific paths/branches.
    PsmVersion = '12.6'

    # --- RD Session Host licensing ---------------------------------------
    Rds = @{
        LicenseMode    = 'PerUser'                 # 'PerUser' | 'PerDevice'
        # One OR several license servers, in order of preference.
        # Written into the 'LicenseServers' registry value (comma-separated list).
        LicenseServers = @(
            '<RDS-LICENSE-SERVER-1>'               # TODO (deployment): FQDN of the server(s)
            # '<RDS-LICENSE-SERVER-2>'
        )
    }

    # --- PSM installation: driving the CyberArk framework (Execute-Stage.ps1) -
    # We drive CyberArk "stage by stage". Each stage has its own XML config
    # (filled in by the team, see the media's Templates folders).
    Install = @{
        MediaRelativePath             = 'media\PSM'              # media subfolder inside the sources
        InstallationAutomationSubPath = 'InstallationAutomation' # CyberArk framework folder
        Stages = @{
            Readiness        = 'Readiness\ReadinessConfig.xml'
            Prerequisites    = 'Prerequisites\PrerequisitesConfig.xml'
            Installation     = 'Installation\InstallationConfig.xml'
            PostInstallation = 'PostInstallation\PostInstallationConfig.xml'
            Registration     = 'Registration\RegistrationConfig.xml'
            Hardening        = 'Hardening\HardeningConfig.xml'
        }

        # ================== INSTALLATION FOLDER: SINGLE SOURCE ==================
        # >>> ONE single place to change to relocate the whole install. <<<
        # From this value, the code automatically DERIVES:
        #   - InstallationDirectory injected into InstallationConfig.xml
        #   - the PSM folder (<InstallDir>\PSM)
        #   - the recordings folder (RecordingDir below, otherwise
        #     <InstallDir>\PSM\Recordings)
        #   - the PSMConfigureAppLocker.xml path (Hardening) => nothing to re-enter.
        # CyberArk default: 'C:\Program Files (x86)\CyberArk'.
        InstallDir   = 'D:\CyberArk'
        RecordingDir = ''            # empty -> <InstallDir>\PSM\Recordings (otherwise absolute path)

        # --- Additional STATIC injections into the stage *Config.xml files (optional) --
        # InstallationDirectory / RecordingDirectory are ALREADY derived from InstallDir /
        # RecordingDir above: no need to re-enter them here. Only add other fields to
        # force here (those WIN). Shape:
        #   @{ <StageKey> = @{ '<xpath>' = @{ Attribute='Value'; Value='...' } } }
        # E.g. Installation = @{ "//Parameter[@Name='Company']" = @{ Attribute='Value'; Value='My Company' } }
        # WARNING: XPath is case-sensitive ('Step'/'Parameter', not 'step').
        # When a node is not found, the script lists the available Steps/Parameters.
        Injections = @{
            # PSM session accounts in the DOMAIN (zones.psd1): these 2 steps only
            # configure LOCAL users (screensaver, session properties) and fail with
            # domain accounts -> disabled.
            # COUNTERPART: the equivalent must be carried by AD/GPO for the zone
            # accounts (as on the existing PSMs).
            PostInstallation = @{
                "//Step[@Name='DisableScreenSaver']" = @{ Attribute = 'Enable'; Value = 'No' }
                "//Step[@Name='ConfigurePSMUsers']"  = @{ Attribute = 'Enable'; Value = 'No' }
            }
        }
    }

    # --- Registration: Vault address injection from zones.psd1 -----------------
    # The script writes the zone's Vault address (cluster,DR) into a COPY of
    # RegistrationConfig.xml -> dropping in a new CyberArk source requires
    # NO manual editing of the XML. The confirmed field in RegistrationConfig.xml
    # is 'vaultip' (RegisterPsm step); the port is a separate 'vaultport' field.
    Registration = @{
        VaultAddressXPath     = "//Step[@Name='RegisterPsm']/Parameters/Parameter[@Name='vaultip']"
        VaultAddressAttribute = 'Value'                          # attribute to write (empty = node's InnerText)

        # --- Component account naming convention -------------------------
        # RegisterComponent.exe generates random names (PSMApp_<hex>/PSMGw_<hex>)
        # with NO naming option for PSM. After the registration, the script renames
        # them automatically (as previously done by hand on the existing PSMs):
        # Vault user via the PVWA API + Username= line of the cred files (password
        # unchanged, .orig backup) + PSMServerId/PSMServerAdminId of basic_psm.ini,
        # PSM service stopped/restarted during the operation. {HOSTNAME} = machine
        # name in UPPERCASE. Set RenameComponents = $false to disable.
        RenameComponents = $true
        AppUserPattern   = 'PSM-{HOSTNAME}'    # e.g. PSM-FRPRDSRV4539  (PSMServerId)
        GwUserPattern    = 'PSMA{HOSTNAME}'    # e.g. PSMAFRPRDSRV4539  (PSMServerAdminId)
    }

    # --- Hardening: DOMAIN PSM session accounts (PSMConnect/PSMAdminConnect) --
    # These accounts are NOT stage parameters: they are declared as VARIABLES at
    # the top of the CyberArk hardening scripts, GENERATED AT INSTALL TIME under
    # <InstallDir>\PSM\Hardening (NOT in the media):
    #   - PSMHardening.ps1          : $PSM_CONNECT_USER / $PSM_ADMIN_CONNECT_USER
    #   - PSMConfigureAppLocker.ps1 : $PSM_CONNECT      / $PSM_ADMIN_CONNECT
    # (observed on a production PSM; if the name differs on your version, the
    # script stops and lists the file's candidate variables).
    # The patch is done IN PLACE (.orig backup, replayable) at the start of the
    # Hardening phase, with the zone's accounts (zones.psd1 PSMConnectUserName /
    # PSMAdminConnectUserName). INACTIVE when the zone accounts are empty.
    # Passwords stay managed in the PSM Safe on the Vault side.
    Hardening = @{
        # Hardening stage failure TOLERATED (WARN instead of a fail-fast stop): the
        # deployment completes even when hardening steps fail (observed case: EDR
        # blocking system ACL modifications, even takeown).
        # The failed steps remain TO BE REDONE: fix the cause (EDR exclusion),
        # remove 'Hardening' from state\progress.json and relaunch. Set back to
        # $false once the environment is fixed to restore the strict behavior.
        NonBlocking  = $true
        HardeningDir = ''   # empty -> derived from Install.InstallDir (<InstallDir>\PSM\Hardening)
        # file -> name of the variables to patch (Connect / AdminConnect)
        ScriptAccountVariables = @{
            'PSMHardening.ps1'          = @{ Connect = 'PSM_CONNECT_USER'; AdminConnect = 'PSM_ADMIN_CONNECT_USER' }
            'PSMConfigureAppLocker.ps1' = @{ Connect = 'PSM_CONNECT';      AdminConnect = 'PSM_ADMIN_CONNECT' }
        }
    }

    # --- Working folders (relative to the sources root) ------------------
    Paths = @{
        State = 'state'
        Logs  = 'logs'
    }
}
