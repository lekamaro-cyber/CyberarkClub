@{
    # =====================================================================
    # ZONE (datacenter) mapping -> Vault / PVWA parameters.
    # The 2 datacenters have closed network flows between them: the zone is
    # selected at launch (-Zone) then confirmed interactively.
    #
    # Secret retrieval: through the PVWA REST API (NO CCP/AIM).
    #   -> The admin performing the installation authenticates to the PVWA
    #      (they have access to all CyberArk accounts); the script retrieves
    #      the Vault install/admin account password on the fly.
    #
    # InstallAccountSafe / InstallAccountUserName:
    #   - filled in -> the script retrieves this account through the PVWA API and
    #                  uses it for the registration (media's registration automation).
    #   - empty     -> the script directly reuses the account of the admin
    #                  connected to the PVWA as the install account.
    #
    # SkipCertificateCheck: $true ONLY in the lab (PVWA with a self-signed certificate).
    #
    # VaultAddress: Vault address(es) for the REGISTRATION, "clusterIp,drIp" format
    #   (cluster/primary first, DR second). Injected at runtime into a copy of
    #   RegistrationConfig.xml -> a new CyberArk source requires no manual
    #   editing of the XML.
    #
    # PSMConnectUserName / PSMAdminConnectUserName: PSM session accounts, DOMAIN
    #   accounts already created (format "DOMAIN\user"). The PASSWORDS are NOT
    #   here: they are managed in the PSM Safe on the Vault side.
    #   These accounts are not stage parameters: they are written into the
    #   hardening script variables and the framework constants (Consts.ps1),
    #   patched IN PLACE at the start of the relevant phases (see settings.psd1
    #   Hardening.*). EMPTY by default = injection INACTIVE.
    #   WARNING: use the account's REAL sAMAccountName (20-character limit, often
    #   truncated compared to the Name/CN shown in the AD console).
    # =====================================================================

    # --- Sandbox / PRE (test PVWA) ---------------------------------------
    PRE = @{
        Name                   = 'PRE'
        PvwaUrl                = 'https://oneconnection.pre.intra.corp'
        PvwaAuthMethod         = 'CyberArk'                # CyberArk | LDAP | Windows | RADIUS
        SkipCertificateCheck   = $true                     # lab: self-signed certificate tolerated
        VaultAddress           = '10.176.202.17,10.176.202.25'   # cluster,DR
        InstallAccountSafe     = ''                        # empty -> uses the connected admin account
        InstallAccountUserName = ''
        PSMConnectUserName      = 'FRANCE\FRSVCPREPSMConnect'
        PSMAdminConnectUserName = 'FRANCE\FRSVCPREPSMAdminConn'  # real sAMAccountName (20-char limit)
    }

    DC1 = @{
        Name                   = 'DC1'
        PvwaUrl                = 'https://<PVWA-DC1>'      # TODO (deployment)
        PvwaAuthMethod         = 'LDAP'                     # domain admin -> usually LDAP
        SkipCertificateCheck   = $false
        VaultAddress           = '<CLUSTER-IP-DC1>,<DR-IP-DC1>'  # cluster,DR
        InstallAccountSafe     = '<INSTALL-SAFE-DC1>'      # Safe of the Vault install account
        InstallAccountUserName = '<INSTALL-USER-DC1>'      # name of the install account to retrieve
        PSMConnectUserName      = ''   # empty = no injection (see note above)
        PSMAdminConnectUserName = ''
    }

    DC2 = @{
        Name                   = 'DC2'
        PvwaUrl                = 'https://<PVWA-DC2>'      # TODO (deployment)
        PvwaAuthMethod         = 'LDAP'
        SkipCertificateCheck   = $false
        VaultAddress           = '<CLUSTER-IP-DC2>,<DR-IP-DC2>'  # cluster,DR
        InstallAccountSafe     = '<INSTALL-SAFE-DC2>'
        InstallAccountUserName = '<INSTALL-USER-DC2>'
        PSMConnectUserName      = ''   # empty = no injection (see note above)
        PSMAdminConnectUserName = ''
    }
}
