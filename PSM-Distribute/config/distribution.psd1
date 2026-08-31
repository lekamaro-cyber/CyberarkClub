@{
    # =====================================================================
    # Source distribution from the CPM (the CPM reaches every PSM on SMB/445).
    # No sensitive value here: the operator authenticates to the PVWA at
    # runtime, and each target machine's LOCAL admin password is retrieved
    # from the Vault on the fly - nothing is ever stored on disk.
    #
    # CPM disk layout (OverlayRoot/StagingRoot created by the script):
    #   D:\PSMSources\
    #     PSM-Deploy\        <- COMMON base (this repo's PSM-Deploy folder)
    #     overlays\<TYPE>\   <- the DELTA of each server type ONLY: typically
    #                           installers\... + config\software.psd1 (different
    #                           binaries per type), but ANY file is allowed
    #                           (e.g. a different media\ version). An overlay
    #                           file at the same relative path ALWAYS wins
    #                           over the base file.
    #     staging\<TYPE>\    <- composed trees (base + overlay), rebuilt by the
    #                           script - never edit them by hand.
    # =====================================================================

    SourceRoot  = 'D:\PSMSources\PSM-Deploy'   # common base tree (on the CPM)
    OverlayRoot = 'D:\PSMSources\overlays'     # per-type deltas
    StagingRoot = 'D:\PSMSources\staging'      # composed trees (script-managed)

    # Destination path ON each PSM server, reached through its admin share
    # (D:\... -> \\<server>\D$\...). The target's state\ and logs\ folders are
    # ALWAYS preserved (a server's deployment progress is local).
    TargetPath  = 'D:\PSMSources\PSM-Deploy'

    # Server types = folder names under overlays\ :
    #   PRD    - pure production, main datacenter
    #   DRP    - pure production, other datacenter (disaster recovery)
    #   PREPRD - separate infrastructure (test/PRE)
    #   PRDNPR - hosted in the DRP datacenter, serves NON-prod accounts
    ServerTypes = @('PRD', 'DRP', 'PREPRD', 'PRDNPR')

    # CyberArk/PVWA connection (same flow as the PSM registration): the
    # operator authenticates to the PVWA at launch (prompt with validation and
    # retry); the LOCAL admin password of EACH target machine is then
    # retrieved from the Vault at push time - no per-datacenter accounts, no
    # manual machine credentials. PRE values prefilled: adjust on another
    # infra's CPM.
    Pvwa = @{
        Url                  = 'https://oneconnection.pre.intra.corp'
        AuthMethod           = 'CyberArk'      # CyberArk | LDAP | Windows | RADIUS
        SkipCertificateCheck = $true           # lab only (self-signed certificate)
    }

    # Default LOCAL admin account: the SAME account name exists on every
    # machine and is onboarded in CyberArk (the local-accounts collection: one
    # Vault account per machine, address = the server). The SMB push then
    # authenticates as <SERVER>\<LocalAdminUserName>.
    LocalAdminUserName = ''        # e.g. 'locadm' - REQUIRED
    LocalAdminSafe     = ''        # optional Safe filter for the Vault lookup

    # Target inventory: machine name + server type (= overlay folder).
    Servers = @(
        @{ Name = 'FRPRDSRV10013'; Type = 'PREPRD' }
        # @{ Name = '<PRD-PSM-1>';  Type = 'PRD'    }
        # @{ Name = '<DRP-PSM-1>';  Type = 'DRP'    }
        # @{ Name = '<NPR-PSM-1>';  Type = 'PRDNPR' }
    )
}
