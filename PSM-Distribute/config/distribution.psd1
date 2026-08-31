@{
    # =====================================================================
    # Source distribution from the CPM (the CPM reaches every PSM on SMB/445).
    # No sensitive value here: the per-datacenter admin credentials are
    # PROMPTED at runtime (Get-Credential), never stored on disk.
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

    # Datacenters reachable with the CURRENT session account (the operator's
    # own CPM logon): NO credential prompt for them, integrated SMB
    # authentication. The other datacenters still get one Get-Credential each.
    # If the current account turns out NOT to have rights there, the push
    # fails with "share unreachable / access denied": remove the datacenter
    # from this list to be prompted again.
    CurrentUserDatacenters = @()     # e.g. @('DC1')

    # Target inventory. 'Datacenter' is a FREE key that only drives which
    # credential is used: the script prompts ONE Get-Credential per DISTINCT
    # datacenter among the selected servers (each datacenter has its own admin
    # account; PRDNPR machines live in the DRP datacenter -> same 'DRP' key).
    Servers = @(
        @{ Name = 'FRPRDSRV10013'; Type = 'PREPRD'; Datacenter = 'PRE' }
        # @{ Name = '<PRD-PSM-1>';  Type = 'PRD';    Datacenter = 'DCA' }
        # @{ Name = '<DRP-PSM-1>';  Type = 'DRP';    Datacenter = 'DRP' }
        # @{ Name = '<NPR-PSM-1>';  Type = 'PRDNPR'; Datacenter = 'DRP' }   # DRP DC account
    )
}
