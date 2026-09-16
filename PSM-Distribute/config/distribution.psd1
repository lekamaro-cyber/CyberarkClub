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

    # Files NEVER pushed to the targets (robocopy /XF). 'autorun.inf' is
    # CD-autorun cruft shipped in the CyberArk media: AV/EDR and read-only/
    # hidden/system attributes routinely DENY overwriting it over SMB
    # (observed: robocopy ERROR 5 on media\PSM\autorun.inf killing the whole
    # push), and the installation never reads it.
    PushExcludeFiles = @('autorun.inf')

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

    # Try the operator's CURRENT session first (integrated SMB auth, free):
    # most CPM operators already have admin-share access to part of the fleet
    # - no point fetching/prompting anything for those machines. $false to
    # always start at the Vault-backed levels below.
    TryCurrentSession = $true

    # DOMAIN push accounts, one per ACCESS LOT - admin rights are granted per
    # scope (PRD France, DRP France, Benelux/NL...), a single account cannot
    # cover the fleet. Vault-managed DOMAIN accounts, fetched once per run and
    # per scope actually used by the selected servers. Each server points at
    # its lot via its 'Push' key below; a 'Default' entry, if present, serves
    # the servers that declare none (otherwise this cascade level is skipped
    # for them - level 0, the operator's own session, often suffices on their
    # own datacenter).
    PushAccounts = @{
        # PRDFR = @{ UserName = 'svc-push-prd'; Address = 'france.intra.corp';  Safe = ''; LogonName = 'FRANCE\svc-push-prd' }
        # DRPFR = @{ UserName = 'svc-push-drp'; Address = 'france.intra.corp';  Safe = ''; LogonName = 'FRANCE\svc-push-drp' }
        # NL    = @{ UserName = 'svc-push-nl';  Address = 'benelux.intra.corp'; Safe = ''; LogonName = 'BENELUX\svc-push-nl' }
        # LogonName empty -> '<UserName>@<Address>' (UPN) is used for the SMB logon.
    }

    # FALLBACK per machine, when the domain account fails on a server (or is
    # not configured): the machine's LOCAL admin account from CyberArk (one
    # Vault account per machine, address = the server, accounts spread across
    # Safes - lookup on username + exact machine address, short name or FQDN).
    # Local account names are NOT uniform across the fleet: a WILDCARD pattern
    # is accepted (e.g. '*adm*' matches AdminVal, admsvc, LocAdm...). Like the
    # PVWA search box, the pattern's core is sent as a keyword next to the
    # address ('adm <server>'), the wildcard is applied on the results, and an
    # address-only retry catches mid-name matches the keyword would hide; the
    # SMB logon uses the REAL name of the matched account. Several matches on
    # one machine = ambiguity error -> manual prompt (last resort).
    LocalAdminUserName = ''        # e.g. 'AdminVal' or '*adm*'; empty = skip this level

    # Target inventory: machine name + server type (= overlay folder) +
    # optional Push = key of the PushAccounts lot that covers the machine.
    Servers = @(
        @{ Name = 'FRPRDSRV10013'; Type = 'PREPRD' }                    # operator's own DC: level 0 usually suffices
        # @{ Name = 'FRDRPSRV10017'; Type = 'PREPRD'; Push = 'DRPFR' }  # other DC: pushed with that lot's account
        # @{ Name = '<PRD-PSM-1>';   Type = 'PRD';    Push = 'PRDFR' }
        # @{ Name = '<NL-PSM-1>';    Type = 'PRDNPR'; Push = 'NL'    }
    )
}
