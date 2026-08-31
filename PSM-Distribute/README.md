# PSM-Distribute — Source distribution from the CPM

Companion tool of [`PSM-Deploy`](../PSM-Deploy/README.md). Runs **on the CPM**
(the only machine with SMB/445 reachability to every PSM) and pushes the right
sources to each server — because the sources cannot be ONE tree: `installers\`
binaries and `config\software.psd1` differ per server type.

## Server types

| Type     | Meaning                                                    |
|----------|------------------------------------------------------------|
| `PRD`    | Pure production, main datacenter                           |
| `DRP`    | Pure production, other datacenter (disaster recovery)      |
| `PREPRD` | Separate infrastructure (test/PRE)                         |
| `PRDNPR` | Hosted in the DRP datacenter, serves NON-production accounts |

## Composition model: base + overlay

```
D:\PSMSources\                      (on the CPM)
├── PSM-Deploy\          # COMMON base: scripts, modules, config, media
├── overlays\
│   ├── PRD\             # the DELTA of each type ONLY - typically:
│   ├── DRP\             #   installers\...            (different binaries)
│   ├── PREPRD\          #   config\software.psd1      (different app list)
│   └── PRDNPR\          # any file works (e.g. a different media\ version)
├── staging\<TYPE>\      # composed trees, MANAGED BY THE SCRIPT - never edit
└── PSM-Distribute\      # this tool
```

Rules:
- **the `Type` value in `distribution.psd1` IS the folder name** under
  `overlays\` and `staging\`, used verbatim (case-insensitive on Windows):

  ```
  Servers entry Type = 'PRD'  ->  overlays\PRD\  ->  staging\PRD\
  ```

  A typo in either side simply means "no overlay found" (WARN, base-only) —
  the Pester tests guard the mapping for the shipped examples;
- an overlay file at the same relative path **always wins** over the base file
  — so an overlay `config\software.psd1` REPLACES the base one entirely:
  list the type's FULL software set in it, not a delta of the file;
- keep overlays to the **delta trees only** — everything common stays in the
  base (one fix in the base benefits every type at the next distribution);
- `state\`, `logs\` and `.git` are never shipped.

## Worked examples (`overlays-example\`)

Ready-to-copy templates, one per type — bootstrap with:
`Copy-Item .\overlays-example\* D:\PSMSources\overlays\ -Recurse`, then drop
the real MSIs over the `DROP-THE-MSI-HERE.txt` placeholders (which name the
exact expected file).

```
overlays-example\
├── PRD\                          # prod: Chrome only, NO test tooling
│   ├── config\software.psd1
│   └── installers\chrome\DROP-THE-MSI-HERE.txt
├── DRP\                          # same set as PRD today, but its OWN folder
│   ├── config\software.psd1      #   (free to diverge later without touching PRD)
│   └── installers\chrome\DROP-THE-MSI-HERE.txt
├── PREPRD\                       # test infra: Chrome + PrivateArk Client
│   ├── config\software.psd1
│   └── installers\{chrome,privateark}\DROP-THE-MSI-HERE.txt
└── PRDNPR\                       # non-prod ACCOUNTS on prod-grade machines: Chrome only
    ├── config\software.psd1
    └── installers\chrome\DROP-THE-MSI-HERE.txt
```

What a PREPRD server ends up with after composition (base + overlay):

```
staging\PREPRD\
├── Deploy-PSM.ps1, modules\, media\, ...   <- from the BASE (common)
├── config\settings.psd1, zones.psd1        <- from the BASE (common)
├── config\software.psd1                    <- from the OVERLAY (replaced)
└── installers\chrome\, installers\privateark\   <- from the OVERLAY
```

## Per-machine local accounts from CyberArk

No per-datacenter accounts and no manual machine credentials: the target
machines' LOCAL admin accounts are onboarded in CyberArk (the local-accounts
collection — the **same account name on every machine**, one Vault account
per machine with `address` = the server). At launch:

1. the operator logs on to the **PVWA once** (`config\distribution.psd1` →
   `Pvwa.Url/AuthMethod`; same validated/retried prompt as the deployment's
   Registration phase, or pass `-PvwaCredential`);
2. for each target, the script retrieves **that machine's** local account
   password from the Vault (`userName = LocalAdminUserName`, exact
   `address` match on the machine — short name or FQDN). The accounts are
   spread across Safes: **no Safe to declare**;
3. the SMB push authenticates as **`<SERVER>\<LocalAdminUserName>`**.

Passwords stay in memory only (masked in the logs) — never written to disk,
consistent with the PSM-Deploy doctrine. If a machine's account is not found
in the Vault (or the retrieve is refused), the script **falls back to a
manual credential prompt** for that machine (pre-filled with
`<SERVER>\<LocalAdminUserName>` — supply any account that has admin-share
access, local or domain); canceling the prompt marks only THAT server FAILED,
the others continue.

One `LocalAdminUserName` line in the settings is the whole configuration.

## Usage

```powershell
# Dry-run: shows the plan, prompts for nothing
.\Distribute-PSMSources.ps1 -WhatIf

# Everything in the inventory
.\Distribute-PSMSources.ps1

# One type / one server
.\Distribute-PSMSources.ps1 -Type PRD
.\Distribute-PSMSources.ps1 -Server FRPRDSRV10013

# Re-push without recomposing the staging trees
.\Distribute-PSMSources.ps1 -Server <srv> -SkipStaging
```

## Behavior & warnings

- Transport is `robocopy /MIR` over the admin share
  (`\\<server>\D$\PSMSources\PSM-Deploy`): the target **converges** to the
  staging tree — files that no longer exist in the sources are **deleted** on
  the target — EXCEPT `state\` and `logs\`, always preserved (the server's
  deployment progress and history are local).
- The SMB session is authenticated with `New-PSDrive` + the machine's local
  account fetched from the Vault (no plaintext password on any command line).
- One server's failure does not stop the others: summary at the end, exit
  code 1, and a ready-made `-Server <failed> -SkipStaging` relaunch hint.
- A type without an overlay folder gets the base tree only (WARN).

## Filling the inventory

`config\distribution.psd1` → `Servers`: one entry per PSM with `Name`
(machine name) and `Type` (one of the four above). Placeholders for
PRD/DRP/PRDNPR are provided; the PRE server is pre-filled. Also set
`LocalAdminUserName` (the CyberArk-managed local admin account) and the
`Pvwa` block if the CPM belongs to another infra.
