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
- an overlay file at the same relative path **always wins** over the base file;
- keep overlays to the **delta only** — everything common stays in the base
  (one fix in the base benefits every type at the next distribution);
- `state\`, `logs\` and `.git` are never shipped.

## Per-datacenter credentials

Admin rights are per datacenter: the DC-A account cannot reach the DRP
machines and vice versa. Each server carries a free `Datacenter` key in
`config\distribution.psd1`; the script prompts **one `Get-Credential` per
distinct datacenter** among the selected targets (`PRDNPR` machines live in
the DRP datacenter → same `DRP` key/credential). Passwords are kept in memory
only — never written to disk, consistent with the PSM-Deploy doctrine.

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
- The SMB session is authenticated with `New-PSDrive` + the datacenter
  credential (no plaintext password on any command line).
- One server's failure does not stop the others: summary at the end, exit
  code 1, and a ready-made `-Server <failed> -SkipStaging` relaunch hint.
- A type without an overlay folder gets the base tree only (WARN).

## Filling the inventory

`config\distribution.psd1` → `Servers`: one entry per PSM with `Name`
(machine name), `Type` (one of the four above) and `Datacenter` (free
credential key). Placeholders for PRD/DRP/PRDNPR are provided; the PRE
server is pre-filled.
