# PSM-Deploy — Idempotent deployment of a CyberArk PSM (PowerShell)

> ⚠️ **Status: skeleton / design phase.** The code defines the structure,
> the idempotence and the flow. The blocks marked `TODO (deployment)` / `STUB`
> must be completed with the CyberArk media and the real values before
> any production use. **No sensitive value is committed to version control.**

## Goal

Deploy a CyberArk **Privileged Session Manager (PSM)** in an **idempotent** way
(Ansible-style: each phase `Test → Set`, reporting `OK / CHANGED / FAILED`),
executed **locally** on each PSM server from a **self-contained "sources"
folder** that is copied onto the machine and then launched with administrator
rights.

## Architecture decisions (validated)

| Topic | Decision |
|---|---|
| Language | PowerShell, idempotent, `-WhatIf` (dry-run) + `-Confirm` |
| Versions | PSM **12.6** target, compatible with **14.0** (parameterized by version) |
| Execution | **Local** on each PSM, admin rights. No WinRM. |
| Delivery | **Self-contained** folder copied onto the target |
| Topology | PSM **in-domain**, **behind Load Balancer**, **2 datacenters with closed network flows** |
| Vault | **Single central** Vault reachable from both DCs |
| Zones | 2 datacenters → mapping `zone ⇄ {PVWA, AuthMethod, install account}` |
| PSM install | **Stage-by-stage driving** of the CyberArk framework (`InstallationAutomation\Execute-Stage.ps1`): Readiness → Prerequisites → Installation → PostInstallation → Registration → Hardening |
| Component accounts | **PSMApp/PSMGw** registered via the media's registration automation |
| Connection accounts | **PSMConnect/PSMAdminConnect = domain accounts managed by CPM** — passwords retrieved at runtime by the PSM service (PSMConnect Safe), **not provided at install time** |
| Secret retrieval | **Via the PVWA REST API** (no CCP/AIM) — the installing admin authenticates to PVWA and the script retrieves the Vault install account |
| PVWA auth | `Connect-PvwaSession`: CyberArk / LDAP / Windows / RADIUS; `SkipCertificateCheck` in lab |
| Additional software | Driven by `config/software.psd1` (cmd + detection) |
| AppLocker | **Controlled embedded policy** (`applocker/`), applied by the script |
| Hardening | **Full CyberArk** (PSMHardening + AppLocker) |
| RDS licensing | Mode + server in config |
| Reboot | **Supervised resume**: the admin's `AtLogOn` task → resumes in their session upon reconnection (state machine) |
| PVWA connection components | **Out of scope** (binaries only on the PSM side) |
| Logs | **Structured local** (transcript + JSONL), secrets masked |
| Failure | **Fail-fast** + idempotent resume |

## Directory layout

```
PSM-Deploy/
├─ Deploy-PSM.ps1            # Orchestrator (phases + state machine + reboot/resume)
├─ config/
│  ├─ settings.psd1          # PSM version, RDS license, paths
│  ├─ zones.psd1             # Per-datacenter mapping (PVWA/AuthMethod/install account)
│  └─ software.psd1          # Additional software (silent cmd + detection)
├─ modules/
│  ├─ PSM.Common.psm1        # Idempotence, logs+masking, state/resume, confirmations
│  ├─ PSM.Pvwa.psm1          # PVWA REST API: logon + Get-PvwaAccountPassword (secrets)
│  ├─ PSM.Stages.psm1        # "Stage-by-stage" driving of CyberArk (Execute-Stage.ps1)
│  ├─ PSM.Prereqs.psm1       # RDS/RDSH, RDS license, registry
│  ├─ PSM.Install.psm1       # CyberArk Installation + PostInstallation stages
│  ├─ PSM.Register.psm1      # CyberArk Registration stage (Vault secret via -spwdObj)
│  ├─ PSM.Hardening.psm1     # PSMHardening + controlled AppLocker policy
│  └─ PSM.Software.psm1      # Generic config-driven install
├─ applocker/PSMConfigureAppLocker.xml   # Controlled AppLocker policy (placeholder)
├─ media/                    # (empty) PSM 12.6/14.0 media — not versioned
├─ installers/               # (empty) additional binaries — not versioned
├─ state/                    # progress (post-reboot resume) — not versioned
├─ logs/                     # transcript + JSONL — not versioned
└─ tests/Deploy-PSM.Tests.ps1
```

## Phase flow

```
PreFlight → Readiness → Prerequisites(RDS) → [reboot+resume] → RdsLicensing → Software
       → Installation → PostInstallation → Registration(secret via PVWA API)
       → Hardening(+AppLocker) → Validation

Readiness / Prerequisites / Installation / PostInstallation / Registration / Hardening
are **CyberArk stages** driven via `InstallationAutomation\Execute-Stage.ps1`
(configured through the `*Config.xml` files filled in by the team). The rest (PreFlight,
RDS license, software, validation) and PVWA secret retrieval are handled by the script.
```
> 🧩 **Stage config driven by ours (media never modified).** The values that
> depend on our environment are **injected** into a **patched copy** of the
> `*Config.xml` under `state\config\<Stage>\` — the media stays intact, so **dropping
> in a new CyberArk source requires no manual editing of the XML files**. A single
> mechanism (`Resolve-PSMStageConfig` → `Update-PSMStageXml`) serves all stages:
> **static** values via `settings.psd1` (`Install.Injections[<Stage>]`) and
> **dynamic** values from the code (e.g. the zone's Vault address for *Registration*).
> Without a declared injection for a stage, the media's XML is used as-is.
Each phase is marked complete in `state/progress.json`. The **`AtLogOn` scheduled
task** for resuming is **armed at the very start of the run** (safety net: some
CyberArk installers reboot the machine **without returning control** — observed at the
Installation stage; without a pre-armed task, nothing would resume after reconnection).
When a reboot is required, this task is (re)armed for the **installing admin**:
as soon as they **reconnect after the restart**, the script **resumes on its own in
their session** (`-Resume`, zone re-read from state) at the first unfinished phase.
The resume is **interactive** (the PVWA `Get-Credential` prompts work) and
**no secret is stored** on disk. The task is removed at the end of the deployment.

## Usage

```powershell
# 1) Copy the PSM-Deploy folder onto the PSM server, drop the media into media\
#    and the installers into installers\.

# 2) "Plan" mode (dry-run) — changes nothing:
.\Deploy-PSM.ps1 -Zone DC1 -WhatIf

# 3) Real deployment (interactive confirmations, including the zone):
.\Deploy-PSM.ps1 -Zone DC1

# 4) Resume (normally automatic via the scheduled task after reboot):
.\Deploy-PSM.ps1 -Zone DC1 -Resume

# 5) Start over from SCRATCH (after uninstalling/cleaning up the PSM): resets
#    the state to replay ALL phases (Installation included):
.\Deploy-PSM.ps1 -Zone DC1 -Reset
```

> ⚠️ **`-Reset` is mandatory if you clean up the PSM by hand.** The orchestrator
> is idempotent: it reads `state\progress.json` and **skips the phases already marked
> complete**. If you uninstall the PSM without resetting the state, it will skip
> the real `Installation` and move straight to `PostInstallation` on a machine without
> a PSM ("*PSM was not located or properly installed*"). `-Reset` (or deleting the
> `state\` folder) resets the counter to zero. `-Reset` is incompatible with `-Resume`.

> 🔒 **Mandatory zone confirmation** before acting (except with `-NonInteractive`):
> a wrong zone = wrong Vault/PVWA/account. Deliberate blunder-proofing.

## Security

- Secrets as `SecureString`, **masked** in all logs; no secret in version control.
- `#Requires -RunAsAdministrator` + elevation check at startup.
- Secret retrieval **via the PVWA REST API** using the installing admin's session
  (no CCP/AIM to provision). The session token is closed (`Logoff`) at the end of the phase.
- `SkipCertificateCheck` reserved for the **lab**; in production, keep TLS validation active.

## To complete before deployment (`TODO` / `STUB`)

- `media/PSM/`: drop in the CyberArk media (contains `InstallationAutomation\Execute-Stage.ps1`).
- **`InstallationAutomation\*\*Config.xml`**: fill in the stage configs (blueprints
  in `InstallationAutomation\Templates\`) — this is the team's data (PVWA, Vault,
  component accounts, hardening/AppLocker options…).
- `zones.psd1` / `settings.psd1`: real values (PVWA, auth method, install account, RDS license).
  - **Installation directory**: a **single** value `settings.psd1` → `Install.InstallDir`
    (e.g. `D:\CyberArk`). The code **derives** everything from it: `InstallationDirectory`
    injected into `InstallationConfig.xml`, the `PSM` folder (`<InstallDir>\PSM`), the
    recordings (`Install.RecordingDir`, otherwise `<InstallDir>\PSM\Recordings`) and the
    `PSMConfigureAppLocker.xml` path for Hardening. **Nothing to re-enter anywhere else.**
  - **PSMConnect / PSMAdminConnect** (session accounts, **domain**): **per zone**
    in `zones.psd1` (`PSMConnectUserName` / `PSMAdminConnectUserName`, format
    `DOMAIN\user`). They are **not** stage parameters — they are **patched
    in place** (`.orig` backup, replayable) at **two levels**:
    1. **`InstallationAutomation\Consts.ps1`** (media) — `PSM_CONNECT` /
       `PSM_ADMIN_CONNECT` constants consumed by the automation steps
       (`Set-PSMAutomationConsts`, called before PostInstallation and Hardening);
    2. **`PSMHardening.ps1` / `PSMConfigureAppLocker.ps1`** (generated at install time
       under `<InstallDir>\PSM\Hardening`) — variables `$PSM_CONNECT_USER` /
       `$PSM_ADMIN_CONNECT_USER` and `$PSM_CONNECT` / `$PSM_ADMIN_CONNECT`
       (`Set-PSMConnectAccounts`, called at the start of the Hardening phase; mapping
       configurable in `settings.psd1` → `Hardening.ScriptAccountVariables`).
    **Empty zone accounts = inactive.** If a variable cannot be found (different media
    version), the script stops and lists the candidate variables. The
    **passwords** are never here: managed in the **PSM Safe** on the Vault side.
    ⚠️ With **domain** accounts, the PostInstallation steps `DisableScreenSaver` and
    `ConfigurePSMUsers` (**local** users only) are **disabled** via
    `Install.Injections` (enabled by default in `settings.psd1`) — carry the equivalent
    (screensaver, session properties) via **GPO/AD** on the zone's accounts.
  - **Component account naming** (`settings.psd1` → `Registration.RenameComponents`,
    enabled by default): `RegisterComponent.exe` generates random names
    (`PSMApp_<hex>`/`PSMGw_<hex>`) **with no naming option** for PSM. After
    registration, the script automatically renames them per the convention
    (`PSM-<HOSTNAME>` / `PSMA<HOSTNAME>`, configurable patterns): Vault user via
    the PVWA API + `Username=` of the cred files (password unchanged, `.orig` backup),
    with the PSM service stopped/restarted during the operation. Idempotent (does
    nothing if already compliant). `PSMServerId`/`PSMServerAdminId` in `basic_psm.ini`
    are **opt-in** (`Registration.RenameServerIds`, off by default): they must stay
    aligned with the "PSM Server" object in PVWA Options — enable only if you **also
    rename that object manually** in PVWA (as done on the production PSMs).
  - **`Hardening.NonBlocking`** (`settings.psd1`, enabled by default): a failure of the
    Hardening stage is **tolerated** (WARN, deployment continues) instead of stopping —
    case encountered: EDR blocking system ACL modifications (even `takeown`). The failed
    steps remain **to be retried** (EDR exclusion, then remove `Hardening` from
    `state\progress.json` and rerun). Set back to `$false` for the strict behavior.
- `config/software.psd1`: any additional software.

## Tests

```powershell
Invoke-Pester -Path .\tests\Deploy-PSM.Tests.ps1
```
Verifies the structure, module loading and the **idempotence contract**
(2nd run of an already-compliant phase = `OK`, no change).
