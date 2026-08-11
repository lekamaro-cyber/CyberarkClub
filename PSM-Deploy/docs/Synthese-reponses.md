# Answer summary — Discovery + L2 interview

> Answers captured during the interactive rounds. Serves as the basis for completing
> the script (`PSM-Deploy/`). The **[L2/to obtain]** points remain to be confirmed or
> obtained (files, values) from the L2.

## OS, RDS & domain
- **Windows Server 2022** for the new servers.
- **RD Session Host role installed by the CyberArk automation script** (we do not duplicate it).
- **RDS licensing set locally** on the PSM (mode + license server).
- PSM **joined to the domain BEFORE** the installation.

## PSM installation
- Install via a **command launched manually with CLI arguments** (no answer file).
  - **[L2/to obtain]** exact command + CLI arguments.
- **3+ reboots / variable** → state machine + automatic resume indispensable.
- **14.0 not tested yet** → target 12.6, code parameterized by version.

## Accounts
- **PSMConnect / PSMAdminConnect**: domain accounts **already created**. Defined **per zone** in `zones.psd1` (`PSMConnectUserName` / `PSMAdminConnectUserName`, format `DOMAIN\user`). Finding (media 12.6.11 + PSM in service): **no stage `*Config.xml`** carries these accounts — they live at **two levels**, patched **in place** (`.orig` backup, replayable): (1) the media's **`InstallationAutomation\Consts.ps1`** (`Set-Variable PSM_CONNECT / PSM_ADMIN_CONNECT`), consumed by the automation steps → `Set-PSMAutomationConsts` before PostInstallation/Hardening; (2) the **variables** of `PSMHardening.ps1` (`$PSM_CONNECT_USER` / `$PSM_ADMIN_CONNECT_USER`) and `PSMConfigureAppLocker.ps1` (`$PSM_CONNECT` / `$PSM_ADMIN_CONNECT`), **generated at install time** under `<InstallDir>\PSM\Hardening` → `Set-PSMConnectAccounts` at the start of the Hardening phase. **Inactive** if the zone accounts are empty; variable not found = stop with the list of candidates. The **passwords** are not in config: **managed in the PSM Safe** on the Vault side.
- PVWA auth of the admin/install account: **CyberArk**.
- Component account naming: **`PSM-<SERVERNAME>` in UPPERCASE**. Finding: `RegisterComponent.exe` (the registration tool) generates random names (`PSMApp_<hex>`) **with no naming option** for PSM — production was renamed by hand (user via PVWA + cred file + basic_psm.ini). This procedure is now **automated** post-Registration (`Rename-PSMComponentAccounts`, see `settings.psd1 Registration.RenameComponents`): app = `PSM-<HOST>`, gateway = `PSMA<HOST>`.
- Credential files (.cred) **bound to the machine** (CreateCredFile with restrictions).

## Secret retrieval — **REVISED DECISION: via the PVWA API (no CCP/AIM)**
- **The admin performing the installation authenticates themselves to the PVWA** (they have
  access to all CyberArk accounts). The script retrieves the password of the **Vault
  install/admin account** on the fly via the **PVWA REST API** (`Get-PvwaAccountPassword`).
- **No more CCP/AIM**: no AppID, no application certificate to provision.
- Supported PVWA auth: **CyberArk / LDAP / Windows / RADIUS** (per zone). In the lab,
  `SkipCertificateCheck = $true` to tolerate the self-signed certificate.
- **[L2/to obtain]** Safe + name of the install account to retrieve per DC (or: the logged-in
  admin acts as the install account → `InstallAccount*` left empty).
- ~~One CCP per datacenter behind a VIP + client certificate~~ *(approach abandoned)*.

## Vault / PVWA / registration
- **Single central Vault** reachable from both DCs.
- Registration via the **"registration automation" present in the sources** + **XML files placed by hand**, with **manual confirmation BEFORE** execution.
- **Evolution (config driven by ours, media never modified)**: the values that
  depend on our environment are no longer edited by hand in the media's `*Config.xml`
  files. A **single injection mechanism** (`Resolve-PSMStageConfig` →
  `Update-PSMStageXml`) writes these values into a **patched copy** under
  `state\config\<Stage>\`, for **all stages** (Readiness → Hardening). Two sources:
  **static** values in `settings.psd1` (`Install.Injections[<Stage>]`) and
  **dynamic** values from the code — including the **zone's Vault address** (`zones.psd1`)
  injected for *Registration*. Result: **dropping in a new CyberArk source requires no
  manual editing of the XML files**; without a declared injection, the media's XML is used as-is.
- **Idempotence**: we connect to the **PVWA with the admin's account** (session opened for secret retrieval) to check whether the PSM is **already registered** before acting.
- **[L2/to obtain]** content/template of the registration XML files + PVWA URL per DC.

## Additional software
- Driven by **an XML to fill in** + **a source folder**; the team puts **the .exe files and the command lines** there.
  - → I align the mechanism on an **XML file** (instead of the `.psd1`).
- **[L2/to obtain]** list of apps, versions, .exe files, silent command lines, detection tests.

## Hardening & AppLocker
- **Customized PSMHardening** (notably for PSMConnect / PSMAdminConnect).
  - **[L2/to obtain]** customized version of PSMHardening.
- **AppLocker: customized in-house XML**.
  - **[L2/to obtain]** reference AppLocker XML (to version in `applocker/`).
- **AV/EDR** exclusions: **already handled by the OS admins** → out of scope.

## Load Balancer
- Adding to / removing from the pool **handled ahead of time** → **out of scope** for the script.

## Validation & operations
- Post-install validation: **PSM services started** (no automated connection test).
- **No non-replayable step** → everything is replayable (healthy idempotence).
- Logging: **structured local logs are sufficient** (no central copy).

---

## Impacts on the skeleton (adjustments to apply)

1. **Prereqs**: no longer install the RDS role (done by CyberArk); keep only the **local RDS licensing** config.
2. **Software**: replace `config/software.psd1` with a **`config/software.xml`** (schema: app = name + relative exe + arguments + return codes + detection test) + installer source folder.
3. **Secrets**: `zones.psd1` = **PVWA per DC** + auth method + install account (retrieved via PVWA API). *(CCP abandoned.)*
4. **Register**: call the sources' **registration automation** with the **XML files**, preceded by a **manual confirmation**; **idempotence = check via PVWA connection**.
5. **Hardening**: hook up the **customized PSMHardening** + apply the versioned **in-house AppLocker XML**.
6. **Naming**: components `PSM-<SERVERNAME>` in uppercase.
7. **Validation**: smoke test = **services up** only.
8. **Logs**: local only (already in place).

## To bring back from the L2 meeting (files/values)
- [ ] Exact command + CLI arguments of the PSM install
- [ ] Registration XML (registration automation)
- [ ] PSMConnect/PSMAdminConnect specification XML (install sources)
- [ ] Customized PSMHardening
- [ ] In-house AppLocker XML
- [ ] Additional software XML + .exe files + command lines
- [ ] Per-DC values: PVWA URL, auth method, Safe + install account to retrieve, RDS license server FQDN
- [ ] Exact reboot points in the procedure
