# Pending items

Open topics parked for later, with what is already known. Remove an item once it is done.

## 1. F5 WAF in front of the PVWA VIP blocks the component rename

**Proven on 2026-10-23** (FRPRDSRV10012): through `https://oneconnection.pre.intra.corp`,
`PUT /PasswordVault/API/Users/{id}` is answered by the F5 application firewall, not by
the PVWA: HTTP 200, `text/html`, page "Request Rejected … Your support ID is: …". The
request never reaches the PVWA. Pointing `zones.psd1` `PvwaUrl` at a single PVWA node
works (rename applied and verified).

To do:
- [ ] **Network ticket**: support ID `8725453128603392203`, `PUT
      https://oneconnection.pre.intra.corp/PasswordVault/API/Users/3012`, 2026-10-23
      16:45:45, source = FRPRDSRV10012's IP. Ask which rule fired, and for an exception
      on `PUT /PasswordVault/API/Users/*`. The answer should also explain why FRPRDSRV10013
      passed.
- [ ] **Script**: route the password reset (`POST /Users/{id}/ResetPassword`) and the user
      deletion (`DELETE /Users/{id}`) through `Invoke-PvwaRequestTraced`
      (`modules/PSM.Pvwa.psm1`), like the rename. Today they use `Invoke-RestMethod`,
      which takes a WAF HTML page for a success: a silently blocked reset would leave the
      new cred file and the old Vault password apart (ITATS004E at service start).
- [ ] Until then: keep `PvwaUrl` on a single PVWA node in `zones.psd1`.

## 2. Domain PSMConnect / PSMAdminConnect not applied by the 14.0 Hardening

The 14.0 Hardening and AppLocker steps read the session accounts from the
`PSMConnectionUsersInfo` key of `InstallationAutomation\InstallationConfiguration\InstallationConfiguration.json`
(`RegularUser` / `AdminUser`, each with `Name` and `Domain`). The media's JSON has no such
key, so both fall back to the LOCAL `<host>\PSMConnect` / `PSMAdminConnect`; the
`Consts.ps1` patch does not reach them.

To do:
- [ ] Validate by hand: add the key to the JSON (`.orig` backup), replay the Hardening,
      check that `FRSVCPRE` appears in the `PSMHardening-*.log`.
- [ ] If confirmed: inject it from `zones.psd1` (domain and name split), like `Consts.ps1`.

## 3. Hardening blocked by the EDR on `C:\`

`RunHardening` stops on `PSMHRD004 Failed to remove permissions … Path: C:\`
(tolerated: `Hardening.NonBlocking = $true`).

To do:
- [ ] EDR exclusion, then `.\Deploy-PSM.ps1 -Zone <zone> -RedoHardening` (the configuration
      check at the end must no longer report "Drive permissions" / "Hardening (last run)").
- [ ] Once clean everywhere: `Hardening.NonBlocking = $false`.

## 4. Not yet run on a server

- [ ] PreFlight version guard (install, never upgrade): test with `-Reset -WhatIf`.
- [ ] Ordered credential sequence with rollback (`Sync-PSMComponentCredential`).
- [ ] Merged software list (`software.psd1` + `software.extra.psd1`).
- [ ] RDP certificate behind the VIP (`RdpCertificate` phase, zones.psd1 `PsmVips`):
      validated on FRPRDSRV10013 (certificate found by SAN, key readable by NETWORK
      SERVICE, already bound -> OK) and the "NO private key" alert on FRPRDSRV10012.
      Not exercised yet on a server: an actual binding change (CHANGED).
- [ ] `-RedoHardening` and the configuration check (`tools\Test-PSMConfiguration.ps1`):
      flows simulated off-Windows only. First run: the check alone on BEDRPSRV10649 (expected
      alerts: drive permissions, RDS logon right with the PRD accounts), then `-RedoHardening`.
      On a PSM not deployed by the script: run the check alone first.

## 5. PRD Vault: PSM license full (blocks every new PSM)

**Found on 2026-10-28** (NLHOUSRV10662): `RegisterComponent.log` -> `ITATS937E Limit of 40
licensed PSM users exceeded`. License file: PSM = 20, multiplicity 2 (one application + one
gateway user per PSM, both of type `PSM`). Registered today: 18 official PSMs + BEDRPSRV10648/10649
= 20 servers = 40/40. PSMP users are counted apart (`PSMPServer`, 16/40). Not a network or
`-NoPvwa` issue.

To do:
- [ ] License extension for the migration (peak = old + new PSMs running at the same time),
      or unregister each replaced old PSM (its 2 users + PSM Server object) before the new one.
- [ ] Check System Health for long-disconnected PSMs still holding 2 slots each.

## 6. Gateway user naming does not match production

Production gateways are `PSMGw_<HOST>` (older PSMs) or `Gw_<HOST>` (recent ones); the
application user is always `PSM-<HOST>`. `settings.psd1` `GwUserPattern = 'PSMA{HOSTNAME}'`
matches no production server (only BEDRPSRV10648/10649, renamed by the script).

To do:
- [ ] Choose the convention: `Gw_{HOSTNAME}`, or `PSMGw_{HOSTNAME}` (= the 14.0 native name:
      no gateway rename at all, only the application user).
- [ ] Set `GwUserPattern` accordingly, then fix BEDRPSRV10648/10649 (remove `Registration`
      from `state\progress.json`, relaunch with the PVWA reachable: only the gateway is renamed).

## 7. RDS logon right: PRD session accounts on an NPR server

**Seen on 2026-10-30** (BEDRPSRV10649, zone NPRFR): "Allow log on through Remote Desktop
Services" = `FRANCE\FRSVCPRDPSMConnect`, `FRANCE\FRSVCPRDPSMAdminConn`, Administrators. A
GPO user right REPLACES the whole local list at every refresh. The configuration check now
reports it ("RDS logon right", with the GPO name).

To do:
- [ ] AD team: one OU per zone for the PSM servers in each domain, one small GPO per zone
      holding only this right (full list: Administrators + the zone's two accounts), and
      the right removed from the common PSM GPO.

## 8. PSM upgrade (`-Upgrade`): wizard-based, not run on a server yet

**Checked on 2026-11-02** on the 14.0 media: `Execute-Stage.ps1` takes only `configFilePath,
silentMode, displayJson, delayedrestart, restartAfterStageCompleted, pwd, spwd, spwdObj` (no
`-modeOfOperation`), no stage XML mentions an upgrade, no upgrade file in the media. The
production PSMs are all 14.0.x; the vulnerability fix comes as a higher 14.0 build (full
media). `-Upgrade` therefore wraps the CyberArk wizard (README, "-Upgrade").

**First run on 2026-11-02** (FRPRDSRV10013, 14.0.5.91 -> 14.0.6.63): `-WhatIf` picked
`media\PSM\setup.exe` and both versions right. Real run, seen:
- the wizard asks for the Oracle Instant Client (19c 64-bit chosen) and for a **Vault
  account** ("update the environment required for the Policy Manager in the Vault");
- `Start-Process -Wait` returned while the wizard was still running ("repairing"): the
  script replayed the Hardening and ran the check mid-install. Fixed: it now waits for
  the installer processes, then asks for ENTER once the wizard is closed;
- the wizard's Vault logon failed: `ITACM020S ... vault was temporarily unavailable
  (520,513,10054)` although `tnc 10.176.202.17 -p 1858` succeeds (10054 = connection reset).

To do:
- [ ] ITACM020S: retry; check the address in `<PSM>\Vault\Vault.ini`, the PRE Vault ITALog
      (source 10.176.91.55). Once the wizard is done: `-RedoHardening` (it ran mid-install).
- [ ] Silent upgrade: NOT with a recorded `.iss` - the wizard's Vault password would sit in
      it in clear. Only if a later media takes the password like the Registration does
      (`-spwdObj`); then replace the wizard step only.
