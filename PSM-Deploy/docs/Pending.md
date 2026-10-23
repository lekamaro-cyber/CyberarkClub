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
- [ ] EDR exclusion, then remove `Hardening` from `state\progress.json` and replay.
- [ ] Once clean everywhere: `Hardening.NonBlocking = $false`.

## 4. Not yet run on a server

- [ ] PreFlight version guard (install, never upgrade): test with `-Reset -WhatIf`.
- [ ] Ordered credential sequence with rollback (`Sync-PSMComponentCredential`).
- [ ] Merged software list (`software.psd1` + `software.extra.psd1`).
- [ ] RDP certificate behind the VIP (`RdpCertificate` phase, zones.psd1 `PsmVips`):
      validated on FRPRDSRV10013 (certificate found by SAN, key readable by NETWORK
      SERVICE, already bound -> OK) and the "NO private key" alert on FRPRDSRV10012.
      Not exercised yet on a server: an actual binding change (CHANGED).
