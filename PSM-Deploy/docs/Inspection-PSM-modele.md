# Inspection of the model PSM (read-only)

> Goal: read the **actual state** of an already-installed PSM in order to turn the
> idempotence detections (the script's `Test { ... }` blocks) into real tests, and
> gather the **exact names/paths** (services, cred files, version, AppLocker…).
>
> **All the commands below are READ-ONLY** (no modification).
> Run them in an **administrator PowerShell** console on the model PSM, then
> paste me the outputs. **Mask** anything sensitive (account names, IPs, URLs)
> if needed — I mostly need the *structure*, not the secrets.

---

## 1. Version & installation path
```powershell
# Installed version (adjust the filter if needed)
Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                 HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Where-Object { $_.DisplayName -like '*Privileged Session Manager*' -or $_.DisplayName -like '*CyberArk*' } |
  Select-Object DisplayName, DisplayVersion, InstallLocation | Format-Table -Auto

# Install path (default) + root contents
Test-Path 'C:\Program Files (x86)\CyberArk\PSM'
Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM' -Directory | Select-Object Name
```
➡️ *Tells me:* the exact key/value to **detect the installed version** and the **real path**.

## 2. PSM services
```powershell
Get-Service | Where-Object { $_.DisplayName -like '*CyberArk*' -or $_.Name -like '*PSM*' } |
  Select-Object Name, DisplayName, Status, StartType | Format-Table -Auto
```
➡️ *Tells me:* the **exact service names** (for the "PSM installed" test and the "services up" validation).

## 3. Credential files & Vault config
```powershell
# Cred files of the component accounts (bound to the machine)
Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM\Vault' -Filter *.cred -ErrorAction SilentlyContinue |
  Select-Object Name, Length, LastWriteTime

# Config files present (we look at the NAMES, not the sensitive content)
Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM' -Include *.ini,*.xml -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName | Format-Table -Auto
```
➡️ *Tells me:* the **cred file names** (`psmapp.cred`/`psmgw.cred`… → "already registered" test) and **where the XML/INI files live**.

## 4. RDS role & licensing
```powershell
Get-WindowsFeature -Name RDS-RD-Server | Select-Object Name, InstallState
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue |
  Select-Object LicensingMode, LicenseServers
```
➡️ *Tells me:* how the RDS license is **actually set** (exact registry values).

## 5. Hardening — "already applied" marker
```powershell
# Logs / traces left by the CyberArk hardening
Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM\Hardening' -ErrorAction SilentlyContinue |
  Select-Object Name, LastWriteTime
Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM\Hardening\*.log' -ErrorAction SilentlyContinue |
  Select-Object Name, LastWriteTime
```
➡️ *Tells me:* whether a **reliable marker** exists (log/file) to detect that hardening is done → idempotence.

## 6. AppLocker — effective policy
```powershell
# AppLocker service
Get-Service AppIDSvc | Select-Object Name, Status, StartType
# Export of the EFFECTIVE policy (paste it to me; this is our in-house reference)
(Get-AppLockerPolicy -Effective -Xml) | Out-File "$env:USERPROFILE\Desktop\AppLocker-effective.xml" -Encoding utf8
"Exported to the Desktop: AppLocker-effective.xml"
```
➡️ *Tells me:* the **actual AppLocker policy** in place (to version in `applocker/`), and the basis for building the idempotence test.

## 7. Additional software actually installed
```powershell
Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                 HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName | Format-Table -Auto
```
➡️ *Tells me:* the **actual list** of installed clients/tools (basis for the software XML + their detection tests).

## 8. PVWA registration / connection (for idempotence)
```powershell
# Spot the files/parameters that indicate registration (names only)
Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM\Vault' -ErrorAction SilentlyContinue |
  Select-Object Name, LastWriteTime
```
➡️ *Tells me:* how to detect locally that a PSM is **already registered**, complementing the check via PVWA.

---

## Open questions (to note down, no command)
- **Exact reboot points** in your procedure (after which step, how many in total)?
- **Exact command + CLI arguments** of the PSM installation?
- Location/retention of the **session recordings** (we will formalize this later)?
- A **sample XML** of the registration automation + of the file referencing PSMConnect/PSMAdminConnect (anonymized)?
