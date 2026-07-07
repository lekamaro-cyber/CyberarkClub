# Inspection du PSM modèle (lecture seule)

> Objectif : lire l'**état réel** d'un PSM déjà installé pour transformer les
> détections d'idempotence (les `Test { ... }` du script) en vrais tests, et
> récupérer les **noms/chemins exacts** (services, cred files, version, AppLocker…).
>
> **Toutes les commandes ci-dessous sont en LECTURE SEULE** (aucune modification).
> Lance-les dans une console **PowerShell administrateur** sur le PSM modèle, puis
> colle-moi les sorties. **Masque** ce qui est sensible (noms de comptes, IP, URLs)
> si besoin — j'ai surtout besoin de la *structure*, pas des secrets.

---

## 1. Version & chemin d'installation
```powershell
# Version installée (adapter le filtre si besoin)
Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                 HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Where-Object { $_.DisplayName -like '*Privileged Session Manager*' -or $_.DisplayName -like '*CyberArk*' } |
  Select-Object DisplayName, DisplayVersion, InstallLocation | Format-Table -Auto

# Chemin d'install (par défaut) + contenu racine
Test-Path 'C:\Program Files (x86)\CyberArk\PSM'
Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM' -Directory | Select-Object Name
```
➡️ *Me dit :* la clé/valeur exacte pour **détecter la version installée** et le **chemin réel**.

## 2. Services PSM
```powershell
Get-Service | Where-Object { $_.DisplayName -like '*CyberArk*' -or $_.Name -like '*PSM*' } |
  Select-Object Name, DisplayName, Status, StartType | Format-Table -Auto
```
➡️ *Me dit :* les **noms de services exacts** (pour le test « PSM installé » et la validation « services up »).

## 3. Credential files & config Vault
```powershell
# Cred files des comptes composants (liés à la machine)
Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM\Vault' -Filter *.cred -ErrorAction SilentlyContinue |
  Select-Object Name, Length, LastWriteTime

# Fichiers de config présents (on regarde les NOMS, pas le contenu sensible)
Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM' -Include *.ini,*.xml -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName | Format-Table -Auto
```
➡️ *Me dit :* **noms des cred files** (`psmapp.cred`/`psmgw.cred`… → test « déjà enregistré ») et **où vivent les XML/INI**.

## 4. Rôle RDS & licences
```powershell
Get-WindowsFeature -Name RDS-RD-Server | Select-Object Name, InstallState
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue |
  Select-Object LicensingMode, LicenseServers
```
➡️ *Me dit :* comment est **réellement posée** la licence RDS (valeurs registre exactes).

## 5. Hardening — marqueur « déjà appliqué »
```powershell
# Logs / traces laissés par le hardening CyberArk
Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM\Hardening' -ErrorAction SilentlyContinue |
  Select-Object Name, LastWriteTime
Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM\Hardening\*.log' -ErrorAction SilentlyContinue |
  Select-Object Name, LastWriteTime
```
➡️ *Me dit :* s'il existe un **marqueur fiable** (log/fichier) pour détecter que le hardening est fait → idempotence.

## 6. AppLocker — politique effective
```powershell
# Service AppLocker
Get-Service AppIDSvc | Select-Object Name, Status, StartType
# Export de la politique EFFECTIVE (à me coller ; c'est notre référence maison)
(Get-AppLockerPolicy -Effective -Xml) | Out-File "$env:USERPROFILE\Desktop\AppLocker-effective.xml" -Encoding utf8
"Exporté sur le Bureau : AppLocker-effective.xml"
```
➡️ *Me dit :* la **vraie politique AppLocker** en place (à versionner dans `applocker/`), et de quoi bâtir le test d'idempotence.

## 7. Logiciels additionnels réellement installés
```powershell
Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                 HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName | Format-Table -Auto
```
➡️ *Me dit :* la **liste réelle** des clients/outils installés (base pour le XML des logiciels + leurs tests de détection).

## 8. Enregistrement / connexion PVWA (pour l'idempotence)
```powershell
# Repérer les fichiers/paramètres qui indiquent l'enregistrement (noms seulement)
Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM\Vault' -ErrorAction SilentlyContinue |
  Select-Object Name, LastWriteTime
```
➡️ *Me dit :* comment détecter localement qu'un PSM est **déjà enregistré**, en complément du check via PVWA.

---

## Questions ouvertes (à noter, pas de commande)
- **Points de reboot exacts** dans ta procédure (après quelle étape, combien au total) ?
- **Commande + arguments CLI exacts** de l'installation PSM ?
- Emplacement/rétention des **enregistrements de session** (on formalisera plus tard) ?
- Un **XML type** de la registration automation + du fichier qui référence PSMConnect/PSMAdminConnect (anonymisé) ?
