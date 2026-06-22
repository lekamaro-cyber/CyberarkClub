# Vérification de comptes CyberArk + résolution du manager AD

Ce dépôt fournit un script PowerShell (`Verify-CyberArkAccounts.ps1`) qui, à partir
d'un CSV listant des couples **compte / serveur**, vérifie pour chacun :

1. **Embarquement** : le compte est-il bien onboardé dans CyberArk ?
   (correspondance `username` ↔ `userName` **et** `host` ↔ `address`)
2. **Safe** : dans quel coffre se trouve le compte ?
3. **Permissions** : liste de **tous les membres/groupes** du safe.
4. **Groupe de domaine externe** : on écarte les groupes par défaut du safe
   (Vault Admins, PVWA*, PSM*, Auditors, etc.) pour ne garder que le groupe AD « métier ».
5. **Manager** : on lit ce groupe dans l'Active Directory et on récupère son
   manager via l'attribut `ManagedBy`.

Le tout est exporté dans un CSV de résultats.

## Pré-requis

- PowerShell 5.1+ (ou PowerShell 7 — supporte alors `-SkipCertificateCheck` nativement).
- Accès réseau au **PVWA** CyberArk et un compte **admin** avec droits API.
- Pour la résolution AD : le module **ActiveDirectory** (RSAT) et un poste joint
  au domaine (ou des droits de lecture sur l'annuaire). Sinon utiliser `-SkipADLookup`.

## Format du CSV d'entrée

Les colonnes minimales attendues sont `host` et `username` (paramétrables via
`-HostColumn` / `-UsernameColumn`). Exemple fourni : `sample-accounts.csv`.

| inventory | host       | username   | home dir         | shell     | ... |
|-----------|------------|------------|------------------|-----------|-----|
| dev       | anthill    | adminunx   | /home/adminunx   | /bin/bash | ... |
| dev       | awx01dev   | root       | /root            | /bin/bash | ... |

## Utilisation

```powershell
# Cas standard (le script demande les identifiants PVWA)
.\Verify-CyberArkAccounts.ps1 `
    -PvwaUrl  https://pvwa.mondomaine.local `
    -CsvPath  .\comptes.csv `
    -OutputPath .\resultats.csv

# Authentification LDAP + certificat auto-signé + identifiants pré-fournis
$cred = Get-Credential
.\Verify-CyberArkAccounts.ps1 `
    -PvwaUrl https://pvwa.corp.local `
    -CsvPath .\comptes.csv `
    -AuthType LDAP `
    -Credential $cred `
    -SkipCertificateCheck

# Test sans interroger l'AD (vérifie uniquement embarquement + safe + groupes)
.\Verify-CyberArkAccounts.ps1 -PvwaUrl https://pvwa.corp.local -CsvPath .\comptes.csv -SkipADLookup
```

## Paramètres clés

| Paramètre              | Rôle                                                                 |
|------------------------|----------------------------------------------------------------------|
| `-PvwaUrl`             | URL du PVWA (obligatoire).                                            |
| `-CsvPath`             | CSV source (obligatoire).                                             |
| `-OutputPath`          | CSV de résultats.                                                     |
| `-AuthType`            | `CyberArk` (défaut) / `LDAP` / `RADIUS`.                             |
| `-AddressMatch`        | `Hostname` (défaut, compare le hostname court), `Exact`, `Contains`. |
| `-DefaultSafeGroups`   | Liste des groupes par défaut à exclure (surchargeable).             |
| `-HostColumn` / `-UsernameColumn` | Noms des colonnes du CSV.                                 |
| `-CsvDelimiter`        | Séparateur du CSV (`,` par défaut ; mettre `;` si Excel FR).          |
| `-SkipADLookup`        | Désactive la partie Active Directory.                               |
| `-SkipIPCheck`         | Désactive le repli par IP (voir ci-dessous).                       |
| `-SkipCertificateCheck`| Ignore la validation TLS du PVWA.                                  |

### Repli (fallback) par IP

Lorsqu'un compte n'est **pas trouvé par son nom d'hôte**, le script résout
automatiquement le `host` en **adresse(s) IP** via DNS, puis relance la recherche
dans CyberArk avec ces IP. Cela couvre le cas fréquent où le compte est embarqué
avec une **adresse IP** plutôt qu'un nom dans CyberArk. Le résultat indique alors
`MatchType = IP (x.x.x.x)` et la colonne `ResolvedIP` liste les IP testées.
Désactivable avec `-SkipIPCheck`.

## Colonnes du CSV de sortie

| Colonne               | Description                                                |
|-----------------------|------------------------------------------------------------|
| `Inventory/Host/Username` | Rappel de la ligne source.                             |
| `Onboarded`           | `Yes` / `No` — compte trouvé dans CyberArk.               |
| `MatchType`           | `Hostname` ou `IP (x.x.x.x)` selon le mode de correspondance. |
| `ResolvedIP`          | IP(s) résolue(s) par DNS lors du repli (ou `non résolu`). |
| `AccountName`         | Nom de l'objet compte CyberArk.                           |
| `AccountAddress`      | Adresse enregistrée dans CyberArk.                       |
| `PlatformId`          | Plateforme du compte.                                     |
| `SafeName`            | Coffre contenant le compte.                              |
| `AllSafeGroups`       | Tous les membres/groupes du safe.                       |
| `ExternalDomainGroup` | Groupe(s) de domaine retenu(s) (hors défaut).           |
| `GroupManager`        | Manager du groupe (AD `ManagedBy`).                     |
| `GroupManagerEmail`   | Email du manager.                                        |
| `Notes`               | Diagnostics (non embarqué, plusieurs groupes, etc.).    |

## Notes & ajustements possibles

- **Correspondance host/address** : si vos `address` CyberArk sont des FQDN
  (`anthill.corp.local`) et le CSV des noms courts (`anthill`), gardez `-AddressMatch Hostname`.
- **Groupes par défaut** : adaptez `-DefaultSafeGroups` à votre nommage interne.
- **Manager** : le script lit `ManagedBy` du groupe. Si chez vous le manager est
  porté autrement (ex. attribut `manager` des membres, ou un OU dédié), signalez-le
  et j'adapte la fonction `Resolve-DomainGroupAndManager`.
