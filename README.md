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

- PowerShell 5.1+ (ou PowerShell 7 — gère alors `$SkipCertificateCheck` nativement).
- Accès réseau au **PVWA** CyberArk et un compte **admin** avec droits API.
- Pour la résolution AD : le module **ActiveDirectory** (RSAT) et un poste joint
  au domaine (ou des droits de lecture sur l'annuaire). Sinon mettre `$SkipADLookup = $true`.

## Format du CSV d'entrée

Les colonnes minimales attendues sont `host` et `username` (paramétrables via
`-HostColumn` / `-UsernameColumn`). Si ces noms sont absents, le script
**détecte automatiquement** les variantes courantes : `UserSam`/`Server`
(produites par `extractSudoRootV0.7.ps1`), `userName`/`address`, `NAME_SERVER`, etc.
Le séparateur (`,` ou `;`) est aussi détecté automatiquement. Exemple : `sample-accounts.csv`.

| inventory | host       | username   | home dir         | shell     | ... |
|-----------|------------|------------|------------------|-----------|-----|
| dev       | anthill    | adminunx   | /home/adminunx   | /bin/bash | ... |
| dev       | awx01dev   | root       | /root            | /bin/bash | ... |

### Enchaînement avec `extractSudoRootV0.7.ps1` (CA_Candidate)

Le script `extractSudoRootV0.7.ps1` (branche `claude/review-code-improvements-eZpQ5`)
produit un audit mensuel `Audit_Privileges_Unix_AAAA-MM.csv` (séparateur `;`) qui
contient, pour chaque couple `UserSam`/`Server`, une colonne **`CA_Candidate`**
(`YES` / `YES-SSH` / `NO` / `CHECK-INVENTORY`).

Vous pouvez passer **directement ce fichier** en entrée de `Verify-CyberArkAccounts.ps1`.
Le script lit alors `CA_Candidate` et **qualifie** chaque compte non embarqué :

- `CA_Candidate = YES`/`YES-SSH` mais non embarqué → **ANOMALIE** (devrait être dans CyberArk).
- `CA_Candidate = NO` et non embarqué → **Normal** (pas de privilège / serveur hors ligne).
- `CA_Candidate = CHECK-INVENTORY` → **À vérifier** (statut inventaire inconnu).

Pour ce pipeline, mettez simplement dans la section CONFIGURATION :
`$CsvPath = "$PSScriptRoot\Input\Audit_Privileges_Unix_2026-06.csv"`
(la sortie de `extractSudoRootV0.7.ps1`), puis lancez le script.

## Utilisation

**Aucun argument en ligne de commande.** Tout se règle dans la section
`CONFIGURATION` en haut de `Verify-CyberArkAccounts.ps1`. Il suffit ensuite de
lancer le script (PowerShell ISE / VS Code / clic droit « Exécuter avec PowerShell »).

1. Ouvrez `Verify-CyberArkAccounts.ps1` et éditez le bloc en haut :

```powershell
$PvwaUrl  = 'https://oneconnection.intra.corp'   # URL du PVWA
$AuthType = 'LDAP'                               # CyberArk | LDAP | RADIUS

$PvwaUsername = ''                               # vide = saisie à l'exécution
$PvwaPassword = ''                               # vide = saisie sécurisée (recommandé)

$CsvPath    = "$PSScriptRoot\Input\Audit_Privileges_Unix.csv"
$OutputPath = "$PSScriptRoot\Output\CyberArk-Verification-Results_$(Get-Date -Format 'yyyy-MM').csv"

$UsernameColumn  = 'Auto'          # 'Auto' = détection automatique
$HostColumn      = 'Auto'
$CandidateColumn = 'CA_Candidate'
$CsvDelimiter    = 'Auto'          # 'Auto' détecte , ou ;

$AddressMatch = 'Hostname'         # Hostname | Exact | Contains

$SkipADLookup         = $false
$SkipIPCheck          = $false
$SkipCertificateCheck = $false
```

2. Lancez le script. Si `$PvwaPassword` est laissé vide, une fenêtre demande le
   mot de passe de façon sécurisée.

### Réglages disponibles (section CONFIGURATION)

| Variable               | Rôle                                                                 |
|------------------------|----------------------------------------------------------------------|
| `$PvwaUrl`             | URL du PVWA.                                                          |
| `$AuthType`            | `CyberArk` / `LDAP` / `RADIUS`.                                      |
| `$PvwaUsername` / `$PvwaPassword` | Identifiants (laisser le mot de passe vide = saisie sécurisée). |
| `$CsvPath`             | CSV source (peut être la sortie de `extractSudoRootV0.7.ps1`).       |
| `$OutputPath`          | CSV de résultats (le dossier est créé si besoin).                   |
| `$AddressMatch`        | `Hostname` (défaut), `Exact`, `Contains`.                            |
| `$DefaultSafeGroups`   | Groupes par défaut à exclure.                                        |
| `$UsernameColumn` / `$HostColumn` | Colonnes (`'Auto'` = détection).                         |
| `$CandidateColumn`     | Colonne de candidature CyberArk (`CA_Candidate`).                    |
| `$CsvDelimiter`        | `'Auto'` (détecte `,`/`;`), sinon `','` ou `';'`.                    |
| `$SkipADLookup`        | `$true` = désactive la partie Active Directory.                     |
| `$SkipIPCheck`         | `$true` = désactive le repli par IP (voir ci-dessous).             |
| `$SkipCertificateCheck`| `$true` = ignore la validation TLS du PVWA.                        |

### Repli (fallback) par IP

Lorsqu'un compte n'est **pas trouvé par son nom d'hôte**, le script résout
automatiquement le `host` en **adresse(s) IP** via DNS, puis relance la recherche
dans CyberArk avec ces IP. Cela couvre le cas fréquent où le compte est embarqué
avec une **adresse IP** plutôt qu'un nom dans CyberArk. Le résultat indique alors
`MatchType = IP (x.x.x.x)` et la colonne `ResolvedIP` liste les IP testées.
Désactivable avec `$SkipIPCheck = $true`.

## Colonnes du CSV de sortie

| Colonne               | Description                                                |
|-----------------------|------------------------------------------------------------|
| `Inventory/Host/Username` | Rappel de la ligne source.                             |
| `CA_Candidate`        | Valeur reprise du fichier d'entrée (si présente).         |
| `Onboarded`           | `Yes` / `No` — compte trouvé dans CyberArk.               |
| `OnboardingAssessment`| Verdict croisé : `OK - embarqué`, `ANOMALIE - candidat non embarqué`, `Normal - non candidat`, `À vérifier`, etc. |
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
  (`anthill.corp.local`) et le CSV des noms courts (`anthill`), gardez `$AddressMatch = 'Hostname'`.
- **Groupes par défaut** : adaptez `$DefaultSafeGroups` à votre nommage interne.
- **Manager** : le script lit `ManagedBy` du groupe. Si chez vous le manager est
  porté autrement (ex. attribut `manager` des membres, ou un OU dédié), signalez-le
  et j'adapte la fonction `Resolve-DomainGroupAndManager`.
