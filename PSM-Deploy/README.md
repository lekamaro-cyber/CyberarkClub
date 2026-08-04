# PSM-Deploy — Déploiement idempotent d'un PSM CyberArk (PowerShell)

> ⚠️ **État : squelette / phase de conception.** Le code définit la structure,
> l'idempotence et le flux. Les blocs marqués `TODO (deploiement)` / `STUB`
> doivent être complétés avec le média CyberArk et les valeurs réelles avant
> tout usage en production. **Aucune valeur sensible n'est versionnée.**

## Objectif

Déployer un **Privileged Session Manager (PSM)** CyberArk de façon **idempotente**
(façon Ansible : chaque étape `Test → Set`, restitution `OK / CHANGED / FAILED`),
exécuté **localement** sur chaque serveur PSM à partir d'un **dossier « sources »
auto-portant** que l'on copie sur la machine puis que l'on lance avec des droits
administrateur.

## Décisions d'architecture (validées)

| Sujet | Décision |
|---|---|
| Langage | PowerShell, idempotent, `-WhatIf` (dry-run) + `-Confirm` |
| Versions | PSM **12.6** cible, compatible **14.0** (paramétré par version) |
| Exécution | **Locale** sur chaque PSM, droits admin. Pas de WinRM. |
| Livraison | Dossier **auto-portant** copié sur la cible |
| Topologie | PSM **in-domain**, **derrière Load Balancer**, **2 datacenters à flux fermés** |
| Vault | **Central unique** joignable des 2 DC |
| Zones | 2 datacenters → mapping `zone ⇄ {PVWA, AuthMethod, compte d'install}` |
| Install PSM | Scripts d'**automatisation CyberArk** |
| Comptes composants | **PSMApp/PSMGw** enregistrés via la registration automation du média |
| Comptes connexion | **PSMConnect/PSMAdminConnect = comptes de domaine gérés par CPM** — mots de passe récupérés à l'exécution par le service PSM (Safe PSMConnect), **non fournis à l'install** |
| Récupération des secrets | **Via l'API REST PVWA** (pas de CCP/AIM) — l'admin qui installe s'authentifie au PVWA et le script récupère le compte d'install Vault |
| Auth PVWA | `Connect-PvwaSession` : CyberArk / LDAP / Windows / RADIUS ; `SkipCertificateCheck` en lab |
| Logiciels additionnels | Pilotés par `config/software.psd1` (cmd + détection) |
| AppLocker | **Politique contrôlée embarquée** (`applocker/`), appliquée par le script |
| Hardening | **CyberArk complet** (PSMHardening + AppLocker) |
| Licences RDS | Mode + serveur en config |
| Reboot | **Reprise supervisée** : tâche `AtLogOn` de l'admin → reprend dans sa session à la reconnexion (machine à états) |
| Connection components PVWA | **Hors périmètre** (binaires seulement côté PSM) |
| Logs | **Local structuré** (transcript + JSONL), secrets masqués |
| Échec | **Fail-fast** + reprise idempotente |

## Arborescence

```
PSM-Deploy/
├─ Deploy-PSM.ps1            # Orchestrateur (phases + machine à états + reboot/reprise)
├─ config/
│  ├─ settings.psd1          # Version PSM, licence RDS, chemins
│  ├─ zones.psd1             # Mapping par datacenter (PVWA/AuthMethod/compte d'install)
│  └─ software.psd1          # Logiciels additionnels (cmd silencieuse + détection)
├─ modules/
│  ├─ PSM.Common.psm1        # Idempotence, logs+masquage, état/reprise, confirmations
│  ├─ PSM.Pvwa.psm1          # API REST PVWA : logon + Get-PvwaAccountPassword (secrets)
│  ├─ PSM.Stages.psm1        # Pilotage "étape par étape" de CyberArk (Execute-Stage.ps1)
│  ├─ PSM.Prereqs.psm1       # RDS/RDSH, licence RDS, registre
│  ├─ PSM.Install.psm1       # Stages CyberArk Installation + PostInstallation
│  ├─ PSM.Register.psm1      # Stage CyberArk Registration (secret Vault via -spwdObj)
│  ├─ PSM.Hardening.psm1     # PSMHardening + politique AppLocker contrôlée
│  └─ PSM.Software.psm1      # Install générique config-driven
├─ applocker/PSMConfigureAppLocker.xml   # Politique AppLocker contrôlée (placeholder)
├─ media/                    # (vide) média PSM 12.6/14.0 — non versionné
├─ installers/               # (vide) binaires additionnels — non versionné
├─ state/                    # progression (reprise post-reboot) — non versionné
├─ logs/                     # transcript + JSONL — non versionné
└─ tests/Deploy-PSM.Tests.ps1
```

## Flux des phases

```
PreVol → Prereqs(RDS) → [reboot+reprise] → Software → InstallPSM
       → Register(session PVWA + secret via API PVWA) → Hardening(+AppLocker) → Validation
```
Chaque phase est marquée terminée dans `state/progress.json`. Quand un reboot est
requis, une **tâche planifiée `AtLogOn`** est créée pour l'**admin installateur** :
dès qu'il **se reconnecte après le redémarrage**, le script **reprend tout seul dans
sa session** (`-Resume`, zone relue depuis l'état) à la première phase non terminée.
La reprise est **interactive** (les prompts `Get-Credential` PVWA fonctionnent) et
**aucun secret n'est stocké** sur disque. La tâche est supprimée en fin de déploiement.

## Utilisation

```powershell
# 1) Copier le dossier PSM-Deploy sur le serveur PSM, déposer le média dans media\
#    et les installeurs dans installers\.

# 2) Mode "plan" (dry-run) — ne modifie rien :
.\Deploy-PSM.ps1 -Zone DC1 -WhatIf

# 3) Déploiement réel (confirmations interactives, dont la zone) :
.\Deploy-PSM.ps1 -Zone DC1

# 4) Reprise (normalement automatique via la tâche planifiée après reboot) :
.\Deploy-PSM.ps1 -Zone DC1 -Resume
```

> 🔒 **Confirmation de zone obligatoire** avant action (sauf `-NonInteractive`) :
> une mauvaise zone = mauvais Vault/PVWA/compte. Anti-bourde voulu.

## Sécurité

- Secrets en `SecureString`, **masqués** dans tous les logs ; aucun secret versionné.
- `#Requires -RunAsAdministrator` + contrôle d'élévation au démarrage.
- Récupération des secrets **via l'API REST PVWA** avec la session de l'admin qui installe
  (pas de CCP/AIM à provisionner). Le jeton de session est fermé (`Logoff`) en fin de phase.
- `SkipCertificateCheck` réservé au **lab** ; en production, laisser la validation TLS active.

## À compléter avant déploiement (`TODO` / `STUB`)

- `media/` + `Install.AutomationScript`/`ResponseFile` : brancher les scripts CyberArk.
- `PSM.Register.psm1` : brancher la registration automation du média + détection d'idempotence.
- `PSM.Hardening.psm1` : exécution PSMHardening + application AppLocker.
- `applocker/PSMConfigureAppLocker.xml` : politique réelle (+ binaires additionnels).
- `zones.psd1` / `settings.psd1` : valeurs réelles (PVWA, méthode d'auth, compte d'install, licence RDS).
- Persistance de la zone pour la reprise post-reboot.

## Tests

```powershell
Invoke-Pester -Path .\tests\Deploy-PSM.Tests.ps1
```
Vérifie la structure, le chargement des modules et le **contrat d'idempotence**
(2ᵉ passage d'une étape déjà conforme = `OK`, aucun changement).
