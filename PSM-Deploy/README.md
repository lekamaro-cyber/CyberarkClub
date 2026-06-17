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
| Zones | 2 datacenters → mapping `zone ⇄ {PVWA, CCP, AppID, Safe, Object, cert?}` |
| Install PSM | Scripts d'**automatisation CyberArk** |
| Comptes composants | **PSMApp/PSMGw auto-créés** via REST PVWA |
| Comptes connexion | **PSMConnect/PSMAdminConnect = comptes de domaine gérés par CPM** — mots de passe récupérés à l'exécution par le service PSM (Safe PSMConnect), **non fournis à l'install** |
| Secrets via CCP | **Uniquement** le compte admin/install Vault |
| CCP | `Get-CcpCredential` gère cert (TLS mutuel) **ou** IP selon la zone |
| Logiciels additionnels | Pilotés par `config/software.psd1` (cmd + détection) |
| AppLocker | **Politique contrôlée embarquée** (`applocker/`), appliquée par le script |
| Hardening | **CyberArk complet** (PSMHardening + AppLocker) |
| Licences RDS | Mode + serveur en config |
| Reboot | **Auto + reprise** (machine à états, tâche planifiée) |
| Connection components PVWA | **Hors périmètre** (binaires seulement côté PSM) |
| Logs | **Local structuré** (transcript + JSONL), secrets masqués |
| Échec | **Fail-fast** + reprise idempotente |

## Arborescence

```
PSM-Deploy/
├─ Deploy-PSM.ps1            # Orchestrateur (phases + machine à états + reboot/reprise)
├─ config/
│  ├─ settings.psd1          # Version PSM, licence RDS, chemins
│  ├─ zones.psd1             # Mapping par datacenter (PVWA/CCP/AppID/Safe/Object/cert)
│  └─ software.psd1          # Logiciels additionnels (cmd silencieuse + détection)
├─ modules/
│  ├─ PSM.Common.psm1        # Idempotence, logs+masquage, état/reprise, confirmations
│  ├─ PSM.Ccp.psm1           # Get-CcpCredential (cert OU ip)
│  ├─ PSM.Prereqs.psm1       # RDS/RDSH, licence RDS, registre
│  ├─ PSM.Install.psm1       # Wrapper scripts d'automatisation CyberArk
│  ├─ PSM.Register.psm1      # REST PVWA : enregistrement PSMApp/PSMGw
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
       → Register(REST PVWA, secret CCP) → Hardening(+AppLocker) → Validation
```
Chaque phase est marquée terminée dans `state/progress.json`. Après reboot, une
tâche planifiée relance le script (`-Resume`) qui **reprend à la phase non terminée**.

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
- CCP : préférer à terme un **endpoint dédié `Require client certificate`** pour les
  zones sensibles (renseigner `ClientCertThumbprint` dans `zones.psd1`).

## À compléter avant déploiement (`TODO` / `STUB`)

- `media/` + `Install.AutomationScript`/`ResponseFile` : brancher les scripts CyberArk.
- `PSM.Register.psm1` : logique REST de création/enregistrement des composants.
- `PSM.Hardening.psm1` : exécution PSMHardening + application AppLocker.
- `applocker/PSMConfigureAppLocker.xml` : politique réelle (+ binaires additionnels).
- `zones.psd1` / `settings.psd1` : valeurs réelles (PVWA, CCP, AppID, Safe, licence RDS).
- Persistance de la zone pour la reprise post-reboot.

## Tests

```powershell
Invoke-Pester -Path .\tests\Deploy-PSM.Tests.ps1
```
Vérifie la structure, le chargement des modules et le **contrat d'idempotence**
(2ᵉ passage d'une étape déjà conforme = `OK`, aucun changement).
