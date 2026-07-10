# Faire une démo (sans média ni valeurs réelles)

Tu n'as encore rien mis dans le dossier (pas de média CyberArk, pas de valeurs) :
c'est **normal**, et tu peux quand même démontrer **ce qui a de la valeur** — le
moteur idempotent et les garde-fous — grâce au **mode démo** (`demo/Demo-PSM.ps1`).

> ✅ Aucun prérequis lourd : **pas besoin** de média CyberArk, **ni** de droits
> admin, **ni** de réseau. Juste **Windows PowerShell 5.1** (présent sur tout
> Windows) sur n'importe quelle machine (ton poste, une VM…).

## Ce que la démo prouve
- **Idempotence réelle** : 1er passage = tout `CHANGED`, 2e passage = tout `OK`
  (le moteur relit un état persistant, il ne rejoue rien).
- **Mode « plan » (`-WhatIf`)** : montre ce qui *serait* fait, **sans rien modifier**.
- **Confirmation de zone** : l'anti-bourde avant d'agir.
- **Masquage des secrets** : un mot de passe loggé apparaît `********`.
- **Récapitulatif final** façon Ansible (OK / CHANGED / FAILED).
- **Point de reboot** : là où le vrai script redémarrerait et reprendrait.

## Déroulé conseillé pour le meeting (3 minutes)

Ouvre PowerShell dans le dossier `PSM-Deploy` puis :

### 1) Mode « plan » — on ne touche à rien
```powershell
.\demo\Demo-PSM.ps1 -Reset -NonInteractive -WhatIf
```
➡️ Tout ressort en `WHATIF` : « voici ce que je ferais ». Aucune modification.

### 2) Premier vrai passage — installation simulée
```powershell
.\demo\Demo-PSM.ps1 -Reset -NonInteractive
```
➡️ Tout ressort en `CHANGED`. Note le message de **reboot** simulé.

### 3) Deuxième passage — LA démonstration d'idempotence
```powershell
.\demo\Demo-PSM.ps1 -NonInteractive
```
➡️ Tout ressort en `OK` : **rien n'est refait**. C'est le cœur du sujet.

### 4) (option) Confirmation de zone interactive
```powershell
.\demo\Demo-PSM.ps1 -Reset        # sans -NonInteractive : il demande de taper OUI
```
➡️ Montre le garde-fou « mauvaise zone = mauvais Vault ».

## Montrer aussi les tests automatisés (facultatif)
Si Pester est présent :
```powershell
Invoke-Pester -Path .\tests\Deploy-PSM.Tests.ps1
```
➡️ Vérifie le **contrat d'idempotence** (2e passage = OK) et la structure.

## Le message à passer au L2
> « Le vrai script (`Deploy-PSM.ps1`) marche **exactement pareil** : mêmes phases,
> même récap, même sécurité. La seule différence, c'est qu'au lieu d'étapes
> *simulées*, il lancera **tes** commandes CyberArk et **tes** fichiers. La démo
> montre la **mécanique** ; le meeting sert à récupérer le **contenu réel**
> (commandes, XML, valeurs par DC). »

## Nettoyage
Les artefacts de démo sont dans `demo/.demo-state` et `demo/.demo-logs`
(ignorés par git). Pour repartir de zéro : `-Reset`, ou supprime ces dossiers.
