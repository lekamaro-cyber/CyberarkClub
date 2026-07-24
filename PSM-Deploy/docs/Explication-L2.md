# À montrer au L2 — De quoi parle ce projet (en clair)

## Le problème qu'on veut résoudre
Aujourd'hui tu déploies les PSM **à la main**, étape par étape. C'est long, il y a
plusieurs reboots, et une petite erreur (mauvaise zone, étape oubliée, étape rejouée)
peut coûter cher. On veut **outiller ta procédure**, pas la remplacer par une boîte noire.

## L'idée : un script « idempotent » (comme Ansible)
« Idempotent » veut simplement dire : **on peut le relancer autant de fois qu'on veut,
il ne refait que ce qui manque**. Pour chaque étape, le script fait deux choses :

1. **TEST** : « est-ce que c'est déjà fait / déjà conforme ? »
2. **SET** : si non → il applique. Si oui → il ne touche à rien.

À la fin, il affiche un récap type :
```
Role RD Session Host .............. OK        (déjà là)
Licence RDS ....................... CHANGED   (appliquée)
Installation PSM .................. OK
Enregistrement Vault .............. CHANGED
Hardening ......................... OK
```
`OK` = rien changé, `CHANGED` = appliqué, `FAILED` = échec (et on s'arrête là).

## Comment on garde le contrôle (anti-bêtise)
- **Mode « plan » (`-WhatIf`)** : on lance à blanc, il **dit ce qu'il ferait** sans rien modifier.
- **Confirmation de la zone** : avant d'agir, il affiche le datacenter et le PVWA visés,
  et **demande OUI** — pour éviter de dérouler sur le mauvais DC.
- **Confirmation avant l'enregistrement Vault** (l'étape sensible).
- **Fail-fast** : à la première erreur, il **s'arrête** ; on corrige, on relance, il **reprend où il en était**.

## Ce que le script fait, dans l'ordre (calqué sur ta procédure)
1. **Pré-vol** : vérifie les droits admin, la zone, les accès Vault/PVWA.
2. **Prérequis** : licence RDS locale (le rôle RDS, lui, est posé par l'auto-install CyberArk).
3. **Logiciels additionnels** : installe les clients/outils (piloté par un fichier de config + un dossier d'exe).
4. **Installation PSM** : lance l'installation automatisée CyberArk (ta commande).
5. **Enregistrement Vault** : registration automation + les XML, **après confirmation**.
6. **Hardening** : ton PSMHardening personnalisé + la politique AppLocker maison.
7. **Validation** : vérifie que les services PSM tournent.
8. **Reboots** : gérés automatiquement, avec **reprise automatique** après redémarrage.

## Où viennent les mots de passe (sécurité)
- **L'admin qui réalise l'installation s'authentifie lui-même sur le PVWA** (il a déjà
  accès à tous les comptes CyberArk). Le script récupère alors, **à la volée via l'API REST
  du PVWA**, le mot de passe du compte d'install/admin Vault dont il a besoin —
  **jamais écrit en dur, jamais dans les logs** (masqué automatiquement).
- **Pas de CCP/AIM** : rien à provisionner (ni AppID, ni certificat applicatif). C'est la
  session de l'admin qui autorise la récupération.
- Les mots de passe **PSMConnect/PSMAdminConnect** ne sont **pas** saisis : le service PSM
  les récupère tout seul à l'exécution (via le Safe PSMConnect), comme aujourd'hui.

## Ce qu'on NE change PAS
- La **façon** dont CyberArk installe (on utilise **tes** commandes/scripts CyberArk).
- Le **Load Balancer** (géré en avance de phase, hors script).
- L'**antivirus/EDR** (géré par les admins OS).
- Le **contenu** de ton hardening et de ton AppLocker : on **embarque tes fichiers** et on
  les applique — tu gardes la main.

## Ce dont on a besoin de toi (le L2)
Surtout : **les fichiers réels** et **comment détecter qu'une étape est déjà faite**.
La liste précise est dans `Inspection-PSM-modele.md` (à lancer sur le PSM modèle) et dans
la checklist de fin de `Synthese-reponses.md`.
