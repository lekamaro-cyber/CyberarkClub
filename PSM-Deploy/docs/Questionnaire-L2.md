# Questionnaire — Rendez-vous L2 « Déploiement manuel d'un PSM CyberArk »

> **But du meeting** : capturer le savoir-faire manuel du L2 (qui déploie ces
> serveurs à la main) afin de fiabiliser/compléter le script de déploiement
> idempotent (`PSM-Deploy/`). Chaque section correspond à une phase du script
> et aux points encore ouverts (`TODO`/`STUB`).
>
> **Mode d'emploi** : on déroule section par section. Pour chaque question,
> noter la réponse + (si utile) la **commande exacte** ou le **fichier** utilisé,
> et signaler les **pièges connus**. Les questions ⭐ sont prioritaires.

---

## 0. Contexte & cadrage général

- [ ] ⭐ Combien de PSM déployés / an, et combien à venir sur ce lot ?
- [ ] ⭐ Quelle est la **procédure manuelle actuelle de bout en bout** ? (existe-t-il un runbook / doc interne ? le récupérer)
- [ ] Durée moyenne d'un déploiement manuel et nombre de reboots typiques ?
- [ ] Quelles sont les **3 erreurs les plus fréquentes** lors d'un déploiement manuel ?
- [ ] Y a-t-il des différences de procédure entre **DC1 et DC2** au-delà du réseau ? (OS, comptes, ordre des étapes…)

## 1. Média, versions & sources

- [ ] ⭐ Emplacement et **structure exacte du média** PSM (12.6) ? (arborescence des dossiers/installeurs)
- [ ] ⭐ Quels **fichiers/scripts CyberArk** sont lancés pour l'install, et dans quel ordre ?
      (ex. `InstallationAutomation.ps1`, `CreateCredFile`, `PSMHardening.ps1`, `PSMConfigureAppLocker.ps1`… — noter les **noms réels**)
- [ ] Existe-t-il un **fichier de réponse** (silent/unattended) ? Lequel, et quels champs faut-il y remplir ?
- [ ] Différences connues **12.6 → 14.0** sur l'install/hardening (chemins, scripts renommés, nouveaux prérequis) ?
- [ ] Le média contient-il déjà les **connection components** ou sont-ils ajoutés à part ?
- [ ] Y a-t-il un **patch / hotfix** à appliquer après l'install de base ?

## 2. Prérequis OS / RDS / licences

- [ ] ⭐ Version(s) de **Windows Server** cible(s) ? (2019 / 2022 …)
- [ ] ⭐ Le **rôle RD Session Host** est-il installé par la procédure, ou pré-provisionné par l'image/GPO ?
- [ ] ⭐ **Licences RDS** : mode (Per-User / Per-Device) + **FQDN du serveur de licence** ? Réglé en local ou par GPO ?
- [ ] Fonctionnalités/prérequis additionnels installés à la main ? (.NET version, redistribuables VC++, etc.)
- [ ] Réglages **registre / services** spécifiques posés manuellement avant ou après l'install ?
- [ ] Le serveur est-il **joint au domaine avant ou après** l'install PSM ? OU déployé hors-domaine puis joint ?
- [ ] Réglages **fuseau horaire / locale / clavier** importants pour les sessions PSM ?

## 3. Comptes

- [ ] ⭐ **PSMConnect / PSMAdminConnect** : noms exacts des comptes de **domaine** ? Dans quelle **OU** ? Convention de nommage ?
- [ ] ⭐ Confirmer : leurs mots de passe ne sont **jamais saisis à l'install** (récupérés à l'exécution via le Safe PSMConnect) ?
- [ ] ⭐ **Compte admin/install Vault** : quel compte, quelle **méthode d'auth PVWA** (CyberArk/LDAP/RADIUS), quels droits exacts ?
- [ ] **Comptes composants PSMApp_/PSMGw_** : convention de nommage (suffixe = hostname ? PSM Server ID ?), dans quel **Safe** ?
- [ ] Les **credential files** locaux (`.cred`) sont-ils générés par `CreateCredFile` ? Où sont-ils stockés ? Liés au hardware/IP ?
- [ ] Droits/local groups à configurer (ex. ajout de PSMConnect aux *Remote Desktop Users*) — manuel ou via script ?

## 4. CCP (récupération des secrets)

- [ ] ⭐ **URL exacte du CCP** par datacenter (DC1 / DC2) ? Un CCP par DC, ou un partagé ?
- [ ] ⭐ Aujourd'hui l'AppID utilisé est-il **avec ou sans certificat** client ? (état réel)
- [ ] ⭐ **AppID / Safe / nom d'objet** du compte admin Vault, par zone ?
- [ ] Si certificat : **thumbprint** + où est installé le cert (LocalMachine\My ?) + autorité ?
- [ ] Restrictions de l'AppID côté CCP (machines autorisées / OS user / path) ?
- [ ] Un endpoint CCP dédié « Require client cert » est-il envisageable côté équipe CCP ? (pour la cible sécurisée)

## 5. Vault / PVWA / enregistrement

- [ ] ⭐ **Adresse(s) du Vault** et **URL PVWA** par datacenter ?
- [ ] ⭐ Étapes **exactes** de l'enregistrement du PSM (côté PVWA et/ou côté serveur) ? Manuel via console ou API ?
- [ ] Comment savoir qu'un PSM est **déjà enregistré** ? (test d'idempotence : quoi interroger ?)
- [ ] **PSM Server ID** : comment est-il déterminé / nommé ?
- [ ] Plateformes / Safes à associer au PSM ? Étape manuelle dans PVWA ?
- [ ] Y a-t-il une étape de **réconciliation** ou de validation côté Vault après install ?

## 6. Load Balancer & haute dispo

- [ ] ⭐ Type de LB et **méthode** (santé/health check sur quel port/URL ?) — pertinent pour la mise en/hors service ?
- [ ] Faut-il **sortir le PSM du pool LB** pendant le déploiement, puis l'y remettre ? Manuel ou automatisable ?
- [ ] Affinité de session / persistance configurée côté LB qui impacte le PSM ?
- [ ] Certificats (PSM Gateway/HTML5 si applicable plus tard) à poser ? (hors périmètre pour l'instant ?)

## 7. Reboots & reprise

- [ ] ⭐ Combien de **reboots** dans la procédure et **à quels moments précis** ?
- [ ] Après reboot, **quelles étapes** sont reprises manuellement ? (valide la machine à états du script)
- [ ] Y a-t-il des **temporisations / attentes de service** nécessaires entre étapes ?

## 8. Logiciels / clients additionnels

- [ ] ⭐ **Liste exhaustive** des binaires installés après le PSM (nom + version) ?
- [ ] ⭐ Pour **chaque** appli : installeur exact + **ligne de commande silencieuse** + **codes de retour** valides ?
- [ ] Comment détecter qu'une appli est **déjà installée** (chemin, clé registre, version) ? (idempotence)
- [ ] Configurations post-install des clients (profils, raccourcis, paramètres par défaut) faites à la main ?
- [ ] Ordre d'installation imposé / dépendances entre logiciels ?

## 9. Hardening & AppLocker

- [ ] ⭐ Le **PSMHardening.ps1** est-il lancé tel quel ou **personnalisé** ? (récupérer la version utilisée)
- [ ] ⭐ La politique **AppLocker** : fichier XML de référence utilisé ? Modifié à la main pour les binaires additionnels ?
- [ ] Comment savoir que le hardening / AppLocker est **déjà appliqué** ? (marqueur d'idempotence)
- [ ] Exclusions / ajustements manuels récurrents (ex. règles AppLocker pour navigateur, SSMS, WinSCP) ?
- [ ] Exclusions **antivirus / EDR** à poser pour le PSM ? (chemins, processus)
- [ ] GPO de domaine qui **complètent ou écrasent** le durcissement local ?

## 10. Enregistrements de session (recordings)

- [ ] Emplacement par défaut et **volume** des enregistrements ? Disque local dédié ?
- [ ] Envoi vers un **Safe** du Vault ou conservation locale ? Politique de rétention/purge ?
- [ ] Réglages à poser à la main aujourd'hui ? (à formaliser plus tard côté script)

## 11. Validation post-installation (smoke tests)

- [ ] ⭐ **Checklist exacte** que le L2 vérifie pour déclarer un PSM « OK » ?
      (services à vérifier, test de connexion via PSM, logs à contrôler…)
- [ ] Quels **services Windows** doivent tourner (noms exacts) ?
- [ ] Test fonctionnel type : se connecter à quoi, via quel connection component, pour valider ?

## 12. Pièges, échecs & rollback

- [ ] ⭐ Cas d'échec déjà rencontrés et **comment ils sont rattrapés** manuellement ?
- [ ] Y a-t-il une étape **non rejouable** (qui casse si relancée) ? → impact direct sur l'idempotence
- [ ] Procédure de **rollback / réinstallation propre** d'un PSM ?
- [ ] Particularités liées aux **flux fermés entre DC1 et DC2** (ce qui n'est joignable que depuis un DC) ?

## 13. Sécurité & traçabilité

- [ ] Sous quel **compte** la procédure est-elle exécutée ? Comment l'élévation est-elle obtenue ?
- [ ] Des secrets transitent-ils aujourd'hui **en clair** quelque part ? (à éliminer)
- [ ] Exigences d'**audit/journalisation** internes (où doivent finir les logs) ?

---

## Synthèse à remplir en fin de meeting

| Point bloquant identifié | Décision / valeur | Responsable | Échéance |
|---|---|---|---|
|  |  |  |  |
|  |  |  |  |

**Éléments à récupérer du L2** (cocher) :
- [ ] Runbook / doc de procédure manuelle
- [ ] Fichier(s) de réponse silencieux PSM
- [ ] `PSMHardening.ps1` utilisé (version réelle)
- [ ] XML AppLocker de référence
- [ ] Liste + lignes de commande des logiciels additionnels
- [ ] Valeurs : PVWA, CCP, AppID, Safe, Object, serveur de licence RDS (par DC)
