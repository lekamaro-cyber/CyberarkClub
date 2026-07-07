# Synthèse des réponses — Découverte + entretien L2

> Réponses captées lors des rounds interactifs. Sert de base pour compléter le
> script (`PSM-Deploy/`). Les points **[L2/à récupérer]** restent à confirmer ou
> à obtenir (fichiers, valeurs) auprès du L2.

## OS, RDS & domaine
- **Windows Server 2022** pour les nouveaux serveurs.
- **Rôle RD Session Host installé par le script d'automatisation CyberArk** (on ne le duplique pas).
- **Licences RDS réglées en local** sur le PSM (mode + serveur de licence).
- PSM **joint au domaine AVANT** l'installation.

## Installation PSM
- Install via une **commande lancée manuellement avec arguments CLI** (pas de fichier de réponse).
  - **[L2/à récupérer]** commande exacte + arguments CLI.
- **3+ reboots / variable** → machine à états + reprise automatique indispensables.
- **14.0 pas encore testée** → cible 12.6, code paramétré par version.

## Comptes
- **PSMConnect / PSMAdminConnect** : comptes de domaine **déjà créés**, **spécifiés dans les fichiers XML des sources d'install**.
- Auth PVWA du compte admin/install : **CyberArk**.
- Nommage des comptes composants : **`PSM-<SERVERNAME>` en MAJUSCULES**.
- Credential files (.cred) **liés à la machine** (CreateCredFile avec restrictions).

## CCP (secrets)
- **Un CCP par datacenter, derrière une VIP** → `CcpUrl` = VIP par zone.
- Passage prévu à l'**authentification par certificat client** de l'AppID.
  - **[Action utilisateur]** récupérer/créer le certificat, puis renseigner le **thumbprint** par zone.
- **[L2/à récupérer]** AppID / Safe / Object du compte admin par DC.

## Vault / PVWA / enregistrement
- **Vault central unique** joignable des 2 DC.
- Enregistrement via la **« registration automation » présente dans les sources** + **XML posés à la main**, avec **confirmation manuelle AVANT** exécution.
- **Idempotence** : on se connecte au **PVWA avec le compte admin (récupéré via CCP)** pour vérifier si le PSM est **déjà enregistré** avant d'agir.
- **[L2/à récupérer]** contenu/gabarit des XML d'enregistrement + URL PVWA par DC.

## Logiciels additionnels
- Pilotés par **un XML à remplir** + **un dossier source** ; l'équipe y met **les .exe et les lignes de commande**.
  - → j'aligne le mécanisme sur un **fichier XML** (au lieu du `.psd1`).
- **[L2/à récupérer]** liste des applis, versions, .exe, lignes de commande silencieuses, tests de détection.

## Hardening & AppLocker
- **PSMHardening personnalisé** (notamment pour PSMConnect / PSMAdminConnect).
  - **[L2/à récupérer]** version personnalisée du PSMHardening.
- **AppLocker : XML personnalisé maison**.
  - **[L2/à récupérer]** XML AppLocker de référence (à versionner dans `applocker/`).
- Exclusions **AV/EDR** : **déjà gérées par les admins OS** → hors périmètre.

## Load Balancer
- Mise en/hors pool **gérée en avance de phase** → **hors périmètre** du script.

## Validation & exploitation
- Validation post-install : **services PSM démarrés** (pas de test de connexion automatisé).
- **Aucune étape non rejouable** → tout est rejouable (idempotence saine).
- Journalisation : **logs locaux structurés suffisent** (pas de copie centrale).

---

## Impacts sur le squelette (ajustements à appliquer)

1. **Prereqs** : ne plus installer le rôle RDS (fait par CyberArk) ; conserver uniquement la config **licences RDS locales**.
2. **Software** : remplacer `config/software.psd1` par un **`config/software.xml`** (schéma : app = nom + exe relatif + arguments + codes retour + test de détection) + dossier source d'installeurs.
3. **CCP** : `zones.psd1` = **VIP CCP par DC** + **thumbprint** (mode certificat) ; PVWA par DC.
4. **Register** : appeler la **registration automation** des sources avec les **XML**, précédée d'une **confirmation manuelle** ; **idempotence = check via connexion PVWA** (compte admin CCP).
5. **Hardening** : brancher le **PSMHardening personnalisé** + appliquer l'**AppLocker XML maison** versionné.
6. **Nommage** : composants `PSM-<SERVERNAME>` en majuscules.
7. **Validation** : smoke test = **services up** uniquement.
8. **Logs** : local only (déjà en place).

## À rapporter du meeting L2 (fichiers/valeurs)
- [ ] Commande + arguments CLI exacts de l'install PSM
- [ ] XML d'enregistrement (registration automation)
- [ ] XML de spécification PSMConnect/PSMAdminConnect (sources d'install)
- [ ] PSMHardening personnalisé
- [ ] XML AppLocker maison
- [ ] XML logiciels additionnels + .exe + lignes de commande
- [ ] Valeurs par DC : VIP CCP, URL PVWA, AppID, Safe, Object, FQDN serveur licence RDS
- [ ] Points de reboot exacts dans la procédure
