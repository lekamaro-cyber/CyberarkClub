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
- **PSMConnect / PSMAdminConnect** : comptes de domaine **déjà créés**. Définis **par zone** dans `zones.psd1` (`PSMConnectUserName` / `PSMAdminConnectUserName`, format `DOMAINE\user`). Constat (média 12.6.11 + PSM en service) : **aucun `*Config.xml` de stage** ne porte ces comptes — ils vivent à **deux niveaux**, patchés **en place** (sauvegarde `.orig`, rejouable) : (1) **`InstallationAutomation\Consts.ps1`** du média (`Set-Variable PSM_CONNECT / PSM_ADMIN_CONNECT`), consommé par les steps d'automatisation → `Set-PSMAutomationConsts` avant PostInstallation/Hardening ; (2) les **variables** de `PSMHardening.ps1` (`$PSM_CONNECT_USER` / `$PSM_ADMIN_CONNECT_USER`) et `PSMConfigureAppLocker.ps1` (`$PSM_CONNECT` / `$PSM_ADMIN_CONNECT`), **générés à l'installation** sous `<InstallDir>\PSM\Hardening` → `Set-PSMConnectAccounts` au début de la phase Hardening. **Inactif** si les comptes de zone sont vides ; variable introuvable = arrêt avec liste des candidates. Les **mots de passe** ne sont pas en config : **gérés dans le Safe PSM** côté Vault.
- Auth PVWA du compte admin/install : **CyberArk**.
- Nommage des comptes composants : **`PSM-<SERVERNAME>` en MAJUSCULES**.
- Credential files (.cred) **liés à la machine** (CreateCredFile avec restrictions).

## Récupération des secrets — **DÉCISION RÉVISÉE : via l'API PVWA (pas de CCP/AIM)**
- L'**admin qui réalise l'installation s'authentifie lui-même sur le PVWA** (il a accès à
  tous les comptes CyberArk). Le script récupère le mot de passe du **compte d'install/admin
  Vault** à la volée via l'**API REST PVWA** (`Get-PvwaAccountPassword`).
- **Plus de CCP/AIM** : ni AppID, ni certificat applicatif à provisionner.
- Auth PVWA supportée : **CyberArk / LDAP / Windows / RADIUS** (par zone). En lab,
  `SkipCertificateCheck = $true` pour tolérer le certificat auto-signé.
- **[L2/à récupérer]** Safe + nom du compte d'install à récupérer par DC (ou : l'admin
  connecté fait office de compte d'install → `InstallAccount*` laissés vides).
- ~~Un CCP par datacenter derrière VIP + certificat client~~ *(approche abandonnée)*.

## Vault / PVWA / enregistrement
- **Vault central unique** joignable des 2 DC.
- Enregistrement via la **« registration automation » présente dans les sources** + **XML posés à la main**, avec **confirmation manuelle AVANT** exécution.
- **Évolution (config pilotée par la nôtre, média jamais modifié)** : les valeurs qui
  dépendent de notre environnement ne sont plus éditées à la main dans les `*Config.xml`
  du média. Une **mécanique d'injection unique** (`Resolve-PSMStageConfig` →
  `Update-PSMStageXml`) écrit ces valeurs dans une **copie patchée** sous
  `state\config\<Stage>\`, pour **tous les stages** (Readiness → Hardening). Deux sources :
  valeurs **statiques** dans `settings.psd1` (`Install.Injections[<Stage>]`) et valeurs
  **dynamiques** par le code — dont l'**adresse Vault de la zone** (`zones.psd1`) injectée
  pour *Registration*. Résultat : **déposer une nouvelle source CyberArk ne demande aucune
  édition manuelle des XML** ; sans injection déclarée, le XML du média sert tel quel.
- **Idempotence** : on se connecte au **PVWA avec le compte de l'admin** (session ouverte pour la récupération des secrets) pour vérifier si le PSM est **déjà enregistré** avant d'agir.
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
3. **Secrets** : `zones.psd1` = **PVWA par DC** + méthode d'auth + compte d'install (récupéré via API PVWA). *(CCP abandonné.)*
4. **Register** : appeler la **registration automation** des sources avec les **XML**, précédée d'une **confirmation manuelle** ; **idempotence = check via connexion PVWA**.
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
- [ ] Valeurs par DC : URL PVWA, méthode d'auth, Safe + compte d'install à récupérer, FQDN serveur licence RDS
- [ ] Points de reboot exacts dans la procédure
