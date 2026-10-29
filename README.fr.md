<p align="center">
  <img src="docs/assets/sir_quacksec.png" alt="Sir Quacksec — GeDefense TV" width="200">
</p>

<h1 align="center">GeDefense TV</h1>

<p align="center"><b>Console de sécurité embarquée pour Android TV OS et Google TV.</b><br>
Filtrage VPN loopback local, carte du trafic avec attribution géographique, XDR-Light et un modèle d'état honnête.<br>
Aucun serveur VPN externe. Aucun cloud. Aucune télémétrie.</p>

<p align="center">
  <a href="https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha1/VGT_GeDefense_TV_0.2.0-alpha1_VC2_release-signed.apk"><img src="https://img.shields.io/badge/release-0.2.0--alpha1-E8C46A?style=flat-square" alt="Version 0.2.0-alpha1"></a>
  <img src="https://img.shields.io/badge/status-early%20alpha-E86A5A?style=flat-square" alt="Alpha précoce">
  <img src="https://img.shields.io/badge/platform-Android_TV%20%7C%20Google_TV-5FBFA8?style=flat-square" alt="Android TV / Google TV">
  <img src="https://img.shields.io/badge/Kotlin-1.9.24-7F52FF?style=flat-square&logo=kotlin&logoColor=white" alt="Kotlin 1.9.24">
  <img src="https://img.shields.io/badge/minSdk-26-3DDC84?style=flat-square&logo=android&logoColor=white" alt="minSdk 26">
  <img src="https://img.shields.io/badge/license-VGT%20proprietary-B08D57?style=flat-square" alt="Licence propriétaire VGT">
</p>

[English](README.md) · [Deutsch](README.de.md) · [Русский](README.ru.md) · **Français** · [简体中文](README.zh-CN.md) · [日本語](README.ja.md)

---

> ## ⚠️ ALPHA PRÉCOCE (early alpha) — chaque utilisateur est un testeur alpha
>
> GeDefense TV **0.2.0-alpha1** est une version alpha précoce. Ce n'est pas un produit grand public
> fini ni un produit de sécurité audité, et l'APK publié est signé avec une **clé de test**. Le
> comportement, l'interface et la politique de filtrage changeront entre les versions alpha. Avant de
> vous y fier : lisez la [portée et les limites](#portée-et-limites), les [notes de version](RELEASE-NOTES.md)
> et traitez chaque résultat comme une indication, jamais comme une garantie.

## Téléchargement

[![Télécharger le dernier APK alpha](https://img.shields.io/badge/Download-latest%20APK-E8C46A?style=for-the-badge&logo=android&logoColor=black)](https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha1/VGT_GeDefense_TV_0.2.0-alpha1_VC2_release-signed.apk)

Utilisez toujours la [page de la dernière version](https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha1/VGT_GeDefense_TV_0.2.0-alpha1_VC2_release-signed.apk) :
l'APK exact, ses sommes de contrôle et les notes de build s'y trouvent. L'APK alpha est signé avec une
clé de test — Android peut afficher un avertissement lors de l'installation. Vérifiez la somme SHA-256
par rapport à [SHA256SUMS.txt](SHA256SUMS.txt) ou aux sommes jointes à la version avant d'installer.

## Captures d'écran

Rendus réels de l'interface anglaise, capturés à partir d'un build en cours d'exécution sur
l'émulateur Android TV (1920×1080, Android 16 Google TV / API 36).

| Accueil — posture de sécurité | Protection — VPN loopback local |
| --- | --- |
| ![Écran d'accueil](docs/screenshots/home.png) | ![Tableau de protection](docs/screenshots/protection.png) |

| Réseau — carte du trafic et destinations | Fenêtre de confinement réversible (Kinetic-Lite) |
| --- | --- |
| ![Réseau et carte du trafic](docs/screenshots/network.png) | ![Fenêtre de confinement temporaire](docs/screenshots/containment.png) |

| Premier démarrage avec Sir Quacksec | XDR-Light — incidents corrélés | Superposition de synchronisation des menaces |
| --- | --- | --- |
| ![Étape 1 de l'assistant](docs/screenshots/onboarding.png) | ![Incidents XDR-Light](docs/screenshots/xdr.png) | ![Synchronisation du renseignement sur les menaces](docs/screenshots/ti-sync.png) |

### Six langues d'interface

L'interface suit la langue du système du téléviseur. L'anglais est la langue par défaut ; l'allemand,
le français, le russe, le chinois simplifié et le japonais disposent de jeux de ressources complets.

| English (par défaut) | Deutsch | Français |
| --- | --- | --- |
| ![Accueil anglais](docs/screenshots/home.png) | ![Accueil allemand](docs/screenshots/languages/home-de.png) | ![Accueil français](docs/screenshots/languages/home-fr.png) |

| Русский | 简体中文 | 日本語 |
| --- | --- | --- |
| ![Accueil russe](docs/screenshots/languages/home-ru.png) | ![Accueil chinois](docs/screenshots/languages/home-zh-CN.png) | ![Accueil japonais](docs/screenshots/languages/home-ja.png) |

## Qu'est-ce que GeDefense TV ?

GeDefense TV est une application de sécurité pour Android TV OS et Google TV, conçue pour la
navigation à la télécommande. Elle associe une couche de filtrage locale à une console d'observation
locale : elle montre ce que le téléviseur fait sur le réseau, ce qui a été bloqué, quelles
applications communiquent avec quels pays et quels constats sont réellement vérifiables sur l'appareil.

Règle directrice : **ne rapporter que ce qui est observable sur cet appareil précis.** Les
autorisations manquantes, les API non prises en charge ou la visibilité partielle sont présentées comme
une visibilité partielle — jamais comme la preuve que le téléviseur est sain. Un état de protection
n'est affirmé que lorsqu'un tunnel est réellement actif.

L'application est une **application TV autonome**. Ce n'est pas un routeur, une passerelle pare-feu ou
un capteur réseau, et elle ne s'intègre pas au firmware d'un routeur.

### Pourquoi un VPN loopback purement local ?

GeDefense TV filtre directement sur l'appareil. L'application crée une interface TUN locale, y
achemine son propre trafic et laisse un assistant de plan de données vendu (fourni avec le projet) et
audité évaluer les métadonnées DNS et de connexion. Le trafic filtré quitte ensuite l'appareil
directement vers sa destination.

Ce choix a des conséquences assumées :

- **Aucun serveur externe, aucun compte, aucun abonnement.** Le trafic ne transite pas par un serveur
  VGT ni par un point de terminaison VPN tiers : il n'y a aucun intermédiaire à qui faire confiance.
- **Aucune inspection du contenu.** Seules les métadonnées DNS et de connexion sont évaluées. Le
  contenu TLS/QUIC reste chiffré et intact — ce n'est pas un proxy MITM et il ne peut pas voir dans HTTPS.
- **Preuves locales.** Constats, compteurs et preuves restent sur le téléviseur. Rien n'est téléversé.
- **Échec honnête.** Si le consentement manque, si l'assistant échoue ou si la politique ne peut pas
  être évaluée, l'application signale un état dégradé/en échec au lieu de laisser passer le trafic
  sans filtrage.

## Fonctionnalités

### Protection locale (VPN loopback)

- Service TUN sur l'appareil (`VpnService`, service de premier plan, prise en charge Always-On) avec un
  assistant natif vendu pour `arm64-v8a` et `x86_64`.
- Démarrage / arrêt avec le consentement VPN Android (une seule fois) ; démarrage automatique
  optionnel après le lancement de l'application.
- Profils de filtrage : **Off**, **Conservative**, **Balanced**, **Strict** — chaque profil modifie la
  manière de traiter les destinations connues de télémétrie, d'ACR, de publicité, de traqueurs et de C2.
- Modèle d'état explicite : Off, Preparing, Active, Limited, Failed, Not supported. « Active » n'est
  affiché que lorsque le tunnel local fonctionne réellement.
- Compteurs en direct : flux bloqués, applications observées, flux actifs et volume transféré depuis
  le démarrage.

### Filtrage : DNS, traqueurs, ACR, publicités et C2

- Évaluation locale des requêtes DNS et des destinations de connexion par rapport à l'index de menaces
  vendu, à un catalogue de traqueurs/télémétrie sélectionné et au profil de confidentialité choisi.
- Actions explicables : autoriser, annoter, corréler ou bloquer — avec un motif issu de la politique
  locale, jamais d'un verdict distant.
- Cache de renseignement sur les menaces limité, alimenté par des listes IOC publiques ; les flux
  périmés sont signalés, pas masqués.
- Limite honnête : si une application utilise DNS-over-TLS/HTTPS, ses noms de domaine ne sont pas
  visibles ; l'application le dit au lieu de deviner.

### Carte du trafic avec attribution géographique locale

- Agrégation par application, par pays et par domaine du trafic observé : octets, flux actifs, flux
  bloqués, flux corrélés.
- Carte mondiale avec marqueurs par pays et marqueur d'origine dérivé de la région/du réseau du
  téléviseur — **pas de GPS, pas d'autorisation de localisation**.
- L'attribution IP→pays utilise un jeu de données hors ligne téléchargé une fois avec des sommes
  SHA-256 ; l'attribution par pays est une estimation (CDN, anycast et hébergement partagé peuvent être
  mal attribués).
- Données limitées et respectueuses de la vie privée : aucun contenu, aucun contenu d'écran, aucun
  audio/vidéo, aucun journal par paquet.

### XDR-Light

Corrèle ce qui est localement observable en incidents explicables : flux bloqués répétés par
application, trafic de télémétrie/ACR bloqué, trafic d'application vu pour la première fois,
correspondances d'indicateurs C2 et corridors à haut risque (informatif uniquement). Chaque incident
porte sa règle, sa confiance, sa visibilité et une recommandation. Dédupliqué, limité et explicitement
**pas** un EDR privilégié : pas de flux à l'échelle du système, pas de surveillance des processus,
aucune affirmation sur l'intégrité du firmware.

### V2.1 Outbound Kinetic-Lite

Heuristiques déterministes et bornées sur fenêtres glissantes appliquées au trafic sortant observé :
rafales DNS, éventail de destinations, motifs de beacon, pics de volume, blocages répétés, catégories
de traqueurs, correspondances C2 et corridors à haut risque. Chaque anomalie est un score avec des
signaux nommés — jamais un verdict de « malware ».

**Observation seule par défaut.** Le confinement temporaire est une option explicite, disponible
uniquement avec le profil « Strict ». Lorsqu'il est activé, seuls des préfixes de destination sont
confinés (jamais des applications), avec des garde-fous stricts : au moins deux signaux indépendants,
un score minimal, un pays de destination connu, une courte durée de vie (1–30 minutes, 10 par défaut),
au maximum quatre confinements actifs et des listes d'autorisation pour les plages plateforme, Google
et CDN. Chaque confinement est réversible : une fenêtre TV apparaît, l'utilisateur peut appuyer sur
**Annuler**, et le blocage se lève automatiquement à l'expiration.

### Assistant de premier démarrage avec Sir Quacksec

Un assistant en six étapes, utilisable uniquement à la télécommande : bienvenue, fonctionnement de la
protection locale, consentement VPN, synchronisation du renseignement sur les menaces (optionnelle),
premier contrôle et un récapitulatif qui active la protection complète. Rien n'est simulé : si le
consentement est refusé ou si une étape échoue, l'assistant le dit.

### Superposition de synchronisation du renseignement sur les menaces

Une superposition compatible télécommande affiche la progression de la synchronisation des flux IOC
publics. Une synchronisation périmée ou échouée est signalée honnêtement et peut être relancée plus tard.

### Preuves, rapports et export

- Registre de preuves local avec chaîne de hachage vérifiée par HMAC et charges utiles chiffrées ;
  comportement fail-closed en cas de perte de clé plutôt qu'un redémarrage silencieux de la chaîne.
- Rapport de sécurité local au format texte et JSON.
- Export via le sélecteur de fichiers du système (SAF) ; sur les images TV sans sélecteur de documents,
  l'application utilise un repli sans autorisation vers `Downloads/GeDefenseTV` et indique où les
  fichiers ont été écrits.

### Six langues, entièrement localisées

Anglais (par défaut), allemand, français, russe, chinois simplifié et japonais — jeux de ressources
complets pour chaque chaîne d'interface, vérifiés par l'outil de contrôle des traductions du dépôt.

### Audit de l'appareil et constats

Au-delà du filtrage, GeDefense TV conserve la surface d'audit en lecture seule avec laquelle le produit
a commencé :

- **Posture de l'appareil :** version/API Android, empreinte de build, ABI et classification de l'âge
  du correctif de sécurité — explicitement des métadonnées, pas une garantie d'absence de vulnérabilité.
- **Applications visibles :** version, installateur, empreintes de signature et état NOUVEAU/MODIFIÉ
  par rapport à une référence, avec les limites de visibilité des paquets Android affichées et non masquées.
- **Contrôles de durcissement :** ADB/débogage, options de développement, builds test-keys/userdebug,
  administrateurs d'appareil, services d'accessibilité et installateurs hors magasin — à trois états, les
  valeurs illisibles restant illisibles et n'étant jamais considérées comme « sûres ».
- **Constats et renseignement sur les menaces :** constats explicables avec gravité, confiance et
  visibilité, ainsi que la fraîcheur locale des flux et les correspondances d'indicateurs.

### Modèle d'état honnête

Le modèle d'état est le produit : capacité et visibilité sont des données de premier ordre. Au lieu
d'un badge vert « sécurisé », vous obtenez un score de posture uniquement lorsque la couverture est
suffisante, des libellés explicites de visibilité partielle et une déclaration claire de ce qui n'a pas
pu être observé.

## Fonctionnement

```text
Android TV / Google TV (non rooté)
┌──────────────────────────────────────────────────────────────────────────┐
│ :app  (bac à sable d'application normal, sans AndroidX ni dépendance)     │
│   UI (Views, télécommande)  Protection  Network  XDR  Onboarding  Settings│
│   contrats / services                                                     │
│        │                                                                  │
│   TvVpnService (service de premier plan, TUN local)                       │
│        │  contrôle et télémétrie bornés                                   │
│        ▼                                                                  │
│   Assistant GaiaNet (.so natif vendu, processus enfant, sans root)        │
│        politique DNS/flux  →  sortie directe vers la destination          │
└──────────────────────────────────────────────────────────────────────────┘
     :tv-core — domaine JVM pur : scan, scoring, trafic, XDR, anomalies,
                 politique de confinement, aides géo, rapports, événements
     :core    — cœur GeDefense Mobile vendu, identique octet pour octet
```

## Portée et limites

GeDefense TV n'est volontairement **pas** :

- un service VPN externe ou de déblocage géographique — il n'y a pas de serveur et rien ne quitte
  l'appareil par un tunnel ;
- un antivirus ou un outil de suppression de malware — il observe le comportement réseau et rapporte,
  il ne nettoie pas les applications ;
- un EDR privilégié — pas d'accès noyau, pas de root, pas de surveillance système des processus ou des flux ;
- un remplacement de routeur/passerelle/pare-feu — il fonctionne uniquement sur le téléviseur ;
- un inventaire complet des applications — la visibilité des paquets Android limite ce qu'une
  application peut voir ;
- une garantie de protection — le filtrage ne couvre que le trafic qui passe réellement par le plan de
  données local, et uniquement les politiques qu'il connaît.

Autres limites connues :

- **Qualité alpha :** le matériel TV réel (appareils OEM) n'est pas encore vérifié ; le comportement
  de l'émulateur constitue la base de preuves actuelle.
- **Visibilité DNS :** le trafic DoT/DoH masque les noms de domaine à l'observation locale.
- **L'attribution géographique est approximative :** les CDN, l'anycast et l'hébergement partagé
  peuvent être attribués au mauvais pays.
- **Le confinement est temporaire par conception :** courte durée de vie, maximum quatre blocages
  actifs, facile à annuler — ce n'est pas une règle de pare-feu permanente.
- **APK alpha signé avec une clé de test :** ce n'est pas un build de production ; l'installation
  nécessite d'autoriser les sources inconnues.

## Sécurité et confidentialité

- **Aucune télémétrie, aucune analytique, aucune publicité, aucun SDK de plantage.** L'application ne
  contient aucun SDK d'exécution tiers.
- **Aucune capture de contenu :** pas de capture d'écran, d'audio, de vidéo ou de charge utile ; pas
  d'interception TLS.
- **Traitement local par défaut :** les métadonnées de trafic, les constats et les preuves restent sur
  l'appareil.
- **Autorisations minimales :** `INTERNET`, `ACCESS_NETWORK_STATE`, `FOREGROUND_SERVICE`,
  `FOREGROUND_SERVICE_SPECIAL_USE`, `POST_NOTIFICATIONS` et l'autorisation de service
  `BIND_VPN_SERVICE`. Pas de localisation, d'accessibilité, de superposition, de caméra, de micro ni
  de `QUERY_ALL_PACKAGES`.
- **Seules des données publiques quittent l'appareil :** les flux de renseignement sur les menaces et
  un jeu de données IP→pays sont récupérés via HTTPS ; aucune donnée de l'appareil n'est téléversée.
- **Signalement de sécurité :** voir [SECURITY.md](SECURITY.md). Merci de ne pas publier de détails
  exploitables dans les tickets publics.

Inventaire complet des données : [PRIVACY.md](PRIVACY.md) · [DATA-SAFETY.md](DATA-SAFETY.md).
Conception de sécurité et modèle de menace : [SECURITY.md](SECURITY.md) · [THREAT-MODEL.md](THREAT-MODEL.md).

## Prérequis

| Composant | Exigence |
| --- | --- |
| Appareil | Android TV OS / Google TV, `minSdk 26` (Android 8.0) ou plus récent, `arm64-v8a` ou `x86_64` |
| Interface TV | Lanceur compatible Leanback, télécommande (aucun tactile requis) |
| Build | JDK 17, plateforme Android SDK 36, Build-Tools 36.0.0, Gradle 8.7 (wrapper inclus) |
| Dépendances d'exécution | aucune — pas d'AndroidX, aucune bibliothèque tierce |

## Installation (sideload)

1. Sur le téléviseur, autorisez l'installation depuis des sources inconnues pour l'application utilisée
   pour installer des APK (application de sideload/gestionnaire de fichiers, ou ADB).
2. Installez l'APK depuis la [dernière version](https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha1/VGT_GeDefense_TV_0.2.0-alpha1_VC2_release-signed.apk).
3. Lancez **GeDefense TV**, suivez l'assistant et acceptez la boîte de dialogue de consentement VPN
   Android (une seule fois).
4. Facultatif, via ADB :

```bash
adb connect <tv-ip>:5555
adb install -r VGT_GeDefense_TV_0.2.0-alpha1_VC2_release-debugsigned.apk
adb shell am start -n de.visiongaia.gedefense.tv/.TvMainActivity
```

L'APK alpha est **signé avec une clé de test**. Aucune clé de signature de production ne fait partie
de cette alpha.

## Compiler depuis les sources

```bash
git clone https://github.com/visiongaiatechnology/gedefense_androidtv.git
cd gedefense_androidtv

export JAVA_HOME=/path/to/jdk-17
export ANDROID_HOME=/path/to/android-sdk

./gradlew :app:assembleDebug           # APK de debug
./gradlew :app:assembleRelease         # APK de release minifié R8
```

La signature de release lit `GEDEFENSE_RELEASE_STORE_FILE`, `GEDEFENSE_RELEASE_STORE_PASSWORD`,
`GEDEFENSE_RELEASE_KEY_ALIAS` et `GEDEFENSE_RELEASE_KEY_PASSWORD` depuis l'environnement. Sans elles,
le build revient à la configuration de signature de debug — acceptable pour les tests alpha, pas pour
la distribution. Plus de détails : [BUILD-RUNBOOK.md](BUILD-RUNBOOK.md).

## Tests

```bash
./gradlew :tv-core:tvCoreCheck     # harnais du domaine cœur
./gradlew :tv-core:tvV2Check       # harnais trafic / confidentialité / XDR
./gradlew :tv-core:tvKineticCheck  # harnais anomalies + confinement V2.1
./gradlew :app:lintDebug           # lint Android
```

Le harnais du cœur vendu (`:core:coreCheck`) nécessite une JVM Linux/macOS : son code de fichiers
durables utilise `fsync` de répertoire, non pris en charge sous Windows. Le guide de l'émulateur
Android TV, avec la création d'AVD et la capture d'écran, se trouve dans
[docs/TV-EMULATOR-TESTING.md](docs/TV-EMULATOR-TESTING.md). La matrice d'acceptation est dans
[TEST-PLAN.md](TEST-PLAN.md).

## Structure du projet

```text
.
├── app/                    module d'application Android TV (Views, sans AndroidX)
│   └── src/main/            java/ · res/ (6 langues) · assets/ · jniLibs/ · AndroidManifest.xml
├── core/                   cœur GeDefense Mobile vendu, identique octet pour octet (JVM pure)
├── tv-core/                domaine JVM pur : scan, scoring, trafic, XDR, anomalies, rapports
├── docs/                   architecture, carte du trafic, onboarding, design DNA, guide émulateur,
│                           screenshots/ et assets/
├── tools/                  scripts build/test/émulateur/télécommande/vérification
├── gradle/ + gradlew*      wrapper Gradle 8.7 (SHA-256 de distribution épinglé)
├── build.gradle.kts        AGP 8.5.2 · Kotlin 1.9.24 · Java 17
└── settings.gradle.kts     modules :core, :tv-core, :app
```

## Documentation

| Document | Contenu |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Graphe des modules, flux de données, collecteurs, preuves, budgets de performance |
| [docs/V2-ARCHITECTURE.md](docs/V2-ARCHITECTURE.md) | VPN loopback, télémétrie, agrégation du trafic, chaîne d'approvisionnement de l'assistant natif |
| [docs/TRAFFIC-MAP.md](docs/TRAFFIC-MAP.md) | Sources de la carte du trafic, limites, couleurs et confidentialité |
| [docs/ONBOARDING.md](docs/ONBOARDING.md) | Assistant de premier démarrage, explications du consentement et des autorisations |
| [docs/DESIGN-DNA.md](docs/DESIGN-DNA.md) | Système de design TV, règles de focus/interaction, motifs interdits |
| [SECURITY.md](SECURITY.md) | Conception de sécurité, garde des clés, autorisations, politique de signalement |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Actifs, frontières de confiance, analyse STRIDE, risques propres à la TV |
| [PRIVACY.md](PRIVACY.md) | Inventaire des données, conservation, export, justification des autorisations |
| [TEST-PLAN.md](TEST-PLAN.md) | Matrice d'acceptation et exigences de preuve |
| [BUILD-RUNBOOK.md](BUILD-RUNBOOK.md) | Build, signature, journaux et dépannage |
| [docs/TV-EMULATOR-TESTING.md](docs/TV-EMULATOR-TESTING.md) | Guide pas à pas de l'émulateur Android TV |
| [docs/SOURCES.md](docs/SOURCES.md) | Sources et références |
| [RELEASE-NOTES.md](RELEASE-NOTES.md) | Changements de cette alpha et état de vérification |

## Licence et mentions tierces

GeDefense TV est un **logiciel propriétaire de VisionGaiaTechnology (VGT)**. Ce dépôt est publié à des
fins de transparence, d'examen et de tests alpha. La publication n'accorde aucune licence de
redistribution ni de création d'œuvres dérivées — voir [LICENSE](LICENSE).

Les composants tiers, binaires vendus, assets et sources de données d'exécution (flux publics de
renseignement sur les menaces, jeu de données public IP→pays, bibliothèque standard Go intégrée à
l'assistant natif) sont documentés dans [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Retour alpha

Les retours sont bienvenus via les [tickets GitHub](https://github.com/visiongaiatechnology/gedefense_androidtv/issues).
Merci d'indiquer le modèle de l'appareil, la version d'Android TV OS et la version de l'application
affichée dans les paramètres. Ne publiez pas de secrets, de données personnelles ou de détails de
sécurité exploitables dans les tickets publics — voir [SECURITY.md](SECURITY.md).

---

<p align="center"><i>GeDefense TV est un projet de VisionGaiaTechnology.<br>
« The humor is load-bearing. The code is not a joke. »</i></p>
