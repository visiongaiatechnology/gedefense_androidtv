# Changelog — GeDefense TV

Alle relevanten Änderungen an diesem Projekt. Format orientiert an *Keep a Changelog*;
Versionierung folgt dem VGT-Produktschema. Es werden nur tatsächlich vorhandene Änderungen
dokumentiert; Build-/Teststatus wird getrennt ausgewiesen.

## [0.3.1-alpha1] — Shizuku Level-2 Bridge & Non-Root TV Hardening Guards, 22.11.2026

**Version:** `0.3.1-alpha1`, VersionCode **5** (`VERSION`, `VERSION_CODE`, `app/build.gradle.kts`).
**Status:** `:tv-core:tvCoreCheck` PASS 591/0 (36/36), `:tv-core:tvV2Check` PASS 4584/0 (29/29), `:tv-core:tvKineticCheck` PASS 3259/0 (24/24), `:tv-core:tvTitanCheck` PASS 6693/0 (17/17), `:app:lintDebug` 0 Errors / 305 Warnings, `:app:assembleDebug` & signiertes `:app:assembleRelease` Exit 0, Source-Fidelity-Check PASS (26 Dateien in `core/` byte-identisch), 7-Locale-Übersetzungscheck PASS (904 Keys / 9 Plurals). **Offen:** Live-Shizuku-IPC und neue Hardening-/Anomaly-Collectors auf physischer Android-TV-Hardware sind **NOT_TESTED**.

### Hinzugefügt — Level-2 Shizuku Bridge (Zero-Dependency)

- **Native AIDL/Binder-IPC ohne Drittabhängigkeiten (`android.useAndroidX=false`):**
  Offizielle Shizuku-AIDL-Schnittstellen (`IShizukuService`, `IShizukuApplication`,
  `IShizukuServiceConnection`, `IRemoteProcess`), eigene Bridge `ITitanShizukuBridge.aidl` mit
  expliziten Methoden-IDs (`= 1`, `= 2`, `= 16777114`), `moe.shizuku.api.BinderContainer`
  (reines Android-`Parcelable`) sowie Manifest-Absicherung über
  `moe.shizuku.manager.permission.API_V23` und `TitanShizukuProvider`
  (`android.permission.INTERACT_ACROSS_USERS_FULL`).
- **Isolierter UserService & Fail-Closed Client:**
  `TitanShizukuUserService` (Allowlist strikt auf `pm`, `am`, `cmd`, `getprop`, `id`, `cat`, `ls`,
  `SAFE_ARG_PATTERN`, Caller-UID-Prüfung, Hard-Timeout & Output-Cap) und `TitanShizukuClient`
  (Attach-Handshake v13, Consent-Flow, `UserService` mit `newProcess`-Fallback, sofortige
  `DeathRecipient`-Degradation auf Level 1 `STANDARD`).
- **Saubere Level-2/Level-3-Trennung (`allowsShizuku`):**
  `TitanShellCommand` und `TitanCommandFactory` trennen Level-2-Kommandos (`APP_FREEZE` mit
  `freezeApp`/`restoreApp`/`forceStopApp`/`listDisabledPackages`, `SOCKET_PROVENANCE` inklusive
  `cmd package list packages -U` gegen `<queries>`-Grenzen) strikt von Root-only-Aktionen
  (`isolateUid`, `killProcess`, `closeAdbTcp`, Vault). Cold-Start setzt `level`,
  `rootShellConfirmed` und `shizukuBridgeAvailable` fail-closed zurück.

### Hinzugefügt & Gehärtet — Non-Root TV Guards & BadBox/Proxy-Relay-Erkennung

- **App-Inventar & Store-Korrektur:** `AppInventoryCollector` extrahiert `FLAG_DEBUGGABLE`
  (`isDebuggable`), und `Inventory.kt` korrigiert `installerIsKnownStore` über
  `hasUnknownInstaller` (Sideloaded Non-System-Apps mit `installerPackage == null`).
- **TV-Hardening (14 Checks):** `Hardening.kt`, `DefaultHardeningRules.kt` und
  `HardeningCollector` prüfen SELinux (`getenforce`), ADB-over-TCP (`service.adb.tcp.port` +
  Loopback-5555-Probe), Wireless-ADB (`adb_wifi_enabled`), unauthentifiziertes ADB
  (`ro.adb.secure == 0`), aktiven HTTP-Proxy / fehlendes Private DNS auf Nicht-VPN-Links sowie
  sichtbare Sideload- und Debuggable-Apps inklusive Darstellung in `HardeningScreen` & `AppsScreen`.
- **BadBox / Residential-Proxy-Heuristiken (`PolicyAction.OBSERVE`):**
  `OutboundAnomalyEngine` erkennt `DIRECT_IP_BYPASS` (rohe öffentliche IPs ohne DNS über mehrere
  Präfixe ab `4 KiB`) und `PROXY_RELAY_PATTERN` (mehrpräfixiges bidirektionales/raw-dominantes
  Relay ab `16 KiB`); `TvXdrEngine` ergänzt korrelierte Regeln inkl. Sideload-Gewichtung (`+10`).
- **Lokalisierung:** Vollständig nachgezogen über alle 7 Sprachordner (`values`, `values-de`,
  `values-en`, `values-fr`, `values-ja`, `values-ru`, `values-zh-rCN`) und `DeCatalog`.

---

## [0.3.0-alpha1] — Titan Engine (V3), 31.10.2026

**Version:** `0.3.0-alpha1`, VersionCode **4** (`VERSION`, `VERSION_CODE`, `app/build.gradle.kts`).
**Status:** Code integriert und verifiziert: **`:tvTitanCheck` PASS 6624/0 (17 Tests)**,
**`:app:lintDebug` 0 Errors / 305 Warnings**, **`:app:assembleDebug`/`assembleRelease` Exit 0**
(Release mit Alpha-Zertifikat, nicht Debug-Key), **Level-1-Emulatorlauf PASS**, **Witness-Runtime
PASS (lokal)**. **Offen:** Level 3 (Root) ist **NOT_TESTED** (nur JVM-verifiziert), Shizuku-Ausführung
und Mobile-Push sind **nicht ausgeliefert**, Produktions-/Upload-Signatur und reale TV-Hardware
offen. Details unten und in [TEST-PLAN.md](TEST-PLAN.md) §9.4. Dieses Release erhebt **keinen**
Produktionsanspruch.

### Hinzugefügt — Titan Engine

- **Drei-Stufen-Privilegmodell** (`:tv-core`, `core.titan.model`): `STANDARD` (Level 1),
  `SHIZUKU` (Level 2, detection-only), `ROOT` (Level 3, nur mit vom Nutzer bestätigtem `su`-Kanal).
  Ein Level über `STANDARD` ist konstruktiv nur mit bestätigtem Kommandokanal möglich
  (`TitanPrivilegeSnapshot`-Invarianten); ein gefundenes `su`-File schaltet **keine** Fähigkeit frei.
- **Dirty-Root-Audit:** `TitanRootKind` (`NONE`/`MANAGED`/`DIRTY`/`UNKNOWN`), `su`-Pfad- und
  Root-Manager-Erkennung, SELinux-/test-keys-/ADB-TCP-Fakten (`TitanBuildIntegrity`) — Dirty Root ist
  ein Befund, keine Freigabe.
- **Capability-Matrix** (`TitanCapabilityMatrix`): Trennung von *theoretischen* und *effektiven*
  Fähigkeiten; UI/Report/Evidenz konsumieren ausschließlich die effektive Menge. Effektive
  Sichtbarkeit `FULL` nur bei bestätigtem Root-Kanal, sonst `PARTIAL`. 7 Capability-IDs
  (`socket-provenance`, `deep-inventory-fim`, `app-freeze`, `network-quarantine`, `adb-lockdown`,
  `process-kill`, `quarantine-vault`).
- **Socket-Provenance** (`:tv-core` Modell; Collector in `:app/platform/titan/collect`):
  `/proc/net/{tcp,tcp6,udp,udp6}`-Parser, Inode→PID→UID→Paket-Zuordnung, Threat-Feed-Abgleich,
  Risiken `THREAT_FEED_MATCH`/`UNATTRIBUTED`/`ADB_EXPOSED`; harte Caps (4096 Sockets,
  4096 Prozesseinträge, 512 Beobachtungen), `truncated`-Signal.
- **FIM / Anti-Planting** (`:tv-core` Modell; Walker in `:app/platform/titan/collect`): feste
  Watch-Policy (`/data/local/tmp`, `/system/bin`, `/system/xbin`, `/vendor/bin`, `/system/etc/init`,
  `/data/adb/modules`), SHA-256-Baseline mit Delta (`NEW_FILE`/`MODIFIED`/`UNREADABLE`), Caps
  (512/Root, 2048 gesamt, 64 MiB Hash); unlesbare Einträge bleiben unlesbar (kein „clean“).
- **Containment (Active Response)** (`:tv-core/titan/response` + `:app` Root-Executor):
  allow-listete, reversible Kommandos (`FREEZE_APP`/`RESTORE_APP`, UID-Quarantäne/-Freigabe,
  `KILL_PROCESS`, `CLOSE_ADB_PORT`, Vault-Move + `chmod 000`); Argument-Whitelist, feste
  Programm-Liste (kein freies `exec`), Fail-Safe-Policy mit geschützten System-/Launcher-/IME-Paketen,
  UID ≥ 10 000, PID ≠ 1/Selbst, max. 16 aktive Containments, 8 Aktionen/60 s. **Kein Lösch-
  /Format-/Partitionskommando im Code.**
- **Status-Composer & Contract:** `TitanStatusComposer` (pur, deterministisch, Notes/Attention),
  `TitanApi` (`status`, `scanNow`, `refreshPrivilege`, `activate`, `contain`, `vaultEntries`,
  `witnessStatus`, `refreshWitnessCheckpoint`) mit Threading-/Honesty-Vertrag; `TitanController`
  (`data/titan/`, ein begrenzter Worker-Thread), `TvTitanStore` (Persistenz) und neuer Screen
  **TITAN LIVE** (`TvRoute.TITAN`, D-Pad-Containment, Zwei-Schritt-Bestätigung) plus kompakter
  Titan-Status im Home-Screen; Socket-/FIM-Guards in den Einstellungen (Default an); Titan-Texte in
  **7 Locales** (Übersetzungsqualität **NOT_TESTED**). **Keine neuen Android-Berechtigungen** (nur
  passive Detektion + nutzerbestätigter `su`-Kanal).
- **Evidenz-Ereignisse** (`TitanEventFactory`): `titan-root-audit`, `titan-c2-socket`,
  `titan-unattributed-socket`, `titan-adb-exposed`, `titan-fim-delta`, `titan-containment`,
  `titan-witness-checkpoint` — secret-frei, bounded, in die bestehende HMAC-Evidenzkette.
- **Witness-Checkpoints:** lokale, HMAC-authentifizierte `TitanWitnessCheckpoint`s der Evidenzkette
  mit ehrlichem Status (`UNAVAILABLE`/`READY`; `PAIRED` ohne Gegenpart wird nicht behauptet).
- **Dokumentation:** neu [docs/TITAN-TV-ARCHITECTURE.md](docs/TITAN-TV-ARCHITECTURE.md) und
  [docs/TITAN-TV-CONCEPT.md](docs/TITAN-TV-CONCEPT.md); Titan-Abschnitte in
  [ARCHITECTURE.md](ARCHITECTURE.md), [THREAT-MODEL.md](THREAT-MODEL.md), [SECURITY.md](SECURITY.md),
  [TEST-PLAN.md](TEST-PLAN.md), [PRIVACY.md](PRIVACY.md), [DATA-SAFETY.md](DATA-SAFETY.md),
  [README.md](README.md).

### Ehrliche Grenzen dieses Alphas (nicht implementiert / nicht behauptet)

- **Level 2 (Shizuku) ist detection-only:** Es wird **keine** Shizuku-Binder-Kommando-Bridge
  ausgeliefert; ohne bestätigten Kanal bleiben die Shizuku-Capabilities effektiv leer.
- **Kein Mobile-Pairing/Push:** Witness-Checkpoints bleiben lokal; QR-Pairing, LAN-Transport und
  Push-Eskalation auf ein Smartphone sind **nicht** Teil von 0.3.0-alpha1.
- **Root nur über nutzerbestätigten `su`-Shell-Kanal** mit allow-listeten, reversiblen Kommandos;
  kein Root-Exploit, keine automatische Eskalation, kein Hintergrund-`su`-Prompt.
- **Nicht-Root-Geräte bleiben Level 1:** Titan-Capabilities melden „nicht verfügbar“, ohne Crash
  und ohne „geschützt“-Behauptung.
- **Sichtbarkeitsgrenzen:** Socket-Attribution und FIM reichen nur so weit, wie der Prozess auf der
  jeweiligen Stufe tatsächlich lesen darf; nicht Zuordenbares wird als `UNATTRIBUTED`/`UNREADABLE`
  ausgewiesen. **Gesamt-Sichtbarkeit = schwächstes Modul** (ein `PARTIAL`-Modul kann einen
  `FULL`-Gesamteindruck nicht erzeugen).
- **Vault:** Binärdaten werden verschoben und `chmod 000` gesetzt; eine Verschlüsselung der
  Vault-Binärdaten ist **nicht** implementiert (nur lokale Metadaten-/MAC-Kette). Der Vault hat in
  dieser Alpha **keinen UI-Aufrufer** (kein Quarantäne-Knopf im Screen), die Capability kann daher
  angezeigt werden, ohne dass eine Verschiebe-Aktion angeboten wird.
- **`CLOSE_ADB_PORT` ist die einzige nicht-reversible Aktion** und im UI nicht exponiert.
- **Shizuku-Ausführung ist nicht ausgeliefert** (Level 2 = Erkennung), **Mobile-Witness-Push ist
  nicht ausgeliefert** (nur lokale HMAC-Checkpoints).
- **Laufzeitgrenzen:** Level 3 (Root-Kanal) ist auf dem Emulator nicht prüfbar (kein `su` im Image;
  produktives Google-TV-Image erlaubt kein `adb root`) — der Kommandopfad ist nur
  JVM-Harness-verifiziert. Witness-Lauf ist **PASS** (lokale Checkpoints; Mobile-Pairing/Push bleibt
  nicht ausgeliefert).

### Verifiziert (Lead-Lauf 31.10.2026, reale Ausgaben)

- **`:tv-core:tvTitanCheck`** → **PASS 6624 / FAIL 0**, **17/17 Tests**, `BUILD SUCCESSFUL`,
  Exitcode **0**.
- **Regression in einem Lauf** (Exitcode 0): `tvCoreCheck` **554/0** (35 Tests), `tvV2Check`
  **4398/0** (28), `tvKineticCheck` **3025/0** (23), `tvTitanCheck` **6624/0** (17).
- **`:app:compileDebugKotlin`** → `BUILD SUCCESSFUL`, Exitcode **0** (nur Deprecation-Warnungen).
- **`:app:lintDebug`** → `BUILD SUCCESSFUL`, Exitcode **0**, **0 Errors / 305 Warnings**
  (`dist/lint-results-debug.txt`; Anstieg gegenüber 169 durch Titan-/V3-Ressourcen und -Tests,
  keine Errors).
- **`:app:assembleDebug`** → `BUILD SUCCESSFUL`, Exitcode **0**; Debug-APK **8.811.121 B**,
  SHA-256 `2fb107bb473bff4c6bcdbe8ed97605d057bd7e18b404bf80561331a25087b2d4`.
- **`:app:assembleRelease`** → `BUILD SUCCESSFUL`, Exitcode **0**; `app-release.apk`
  **6.522.110 B**, SHA-256
  `da4110eb18ed9376b2c16ad70065c9f39a1f7592865b612a469e969b0f3f2934`, signiert mit
  **CN=VisionGaiaTechnology GeDefense TV Alpha, OU=Android TV, O=VisionGaiaTechnology** — **nicht**
  mit dem Debug-Key (Produktions-/Upload-Zertifikat bleibt ein eigener offener Punkt); auf dem
  Emulator installiert und gestartet (Onboarding erster Screen, kein Crash). Staged in `dist/`
  (`VGT_GeDefense_TV_0.3.0-alpha1_VC4_debug.apk`, `…_VC4_release-signed.apk`, `SHA256SUMS`
  ergänzt).
- **Witness (Runtime, Emulator) = PASS:** Nach dem Fix der „gepunkteten Ledger-Typen“ erzeugte ein
  Titan-Scan `witness.state=READY`, `checkpoints=1`, `witness.prefix=82b6992b31d31034`,
  `sequence=1`; das Ledger verzeichnete ein neues `witness-checkpoint`-Event (gesund, 9 Records).
  UI zeigt „Checkpoints: 1 · Last checkpoint: just now“ plus den ehrlichen „nicht gekoppelt“-Hinweis.
  **Mobile-Pairing/Push bleibt nicht ausgeliefert.**
- **Emulator final** (Android 16 Google TV, API 36, AVD `gedefense_tv`, 1920×1080, 320 dpi):
  Debug-APK nach Hardening neu installiert; **TITAN LIVE Level 1**, 7× „Unavailable“, **kein
  Aktivierungs-Button** (kein `su`/Shizuku-Marker), passiver Scan `titan scan ms=754
  level=STANDARD caps=0`, Status persistiert, **kein AndroidRuntime-Crash**; Erststart-Onboarding
  per D-Pad abgeschlossen; D-Pad-Navigation: LEFT → Rail, DOWN×7 → „Titan Live“ (fokussierte
  content-desc „Privilege level, socket radar and quarantine“), OK → Titan-Screen; **Home-Titan-
  Strip** sichtbar („Titan · Level 1 · Standard“, „Open Titan“).
- **Übersetzungen:** `tools/check_translations.py --include-plurals` → **PASS** (0 Probleme,
  **6 Locales**, je **890 String-Keys**, je **9 Plural-Gruppen**).
- **Multi-Resolution (ehrlich):** Emulator-Framebuffer blieb 1920×1080; verifiziert sind
  1080p-Framebuffer plus **2K-/4K-äquivalente Density (426/640)**. Ein echtes 2K-/4K-Framebuffer-
  Rendering ist in dieser Session **NOT_TESTED**.
- Screenshots `titan-13-final-scan.png`, `titan-14-onboarding.png`, `titan-15-after-onboarding.png`,
  `titan-02-passive-scan.png`, `titan-03-sections.png`, `titan-04-home.png`,
  `titan-05-evidence.png` in `_inbox/screenshots` (Lead-Arbeitsverzeichnis, gitignoriert).
- **Unabhängiges Read-only-Security-Audit (31.10.2026):** **kein kritischer Befund und kein
  Shell-Injection-Blocker**; der privilegierte Kanal ist durch Allowlist + Argument-Charset
  eingegrenzt. Verbleibende Alpha-Befunde siehe [SECURITY.md](SECURITY.md) §17 (TF-01…TF-12) und
  [THREAT-MODEL.md](THREAT-MODEL.md) §23.

**Noch offen (nicht behauptet):** Level-3-Lauf auf realem Root-Gerät (Kommandopfad nur
JVM-verifiziert), Produktions-/Upload-Signatur (Alpha-Zertifikat), reale TV-Hardware, echtes
2K-/4K-Framebuffer-Rendering, unabhängige Vollprüfung der Titan-Laufzeitpfade, Quarantäne-UI
(read-only Vault).

## [Unreleased — V2]

### In Arbeit (V2, NOT_TESTED)

- **On-Device-Loopback-VPN:** `VpnService`/TUN + vendorter GaiaNet-Helper (kein externer Server),
  Consent, Start/Stop, Auto-Start, Always-On, Fail-Closed/Recovery; FGS-Typ `specialUse`.
- **Traffic-Metadaten:** `TrafficSnapshot`/`TrafficFlow`/`AppTraffic`/`CountryTraffic`/
  `DomainTraffic` in `:tv-core`; `VpnControlApi`/`TrafficApi` in `:app`; Traffic-Map-Grundlage.
- **XDR-Light:** `TvXdrEngine` in `:tv-core` angelegt; Regeln/Korrelation/Dedupe vorhanden,
  Verhalten **NOT_TESTED**.
- **Onboarding/UI:** `OnboardingScreen`, `ProtectionScreen`, `TrafficScreen` (+
  `TrafficWorldMapView`), `XdrScreen` angelegt; Sir-Quacksec-/TI-Sync-Overlay-Hooks in
  `ScreenHost`; Laufzeit **NOT_TESTED**.
- **Neue Berechtigungen:** `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE`,
  `POST_NOTIFICATIONS`; Service-Permission `BIND_VPN_SERVICE`; keine Standort-/Accessibility-/
  Overlay-/`QUERY_ALL_PACKAGES`-Rechte.
- **Native Helper:** `libgedefense_gaianet_v2.so` byte-identisch aus Mobile 0.28.0-beta1
  (`arm64-v8a` **3.588.356 B**, `x86_64` **3.899.320 B**); SHA-256 vom Doku-Team verifiziert:
  arm64 `d34fda6f06ed7809c386af243b55e55cadd20794f1413b94ada3a729b26fd15e`,
  x86_64 `9f393ce49032a84f75717174b09748c08e86ff831886a38f68d0ac12975394f3`.
- **Assets:** `sir_quacksec.png` (vom Nutzer bereitgestellt, 749×820), `world_map_ambient.png`
  (2560×1280, byte-identisch aus Mobile-Dossier).
- **Doku:** `docs/V2-ARCHITECTURE.md` (erweitert), `docs/TRAFFIC-MAP.md`, `docs/ONBOARDING.md`;
  V2-Abschnitte in THREAT-MODEL/SECURITY/PRIVACY/DATA-SAFETY/TEST-PLAN.

### Status V2 (29.10.2026)

- **Alle V2-Funktionen: NOT_TESTED.** Keine V2-Builds, keine VPN-/Traffic-/XDR-Läufe, keine
  V2-Screenshots. V2 ist **nicht releasefähig**.
- Offene V2-Blocker: Laufzeit-/Emulator-Evidenz, Fail-Closed/Always-On auf realen TVs,
  Policy-/Geo-Integrität, Streaming-/DRM-Kompatibilität, Akku/Thermik, Play-FGS-/VPN-Deklaration,
  Traffic-Datenschutztext/Retention.
- Lint aktuell (dist/lint-results-debug.txt): **0 Errors / 169 Warnings** (V1-Ledger nannte 165;
  Differenz durch spätere Änderungen). Keine V2-Compile-/Lint-Evidenz behauptet.

## [Unreleased] — RC-Finalisierung 29.10.2026

### Verifiziert (Lead-Endledger, Emulator Android 16 Google TV, API 36, AVD `gedefense_tv`, 1920×1080)

- **`:tv-core:tvCoreCheck`** → Exit 0, `BUILD SUCCESSFUL`, `PASS 554 / FAIL 0`, 35 Tests (nach
  DeCatalog-Sonderzeichenfix `[{]`/`[}]` erneut grün).
- **`:core:coreCheck`** → Win32-Host **BLOCKED** (Verzeichnis-`fsync` via `FileChannel`,
  Upstream-Limitierung der byteidentischen Mobile-Core-Kopie); identische kompilierte
  Harness-Klassen unter Linux-JVM (WSL Ubuntu 24.04, OpenJDK 17.0.20.1) → `CORE_TESTS_PASS`,
  Exit 0.
- **`:app:compileDebugKotlin`** → Exit 0; **`:app:lintDebug`** → Exit 0, **0 Errors / 165
  Warnings** (131 `UnusedResources`, 22 `PluralsCandidate`, 4 `DrawAllocation`,
  2 `QueryPermissionsNeeded`, 2 `ApplySharedPref`, je 1 `TranslucentOrientation`,
  `ObsoleteSdkInt`, `DiscouragedApi`, `DataExtractionRules`).
- **`:app:assembleDebug`** → Exit 0, `app-debug.apk` **2.860.091 Bytes** (~2,86 MB, Brand-PNGs
  inkl.).
- **`:app:assembleRelease`** → Exit 0, `app-release.apk` **1.629.037 Bytes**, R8-minifiziert, mit
  **Debug-Zertifikat** signiert (Produktions-Blocker F-01); installiert und auf dem Emulator
  gestartet (Smoke-Test).
- **UI-Remake (2-Spalten-Architektur, Header-Aktionen & Multi-Resolution 1080p/2K/4K):**
  - **Abschaffung der docked Bottom Action Bar:** Feste `actionArea` in `ScreenScaffold.kt` entfernt;
    Aktionen sitzen jetzt nativ und ergonomisch in der Header-Aktionsleiste (`headerActionBar`) oben rechts.
  - **Responsive 2-Spalten-Dashboards:**
    - `HomeScreen.kt`: Schlanke Hero-Card (124 dp), 4-Kachel-KPI-Zeile (44 dp), zwei Spalten darunter
      (54 % Top-Befunde, 46 % Gerät & Prüfumfang) – passt zu 100 % ohne Scrollen auf den TV-Schirm.
    - `AppsScreen.kt`: 2 Spalten – links App-Statistik & Sichtbarkeitshinweis (32 %), rechts sofort
      startende App-Liste (68 %); die ersten 7 Apps sind ohne D-Pad-Scrollen sofort sichtbar.
    - `CheckScreen.kt` & `FindingsScreen.kt`: Übersicht/Steuerung links, Befunde/Collectors rechts.
  - **Typografie & Spacing-Entzerrung:** `SectionHeader.kt` mit vertikalem Padding `(0, 4dp, 0, 8dp)`
    und 15 dp Akzentlinie; Text klebt nicht mehr an Titeln; Overscan auf 24 dp reduziert;
    Rail-Breite auf 196 dp optimiert; Type-Scale straff kalibriert (Display 28, Score 34, Title 22,
    Heading 16, Body 13, Label 12, Caption 11, Micro 10 sp).
  - **Multi-Resolution Verifikation:** Erfolgreich auf 1080p (960×540 dp), 2K (961×540 dp) und
    4K (960×540 dp) via `tools/test-tv-resolutions.ps1` verifiziert und per Screencap belegt.
- **UI-Overscaling & Density-Fix (10-Foot-Baseline):** Kanonische Android-TV-Dichte 960×540 dp (`sw540dp`)
  durch Bereinigung des fehlerhaften Emulator-Overrides (`wm density 640` auf 1080p beseitigt) und
  Neukalibrierung aller UI-Tokens (`dimens.xml`, `TvTheme.kt`).
  `RingGaugeView` mit robuster SP-zu-PX-Konvertierung via `TypedValue.applyDimension`.
  Screen-Inhalte passen nun vollständig ohne vertikalen Anschnitt auf den Bildschirm.
- **Kaltstart** (Debug, Emulator, Software-GPU): `am start -W` TotalTime **1,81–2,29 s** (vorher
  6,7 s); App-Bootstrap 191–261 ms; `navigate(HOME)` 118–135 ms; erster sichtbarer Frame ohne
  schwarzen Screen; verbleibende ~1,4 s Window/Theme/Inflate (Emulator-Software-GPU-Anteil;
  reale TV-Hardware **NOT_TESTED**).
- **Performance-Fix:** `TvThreatIntelRepository.status()` ist O(1) (persistierter Snapshot,
  Hintergrund-Validierung ~1,1 s, `MIN_PRIORITY`); Beweis: vorher `navigate` 4.519 ms, nachher
  118–135 ms.

### Emulator-/UI-Evidenz (Lead, read-only durch Doku-Team gegengeprüft)

- Scan per D-Pad: `PARTIAL` / „Teilweise abgeschlossen“ / „Teilweise Sicht“, 3 Befunde,
  6 Prüfbereiche, Daueranzeige, kein Crash (Logcat clean).
- TI-Sync: 9/9 Feeds aktuell, Feed-Liste mit Records/Modus, HMAC-Cache verifiziert.
- Evidenz: „Evidenzspeicher gesund“, **40 Einträge**, HMAC-Kette; Key-Custody-Redesign
  (`TvKeyCustody`: Keystore-gewrappter 256-bit-Root, domain-separierte Software-Subkeys);
  Alt-Ledger nach `no_backup/evidence/legacy/` archiviert; Keyring
  `no_backup/evidence/keyring.v1` belegt.
- Export: SAF-Stub auf TV erkannt → MediaStore-Fallback schreibt
  `/sdcard/Download/GeDefenseTV/GeDefense-TV-Report-<UTC>.txt` + `.json` (**30.246 B** /
  **4.562 B**, valides JSON), keine Storage-Permission.
- Restart nach `force-stop`: Home zeigt persistierte Scan-Summary (Score/Band/Status + ehrlicher
  Neustart-Hinweis), Check „Letzter Lauf“; Apps/Härtung summary-aware.
- D-Pad: alle Screens erreichbar, Listen fokussierbar/scrollbar, Delete zweistufig, LEFT zur Rail,
  BACK korrekt, keine Touch-Abhängigkeit; Text Weiß-Familie (Kontrast ≥ 4,5:1), Gold nur
  Brand/Primary/Warning, Blau live/info, Grün verifiziert, Rot kritisch.
- Screenshots **80–96** (1920×1080) in `TV/_inbox/screenshots` (Lead-Arbeitsverzeichnis,
  gitignoriert).
- Eigene read-only Gegenprüfung: Emulator `emulator-5554` aktiv; `ro.build.version.sdk=36`,
  `release=16`, Fingerprint `…:user/dev-keys`, `security_patch=2026-04-01`; App installiert
  (`versionName=0.1.0-alpha1`, versionCode 1, DEBUGGABLE); Ledger 19.169 B / 32 Zeilen,
  `keyring.v1` 61 B, Legacy-Archiv 14.375 B, Exportdateien 30.246 B/4.562 B per
  `adb shell`/`run-as` verifiziert.

### Geändert (Redesign)

- Original-GeDefense-Logo integriert (Rail, Settings/About-Brandblock, Hero-Watermark,
  Launcher-Banner `tv_banner.png` 640×360, App-Icon `ic_tv_launcher.png` 512×512).
- Palette auf Obsidian-Mineral + metallisches Gold + Electric-Blue umgestellt; Text durchgehend
  Weiß-Familie; Glass mit Gold-Kante; 4 dp Gold-Fokusring, Focus-Scale 1.02/140 ms,
  220 ms Eingangsanimation.
- `TvKeyCustody` eingeführt (ersetzt direkte per-Record-Keystore-Keys; behebt
  Opaque-Key-Executor-Defekt), Export-Fallback, Scan-Summary-Persistenz, Performance-Fix.

### Bekannte Lücken / offene Punkte

- Reale TV-Hardware (≥ 2 OEM-Profile) **NOT_TESTED**; Launcher-Visual auf unprovisioniertem
  Emulator nicht prüfbar (Intent + Banner-Ressource statisch belegt); vollständiges
  Security-Review offen; Produktionssignatur/DSE/Sicherheits-Meldeweg offen; automatische
  Retention **V2**; finaler RC-Rebuild (Debug+Release) nach Doku-Abschluss; Export-Fallback nach
  Redesign nicht separat neu belegt (Datei-Nachweis 10:32 UTC).

## [0.1.0-alpha1] — 2026-10-29

Erster Projekt-Snapshot (Pre-Alpha/RC-Kandidat, **kein produktionsfähiges Release-Artefakt**).
VersionCode 1, Anwendungspaket `de.visiongaia.gedefense.tv`, `minSdk 26`,
`targetSdk`/`compileSdk 36`.

### Hinzugefügt

- **Projektgerüst:** Gradle-Root `VGT-GeDefense-TV` mit Modulen `:core`, `:tv-core`, `:app`;
  AGP 8.5.2, Kotlin 1.9.24, Gradle 8.7 (Distribution-SHA-256 gepinnt), Java 17.
- **Vendored Core:** byte-identische Kopie des GeDefense-Mobile-Core aus
  `GeDefense/Mobile/0.28.0-beta1/Source/core` (VersionCode 59) inklusive
  `core/PROVENANCE.md` und `SOURCE-MANIFEST.sha256` (26 Dateien).
- **`:tv-core`:** Domänenmodelle und Implementierungen für Plattform-/Patch-Bewertung,
  App-Inventar, Hardening, Scan, Scoring/Coverage, Findings, Events (JSONL-Codec),
  Reports und Threat-Intel-Status; `DeCatalog` (214 deutsche Keys); `TvCoreTestMain`
  (PASS/FAIL-Zählung, Exitcode 1 bei Fehlern).
- **`:app`:** Manifest (TV-only, Leanback required, minimale Permissions), `TvApplication`,
  `TvServices`-Container, Contract-Interfaces, Scan-Controller, 6 Collectors,
  Evidence-/TI-/Report-/Settings-Repositories inkl. `TvKeyCustody`, TV-UI-Shell
  (`TvMainActivity`) mit D-Pad-Rail, 10 Screens, `ScreenRegistry`, Komponenten,
  `TvTheme` (GLASS-2100-Tokens, Redesign), Brand-PNGs, ProGuard-/R8-Regeln.
- **Dokumentation:** README, ARCHITECTURE, THREAT-MODEL, SECURITY, PRIVACY, DATA-SAFETY,
  TEST-PLAN, BUILD-RUNBOOK, docs/TV-EMULATOR-TESTING, docs/DESIGN-DNA, docs/SOURCES,
  CHANGELOG, SBOM (CycloneDX 1.5), `Next.md` (Lead-owned).
- **Tooling:** `tools/build.ps1`, `tools/test.ps1`, `tools/verify-source-fidelity.ps1`
  (SHA-256-Fidelity-Gate), `tools/run-tv-emulator.ps1` (Helper, keine Erfolgsbehauptung),
  `tools/generate_brand_assets.py`.

### Verifiziert (reale Belege)

- **Quellentreue:** `tools/verify-source-fidelity.ps1` → Exitcode **0**, 26/26 Dateien
  SHA-256-identisch zum Manifest; dokumentierte Ausnahme `core/PROVENANCE.md`.
- **JVM-Harnesse:** `:tv-core:tvCoreCheck` Exit 0 (`PASS 554 / FAIL 0`, 35 Tests); `:core:coreCheck`
  Linux-JVM Exit 0 (`CORE_TESTS_PASS`), Win32 BLOCKED (Upstream-`fsync`-Limitierung).
- **Plain Build/Lint:** `compileDebugKotlin`/`assembleDebug`/`lintDebug` Exit 0; Lint
  0 Errors / 169 Warnings; Debug-APK 2.860.091 B.
- **Release-Pipeline:** `assembleRelease` Exit 0; Release-APK 1.626.209 B, R8-minifiziert,
  **debug-signiert** (F-01); installiert/gestartet (Smoke-Test).
- **Emulator:** Android 16 API 36, AVD `gedefense_tv`; Scan/TI/Evidenz/Export/Restart/D-Pad
  belegt, Screenshots 80–96; Kaltstart 1,81–2,29 s.
- **Statisch:** Manifest nur `INTERNET`/`ACCESS_NETWORK_STATE`, `allowBackup="false"`,
  `usesCleartextTraffic="false"`, keine Provider/Receiver, JobService mit `BIND_JOB_SERVICE`;
  TLS-Config nur System-TrustAnchors; SBOM/Doku-Links gültig; Secret-Muster-Grep ohne Treffer.
- **SDK-Inventur:** Plattform `android-36`, Build-Tools `36.0.0`, TV-Image
  `android-36;google-tv;x86_64` installiert; Emulator/`platform-tools` vorhanden.

### Nicht verifiziert / offen (NOT_TESTED)

- Reale TV-Hardware (≥ 2 OEM-Profile), Doze-/Reboot-Volltest, Offline/Stale-Szenario,
  synthetischer IOC-Match, Tamper-/Fail-closed-Adversarialtest, Collector-Timeout im Emulator,
  Fuzz-/Negativtests, App-Unit-Tests, unabhängiges Security-Review.
- Finaler RC-Rebuild mit dokumentiertem Stand; echte Produktionssignatur.
- Automatische Retention/Rotation (**V2**, in V1 nicht aktiv); Feed-Signaturen (nur TLS);
  Sicherheits-Meldeweg; Datenschutzerklärung/Impressum (Release-Blocker).

### Sicherheit

- Minimales Berechtigungsmodell, `allowBackup=false`, TLS-Only-Feeds, Fail-closed-Evidenz mit
  Keystore-gewrapptem Root und domain-separierten Subkeys, keine Telemetrie. Kein durchgeführtes
  Security-Review; VGT-100 nur als Profil-Mapping-Summary dokumentiert (siehe
  [SECURITY.md](SECURITY.md)). Belegter Stand: **GOLD / PARTIAL_VERIFIED**, kein DIAMANT.

### Hinweise

- Kein Lizenztext im Repository; keine Veröffentlichung/Weitergabe ohne Freigabe.
- Git-Repository mit Baseline-Commit `fe555cd`; der RC-Commit erfolgt nach Abschluss der
  Doku-Evidenzübernahme.

## [0.2.0-alpha1] — 2026-10-29`n`nGeDefense TV V2: lokaler Loopback-VPN, Traffic-Map mit Geo-Attribution, XDR-Light, Onboarding-Neubau, Sir Quacksec, TI-Sync-Popup.`n`n### V2 verified smoke (2026-10-29)

- On-device loopback VPN verified on emulator: TUN `10.253.0.2/32` + `fd7a:4744::2/128`, helper `libgedefense_gaianet_v2.so` alive, state ACTIVE (54689 threat records) after TI sync; empty TI cache starts honestly as DEGRADED.
- DNS/tracker blocking verified: `doubleclick.net`, `samsungads.com`, `samba.tv`, `inscape.tv`, `alphonso.tv` resolve to unknown host via the tunnel; `example.com` resolves normally; 6 blocked flows recorded.
- Geo attribution verified after offline geo generation: US country resolved, map route drawn; unknown owners stay „Nicht zuordenbar“.
- Traffic and XDR screens redesigned (GLASS 2100 composition): map+numbers hero, top destinations, two-column app cards; XDR summary band, explainable incidents, context panel; fixed cached-incident merge and duplicate density.
- First-run wizard rebuilt and verified (6 steps, focus on primary action, honest VPN/TI/scan states, completion persists); Sir Quacksec welcome overlay and TI sync popup with logo/progress verified; VPN auto-start on relaunch verified.
- Screenshots: `_inbox/screenshots/v2/` (W/X/Y/Z series).
