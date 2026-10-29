# GeDefense TV — Architektur

> **Release-Tree 0.2.0-alpha1:** Dieses Dokument ist für den Quellstand `0.2.0-alpha1` (VersionCode 2) kuratiert. Evidenzangaben mit Datum 29.10.2026 beziehen sich auf den jeweils genannten Build; V2/V2.1-Funktionen sind Alpha und nicht vollständig auf realer TV-Hardware abgenommen.


**Version:** 0.2.0-alpha1 · **Stand:** 29. Oktober 2026 · **Status:** Architekturdokumentation mit
realer Build-/Emulator-Evidenz; `:tv-core` und `:core` (Linux-JVM) verifiziert, `:app` gebaut,
gelintet und auf Android-16-TV-Emulator (API 36) getestet; reale TV-Hardware **NOT_TESTED**

Dieses Dokument beschreibt die tatsächlich angelegte Modul- und Klassens­truktur, die
Vertragsgrenzen und die verbindlichen Architekturregeln. Wo ein Nachweis noch fehlt
(insbesondere App-Build, Emulator, reale Geräte), ist das ausdrücklich als **NOT_TESTED**
markiert. Es werden keine Implementierungsdetails erfunden.

---

## 1. Architekturüberblick

GeDefense TV ist eine Drei-Modul-Anwendung mit strikter Trennung zwischen Android-Oberfläche,
plattformunabhängiger TV-Domänenlogik und dem unverändert eingebundenen GeDefense-Mobile-Core.

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ :app  (Android-Anwendung, Kotlin, Java 17, View-System, keine AndroidX)      │
│                                                                              │
│  TvApplication ──► TvServices (Prozess-Container, exakt einmal installiert)  │
│  TvMainActivity ─► TvServices + ScreenRegistry + Navigations-Rail            │
│                                                                              │
│  ui/          TvTheme · Screen-Verträge · TvRoute · Screens                  │
│  contract/    ScanControllerApi · EvidenceApi · ThreatIntelApi ·             │
│               ReportApi · SettingsApi · ScanListener/ScanUiState             │
│  scan/        DefaultScanController (1-Thread-Executor, Progress→Main)       │
│  platform/    6 Collectors + TvThreatIntelJobService                         │
│  data/        TvServicesBootstrap · AndroidSecrets · AndroidKeystoreGate ·   │
│               TvKeyCustody · SecureFiles · TvEvidenceRepository ·            │
│               TvFeedDownloader · TvThreatIntelRepository · TvReportExporter ·│
│               TvSettingsStore · TvInventoryBaseline                          │
│                                                                              │
│  Abhängigkeiten: nur Plattform-APIs + :core + :tv-core                       │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │ statische Kotlin-API (keine Reflection)
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ :tv-core  (Pure JVM, keine Android-Abhängigkeit, JVM-Toolchain 17)           │
│                                                                              │
│  model/    PlatformIdentity · PatchAssessment/PatchPolicy · InstalledApp ·   │
│            AppInventory · InventoryDelta · HardeningObservations ·           │
│            CapabilityState · DataVisibility · Severity · Confidence ·        │
│            PolicyAction · DataQuality · EventClass · MessageRef ·            │
│            TextCatalog · Finding/EvidenceRef · TvEvent · CollectorResult ·   │
│            ScanResult/ScanOutcome/ScanState/ScanProgress · PostureScore ·    │
│            FeedSnapshot/ThreatIntelStatus/ThreatMatch · SecurityReport       │
│  scan/     ScanEngine · ScanEngineConfig · CancelSignal                      │
│  score/    ScoringEngine · CoverageAggregator                                │
│  rules/    HardeningRuleEvaluator                                            │
│  report/   ReportRenderer (Text + JSON)                                      │
│  event/    EventCodec (JSONL, deterministisch)                               │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │ nur öffentliche API (pure JVM)
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ :core  (vendored GeDefense Mobile Core 0.28.0-beta1, VersionCode 59)         │
│                                                                              │
│  EvidenceLedger v3 (HMAC-Kette, optionale per-Record-Verschlüsselung)        │
│  AeadVaultEnvelope (AES-256-GCM) · AuthenticatedSnapshotStore ·              │
│  BoundedSecretKeyCrypto · DurableAtomicFiles · ThreatCacheStore ·            │
│  ThreatFeedCatalog (9 Feeds) · ThreatIntelParser · ThreatIndex ·             │
│  IpPrefix · Integritäts-/Recovery-Bausteine                                  │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Quellentreue-Regel:** `:core` ist eine byte-identische Kopie aus dem Mobile-Quellstand
(`GeDefense/Mobile/0.28.0-beta1/Source/core`). Änderungen dürfen **nicht** in der Kopie erfolgen,
sondern nur im Mobile-Quellstand mit anschließendem vollständigem Neuimport und frischem Manifest
(`core/PROVENANCE.md`). Prüfung: `tools/verify-source-fidelity.ps1`.

---

## 2. Module und Build-Konfiguration

| Attribut | Wert | Beleg |
| --- | --- | --- |
| Root-Projekt | `VGT-GeDefense-TV`, Module `:core`, `:tv-core`, `:app` | `settings.gradle.kts` |
| Anwendungspaket / Namespace | `de.visiongaia.gedefense.tv` | `app/build.gradle.kts` |
| Version | `0.2.0-alpha1`, versionCode 2 | `app/build.gradle.kts`, `VERSION`, `VERSION_CODE` |
| SDK | `minSdk 26`, `targetSdk 36`, `compileSdk 36`, Build-Tools `36.0.0` | `app/build.gradle.kts` |
| JVM | Java/Kotlin-Ziel 17, `-Xjsr305=strict` | `app/build.gradle.kts` |
| Toolchain | AGP 8.5.2, Kotlin 1.9.24, Gradle 8.7 (Wrapper, Distribution-SHA-256 gepinnt) | `build.gradle.kts`, `gradle/wrapper/gradle-wrapper.properties` |
| Runtime-Abhängigkeiten | **keine** Drittanbieter-Bibliotheken | `app/build.gradle.kts` |
| AndroidX | **deaktiviert** (`android.useAndroidX=false`) | `gradle.properties` |
| UI-Technologie | Android-View-System, programmatische Views, kein Compose/WebView | `ui/TvTheme.kt`, `TvMainActivity.kt` |
| Release-Härtung | R8 minify + shrinkResources, `-keepattributes SourceFile,LineNumberTable`, keine Reflection-Serialisierung | `app/build.gradle.kts`, `app/proguard-rules.pro`; `assembleRelease` Exit 0, APK 1.626.209 B, R8-minifiziert (debug-signiert) |
| Lint | `abortOnError = true`, `checkReleaseBuilds = true` | `app/build.gradle.kts`; `lintDebug` Exit 0, **0 Errors / 169 Warnings** |
| Repositories | `google()`, `mavenCentral()`, optional lokaler Mirror via `VGT_LOCAL_MAVEN`; `FAIL_ON_PROJECT_REPOS` | `settings.gradle.kts` |

**Signaturhinweis (Release-Gate):** Die Release-Signatur wird nur konfiguriert, wenn alle vier
Umgebungsvariablen `GEDEFENSE_RELEASE_STORE_FILE`, `GEDEFENSE_RELEASE_STORE_PASSWORD`,
`GEDEFENSE_RELEASE_KEY_ALIAS`, `GEDEFENSE_RELEASE_KEY_PASSWORD` gesetzt sind. Andernfalls fällt
`release` auf die **Debug-Signatur** zurück. Ein 0.2.0-alpha1-Artefakt ist ausdrücklich ein
**debug-signiertes Testartefakt**; für eine echte Veröffentlichung ist der Fallback unzulässig und
muss vor dem Release-Gate erzwungen werden (offener Punkt).

**Verifikationsstand der Module (29.10.2026):** `:tv-core` – `tvCoreCheck` verifiziert
(Exitcode 0, `PASS 554 / FAIL 0`, 35 Tests, `BUILD SUCCESSFUL`). `:core` – `coreCheck` unter
Win32 **BLOCKED** (Verzeichnis-`fsync` via `FileChannel`), auf Linux-JVM (WSL Ubuntu 24.04,
OpenJDK 17.0.20.1) `CORE_TESTS_PASS`, Exitcode 0. `:app` – `compileDebugKotlin` Exit 0,
`lintDebug` Exit 0 (0 Errors / 169 Warnings), `assembleDebug` Exit 0 (`app-debug.apk`
2.860.091 B), `assembleRelease` Exit 0 (`app-release.apk` 1.626.209 B, R8, debug-signiert).
Emulator (Android 16 Google TV, API 36, AVD `gedefense_tv`, 1080p): Scan/TI/Evidenz/
Export-Fallback/Restart-Summary/D-Pad verifiziert; Kaltstart 1,81–2,29 s. Reale TV-Hardware
**NOT_TESTED**.

---

## 3. Schichten und Verträge

### 3.1 Vertragsschicht (`app/contract/Contracts.kt`)

Die UI kennt ausschließlich diese Schnittstellen; Implementierungen liegen in `scan/` und `data/`.

| Vertrag | Verantwortung |
| --- | --- |
| `ScanControllerApi` | `state()`/`lastResult()`, `lastSummary(): ScanSummary?`, `start(listener): Boolean` (false, wenn bereits ein Scan läuft), `cancel(): Boolean` |
| `ScanListener` | `onStarted`, `onProgress(ScanProgress)`, `onCompleted(ScanResult)`, `onFailed(MessageRef)`; Callbacks dürfen auf Hintergrundthreads eintreffen |
| `EvidenceApi` | `health(): EvidenceHealth`, `recordScan(ScanResult): Boolean`, `rows(limit): List<EvidenceRow>`, `clear(): Boolean` |
| `ThreatIntelApi` | `status(): ThreatIntelStatus` (**O(1)** aus validiertem Snapshot), `syncNow(listener): Boolean`, `schedulePeriodicSync(enabled)` |
| `ReportApi` | `build(ScanResult): SecurityReport`, `export(report, activity, listener): Boolean` (SAF, mit MediaStore-Fallback) |
| `SettingsApi` | `tiAutoSyncEnabled`, `retentionDays` (in V1 **nicht wirksam**; automatische Retention ist V2), `lastScanAtMillis`, `lastScanSummary`/`setLastScanSummary` (Persistenz der Scan-Zusammenfassung), `onboardingDone` – jeweils Getter/Setter |

`TvServices` ist der prozessweite Container (App-Kontext, TextCatalog, Settings, Device-ID,
App-Version, Scan/Evidence/TI/Report). Er wird von `TvApplication` über
`TvServicesBootstrap.create(this)` **genau einmal** installiert; ein Fehlschlag beendet den Prozess
bewusst fail-fast, statt eine halb verdrahtete Sicherheits-App zu starten. Für Tests existiert
`createForTest`.

### 3.2 Domänenschicht (`:tv-core`)

Reine JVM-Logik ohne Android-Importe, dadurch vollständig auf dem JVM-Testharness prüfbar.
Benutzertexte sind `MessageRef`-Schlüssel (`key(arg0, …)`) und werden erst in der App-Schicht über
einen `TextCatalog` aufgelöst; der Fallback `PassthroughTextCatalog` macht fehlende Übersetzungen
sichtbar, statt sie zu verschlucken. Der deutsche Katalog ist `text/DeCatalog` (214 Keys,
`resolve()` wirft nie, Fallback = sichtbarer Key; `isDefined()`/`missingKeys()` für Testbarkeit).

**Reale Implementierungen (Stand der Implementierung):**

| Datei | Implementierung |
| --- | --- |
| `scan/DefaultScanEngine.kt` | `class DefaultScanEngine(...) : ScanEngine` |
| `score/RuleBasedScoringEngine.kt` | `object RuleBasedScoringEngine : ScoringEngine` + `ScoringConfig`; `object DefaultCoverageAggregator : CoverageAggregator` |
| `rules/DefaultHardeningRules.kt` | `object DefaultHardeningRules : HardeningRuleEvaluator` |
| `report/DefaultReportRenderer.kt` | `object DefaultReportRenderer : ReportRenderer` (Text + deterministisches JSON, Schema `gedefense-tv-report/1`) |
| `event/DefaultEventCodec.kt` | `object DefaultEventCodec : EventCodec` (JSONL, Schema `gedefense-tv-event/1`, strikte Decode-Regeln) |
| `text/DeCatalog.kt` | `object DeCatalog : TextCatalog` |

Zentrale Invarianten (durch `require(...)` in den Modellen erzwungen):

- IDs (Collector, Rule, Event, Scan, Report, Device) haben feste Muster.
- Zeitstempel: `completedAtMillis >= startedAtMillis`, `lastSeen >= firstSeen`.
- Ein `FAILED`-Collector **muss** einen `errorKey` tragen.
- `DataVisibility.FULL` setzt `CapabilityState.SUPPORTED` voraus.
- Ein numerischer Score existiert **nur**, wenn der Band nicht `UNKNOWN`/`INSUFFICIENT_COVERAGE` ist.
- `DataVisibility.FULL` darf keinen `capReason` haben; eine Kappung muss begründet sein.
- Event-Attribute: max. 12, Schlüssel `[a-z][a-z0-9_]{1,31}`, Werte ≤ 256 Zeichen, keine
  Zeilenumbrüche.

### 3.3 UI-Schicht (`app/ui/`)

Einzelne `Activity` (`TvMainActivity`, `singleTask`, Landscape, immersive, `KEEP_SCREEN_ON`).
Sie besitzt Navigation, Fenster und Back-Stack; Screens erhalten einen `ScreenHost` und starten
selbst keine Activities.

- `TvRoute`: `HOME`, `CHECK`, `FINDINGS`, `FINDING_DETAIL`, `APPS`, `HARDENING`, `THREAT_INTEL`,
  `EVIDENCE`, `SETTINGS`, `ABOUT`.
- Top-Level-Rail (8 Ziele): `HOME`, `CHECK`, `FINDINGS`, `APPS`, `HARDENING`, `THREAT_INTEL`,
  `EVIDENCE`, `SETTINGS`; `FINDING_DETAIL` und `ABOUT` werden gepusht.
- `TvScreen`-Vertrag: `createView(host)`, `onShown/onHidden`, `handleBack(): Boolean`,
  `initialFocus(): View?`, `onKeyEvent(event): Boolean`. Jedes interaktive Element muss per D-Pad
  erreichbar und aktivierbar sein; Touch/Hover sind optional.
- BACK-Semantik: zuerst screen-lokaler Zustand (`handleBack`), dann Back-Stack, zuletzt Übergang
  zu `HOME`.
- Fokus: `initialFocus()` wird nach dem Anzeigen angefordert; ohne Angabe erhält der
  Content-Bereich den Fokus. Der Fokusring ist nicht optional (4 dp, Akzentfarbe, zusätzlich
  `accentDim`-Fläche) – Status wird nie ausschließlich über Farbe vermittelt.
- Oberflächen-Tokens: zentral in `ui/TvTheme.kt` (Redesign 2026: Obsidian-Mineral, metallisches
  Gold als Brand/Primary, Electric-Blue für Live/Info, Grün nur verifiziert, Rot nur kritisch;
  Text durchgehend Weiß-Familie; Radien 20/14 dp, Fokusring 4 dp Gold, Focus-Scale 1.02/140 ms,
  Eingangsmotion 220 ms). XML-Ressourcen spiegeln diese Werte. Details:
  [docs/DESIGN-DNA.md](docs/DESIGN-DNA.md).

> **Status:** `ui/ScreenRegistry`, alle 10 Screens, die Komponenten unter `ui/components/` sowie
> die Ressourcen (inkl. Brand-PNGs) sind vorhanden. `compileDebugKotlin` und
> `assembleDebug`/`lintDebug` sind **Exit 0**; die UI wurde auf dem Android-16-TV-Emulator
> (API 36) über D-Pad getestet (Screenshots). Reale TV-Hardware: **NOT_TESTED**.

---

## 4. Collector-Modell und Sichtbarkeit

### 4.1 Collector-Vertrag (`tv-core/model/Collector.kt`)

Ein Collector ist read-only, erhält eine unveränderliche `CollectorEnvironment` (Zeitpunkt,
pseudonyme `deviceId`, `PlatformIdentity`, `PatchAssessment`) und ein `CancelSignal`. Er liefert
genau ein `CollectorResult`.

Regeln:

- fehlende Berechtigung/API ist **kein** Fehler, sondern `PERMISSION_REQUIRED` bzw. `UNSUPPORTED`;
- unerwartete Exceptions werden zu `FAILED` mit stabilem `errorKey` (keine rohen
  Exception-Texte in der UI);
- Zeitbudget einhalten, Teilergebnisse statt Hänger;
- `coverage.observed` ohne belastbaren Nenner (`total = null`) ist ausdrücklich erlaubt und
  verhindert jede Vollständigkeitsbehauptung (`CollectorCoverage.complete == false`).

### 4.2 Implementierte Collector (`app/platform/`)

| `collectorId` | Kategorie | Aufgabe | Sichtbarkeitsgrenze |
| --- | --- | --- | --- |
| `platform` | `PLATFORM` | Build-/Geräteidentität, Patch-Bewertung | Metadaten, kein Integritätsbeweis |
| `apps` | `APPS` | sichtbares App-Inventar, Versionen, Signatur-Digests, Installationsquelle, Delta zur Baseline | Package Visibility; `PARTIAL` ab API 30, kein vertrauenswürdiger Nenner |
| `hardening` | `HARDENING` | Debugging-/Entwickleroptionen, test-keys/userdebug, Device-Admin, Accessibility-Dienste, sichtbare Nicht-Store-Installer | tri-state; nicht lesbar ≠ sicher |
| `connectivity` | `CONNECTIVITY` | Netzwerkstatus/-wechsel der eigenen App | kein Flow-/Socket-Inventar |
| `sensor-health` | `SENSOR_HEALTH` | App-/Collector-Gesundheit, Datenalter, Permission-Verlust | interne Selbstauskunft |
| `threat-intel` | `THREAT_INTEL` | lokaler Feed-/IOC-Status, Stale-Erkennung | nur Indikatoren, die die App real kennt |

> **Status:** Die sechs Collector-Klassen sind implementiert und über den Emulator-Scan belegt
> (6 Prüfbereiche, Ergebnis `PARTIAL`). Reale OEM-Geräte: **NOT_TESTED**.
>
> **Reale Hardening-Regeln (`DefaultHardeningRules`):** `hardening-adb`, `hardening-devoptions`,
> `hardening-unknownsources` (unlesbare Werte erzeugen jeweils ein `…-unreadable`-Info-Finding mit
> `DataVisibility.NONE`), `hardening-testkeys` (test-keys/userdebug/eng), `hardening-deviceadmin`,
> `hardening-accessibility` (nur Nicht-System-Pakete; bekannte Systempakete ausgenommen),
> `hardening-installer` (sichtbare Nicht-Store-Installer). Deterministisch, dedupliziert, sortiert.

### 4.3 Ehrliches Sichtbarkeitsmodell

`DataVisibility` hat vier Stufen; `CapabilityState` vier Zustände. Die Aggregation
(`CoverageAggregator`) ist als **eine** Definition vorgesehen, damit UI, Report und Event-Schicht
identisch urteilen.

Verbindliche Semantik:

| Sichtbarkeit | Bedeutung | UI-/Report-Konsequenz |
| --- | --- | --- |
| `FULL` | Collector unterstützt und vollständig ausgeführt | erst hier darf „vollständig geprüft“ erscheinen |
| `PARTIAL` | nur ein Teil der Daten beobachtbar (z. B. Package Visibility) | Einschränkung sichtbar, keine „clean“-Aussage, Score ggf. gekappt |
| `STALE` | Daten vorhanden, aber älter als ihr Budget (TI-Feeds) | Quelle + Alter sichtbar, Nutzung erlaubt, Kennzeichnung Pflicht |
| `NONE` | Bereich nicht beobachtbar | **niemals** grün/„sauber“; Score wird `INSUFFICIENT_COVERAGE`/`UNKNOWN` |

Abweichung zum Datenblatt: Das Datenblatt nennt eine „Capability Registry“ als logische
Komponente. Die konkrete Umsetzung dieses Prinzips ist das **per-Collector-Capability- und
Visibility-Modell**: jeder `CollectorResult` trägt `CapabilityState` + `DataVisibility`, der
`DefaultScanController` orchestriert die Collector-Läufe, und `DefaultCoverageAggregator`
aggregiert die Einzelwerte zu einer Gesamt-Sichtbarkeit (Worst-Case). Das ist die konkrete
Instanziierung der Registry-Anforderung, keine fehlende Komponente.

---

## 5. Scan-Pipeline

```text
UI (CHECK/HOME)
  │ ScanControllerApi.start(listener)
  ▼
DefaultScanController (app/scan)
  │  – genau ein Lauf gleichzeitig (start() == false sonst)
  │  – 1-Thread-Executor; Fortschritt/Listener auf Main-Thread
  │  – Cancel-Flag
  ▼
ScanEngine (tv-core) mit ScanEngineConfig
  │  collectorTimeoutMillis = 12_000 (hartes Budget je Collector)
  │  maxCollectors = 32
  │  – Collector wirft → CollectorResult.failed(), Lauf läuft weiter
  │  – Timeout → FAILED mit `collector.timeout`
  │  – Abbruch zwischen Collectoren, Fortschritt einmalig propagiert
  │  – kein Collector doppelt
  ▼
List<CollectorResult>
  │  + PlatformIdentity + PatchAssessment (app/platform)
  │  + AppInventory + InventoryDelta (apps-Collector/Baseline)
  ▼
ScoringEngine.score(results, patch) → PostureScore
  │  jede Punktdifferenz = ScoreContribution(ruleId, delta, message)
  │  NONE/partial/stale-Regeln (siehe §6)
  ▼
CoverageAggregator.aggregate(results) → DataVisibility
  ▼
ScanResult.compose(...) → immutables Snapshot
  │
  ├─► UI (Status, Findings, Coverage)
  ├─► EvidenceApi.recordScan(result) → EvidenceLedger (HMAC-Kette, v3)
  └─► ScanController speichert letztes Ergebnis in-memory + lastScanAt in Settings
```

Terminale Zustände: `COMPLETED`, `PARTIAL`, `CANCELLED`, `FAILED`. „Partial“ ist kein Fehler,
sondern die ehrliche Abbildung eingeschränkter Sichtbarkeit.

**Reale Implementierungsdetails (`tv-core`, Stand der Implementierung):**

- `DefaultScanEngine` ist no-arg konstruierbar und führt Collectoren **sequenziell** auf einem
  dedizierten Daemon-Thread je Scan aus.
- Fehlerpfade: Collector wirft → `FAILED` + `collector.failed`; Timeout →
  `collector.timeout`; CollectorResult mit falscher `collectorId`/`Category` →
  `collector.invalidresult`.
- `CancelSignal` → `ScanState.CANCELLED` (restliche Collectoren laufen nicht); Thread-Interrupt →
  `InterruptedException`.
- Fortschritt: genau ein Update pro gestartetem Collector plus genau ein finales Update
  (`currentCollectorId = null`).
- Doppelte Collector-IDs und mehr als `maxCollectors` → `IllegalArgumentException` (harte
  Architekturgrenze, kein stilles Ignorieren).
- `ScanOutcome` enthält Coverage (`DefaultCoverageAggregator`) und Score
  (`RuleBasedScoringEngine`).

> **Status:** `DefaultScanController`, `DefaultScanEngine` und die Engine-Implementierungen sind
> implementiert; der Emulator-Scan (6 Collector-Bereiche) lief ohne Crash. Timeout-, Cancel- und
> Failure-Isolation sind im JVM-Harness (35 Tests, 554 Checks) abgedeckt; ein künstlicher
> End-to-End-Timeout im Emulator ist **NOT_TESTED**.

---

## 6. Scoring und Patch-Bewertung

### 6.1 Scoring-Regeln (`tv-core/score/ScoringEngine.kt`)

Verbindlich (aus den Schnittstellen-Kommentaren):

1. Jede nicht-null-Beitragung ist eine `ScoreContribution` mit stabilem `ruleId` und
   auflösbarem `MessageRef`.
2. `DataVisibility.NONE` → `PostureBand.INSUFFICIENT_COVERAGE`, Score **null**.
3. `PARTIAL`/`STALE` darf **nie** `STRONG` ergeben; die Kappung wird über `capReason` begründet.
4. Ein altes Patch-Level wird als „alt“ gemeldet, **nie** als „bekannt verwundbar“.
5. Ein einzelnes Merkmal (unbekannter Name, offener Status, hoher Datenverbrauch) löst keine
   kritische Einstufung aus; dieselbe IOC-Quelle über mehrere Spiegel zählt nicht als mehrere
   unabhängige Signale.
6. `Allowlisting` darf einen Baseline-Hinweis reduzieren, aber keine anderen Signale aufheben.

`PostureScore.findingCount` zählt nur negative Beiträge; `value == null` ist an
`UNKNOWN`/`INSUFFICIENT_COVERAGE` gekoppelt.

**Reale Scoring-Parameter (`RuleBasedScoringEngine`, Stand der Implementierung):**

| Element | Wert |
| --- | --- |
| Basiswert | 100 |
| Severity-Penalty | `CRITICAL` −40 · `HIGH` −25 · `MEDIUM` −12 · `LOW` −5 · `INFO` 0 |
| Patch-Penalty | alternd −5 · veraltet −15 · kritisch veraltet −25 (`UNKNOWN`: keine Penalty) |
| Ergebniswert | `clamp(100 + Summe der Deltas, 0..100)`; jede Penalty ist eine `ScoreContribution` mit `ruleId` + `MessageRef` |
| `DataVisibility.NONE` | `INSUFFICIENT_COVERAGE`, **value = null** |
| PARTIAL/STALE oder Patch `UNKNOWN` | nie `STRONG` (Kappung mit `capReason`) |

**Coverage-Aggregation (`DefaultCoverageAggregator`, Worst-Case):** ein Collector mit `FAILED`
oder `NONE` bzw. **keine** Ergebnisse ⇒ `NONE`; `PARTIAL` vor `STALE`; unvollständige quantitative
Coverage (`total != null`, `observed < total`) ⇒ `PARTIAL`; `total = null` wertet nicht ab (kein
erfundener Nenner). Das Scoring erzeugt bewusst **keinen** `UNKNOWN`-Band; das Modell erlaubt ihn
für andere Erzeuger.

### 6.2 Patch-Policy (`tv-core/model/Platform.kt`)

`PatchPolicy.assess(securityPatch, nowMillis)` parst das AOSP-Format `yyyy-MM-dd` (UTC-Mitternacht)
und klassifiziert:

| Alter | Status |
| --- | --- |
| < 90 Tage | `CURRENT` |
| < 180 Tage | `AGING` |
| < 365 Tage | `OUTDATED` |
| ≥ 365 Tage | `CRITICALLY_OUTDATED` |
| fehlend/malformed/plausibilitätswidrig (vor 2007, nach 2100, > 7 Tage Zukunft) | `UNKNOWN` |

Die Plausibilitätsprüfung erkennt auch normalisierte Überläufe (z. B. `2026-02-31`), damit kein
falsches Datum als gültig gilt.

---

## 7. Evidenzkette

Grundlage ist `:core` `EvidenceLedger` (Format **v3**):

- Datei: `context.noBackupFilesDir/evidence/events.v3.log`; **kein** Cloud-Backup
  (`allowBackup="false"`).
- Struktur: append-only, jede Zeile ein Record mit Sequenz und `prev`-Hash; HMAC-SHA-256-Kette.
- Zusätzliche Vertraulichkeit pro Record über einen `EvidencePayloadProtector`
  (AES-256-GCM; AAD bindet Sequenz und Zeitstempel).
- Größenlimit: `EvidenceLedger(maxBytes = 16 MiB)` als Default der Core-Klasse.
- `open()`/`verify()` liefern `LedgerHealth(ok, records, reason)`; Recovery-Archive werden mit
  Manifest und SHA-256 geprüft (`recover`, `verifyRecoveryArchive`).
- **Fail-closed:** Kann die Schlüsselhohheit nicht hergestellt werden, wird ein
  `UnavailableEvidenceStore("evidence_key_custody_unavailable")` verwendet: keine Writes, keine
  „gesunde leere“ Ledger-Behauptung.

**Schlüsselhohheit (`data/TvKeyCustody.kt`, Redesign 2026):**

```text
Android Keystore AES-256-GCM KEK  (Alias vgt.gedefense.tv.evidence.kek.v1, StrongBox versucht)
        │  wrappt
        ▼
keyring.v1  (no_backup/evidence/keyring.v1, 61 B im Emulator)
        │  enthält 256-bit-Zufallsroot, AES-GCM mit AAD "vgt.gedefense.tv.keyring.v1"
        ▼
domain-separierte Software-Subkeys (SHA-256(root || label), nur im Prozess):
  evidence-hmac-v1     → HMAC-SHA-256-Ledgerkette
  evidence-aes-v1      → AES-256-GCM-Record-Protector
  threatintel-hmac-v1  → HMAC-Authentisierung des TI-Caches
```

Begründung: Der vendored Core routet nicht-exportierbare (opaque) Keys durch einen
Single-Slot-Executor (`BoundedSecretKeyCrypto`). Bei direktem per-Record-Keystore-Einsatz kam es
auf dem TV-Image zu transienten Ablehnungen (`evidence_key_custody_unavailable`). Die
Software-Subkeys sind deterministisch, verlassen den Prozess nicht und bleiben at rest durch den
Keystore-gewrappten Root geschützt. `AndroidKeystoreGate` begrenzt Keystore-Aufrufe weiterhin mit
Admission-Lock/Timeout. **Hardware-Backing wird nicht behauptet**, sondern nur versucht
(StrongBox ab API 28, Fallback auf Software-Keystore).

**Fail-closed/Recovery:** Bei fehlender Custody `UnavailableEvidenceStore` (keine Health-Lüge).
Ein gesundes Ledger wird bei neuem Keyring nicht still verworfen: Ein unverifizierbares
Alt-Ledger wird nach `no_backup/evidence/legacy/events.v3-<ts>.log` **archiviert** (Alpha-
Upgrade-Pfad) und eine neue Kette gestartet; bei bestehendem Keyring gilt ein ungesundes Ledger
als Tamper-Indiz. `clear()` löscht Ledger und – im Recovery-Pfad – den Keyring.

> **Belegt (Emulator 29.10.2026):** Evidenzspeicher „gesund“, **40 Einträge**, HMAC-Kette;
> Ledger 19.169 B / 32 Zeilen, `keyring.v1` 61 B, Legacy-Archiv 14.375 B – read-only per
> `adb shell run-as` verifiziert. Tamper-/Fail-closed-Adversarialtest: **NOT_TESTED**.

---

## 8. Threat-Intelligence-Client

### 8.1 Feed-Katalog (vendored Core, `ThreatFeedCatalog`)

Der Katalog ist Bestandteil des Core-Moduls und darf nur durch einen Core-Neuimport geändert
werden (`POLICY_ABI_VERSION = 2`). Neun öffentliche HTTPS-Feeds:

| ID | Name | Semantik | Enforcement | Größen-/Eintragslimit |
| --- | --- | --- | --- | --- |
| `feodo` | Feodo Tracker C2 | `MALICIOUS_C2` | `ROUTE_BLOCK` | 2 MiB / 20 000 |
| `spamhaus-drop-v4` | Spamhaus DROP IPv4 | `DROP_NETWORK` | `ROUTE_BLOCK` | 4 MiB / 30 000 |
| `spamhaus-drop-v6` | Spamhaus DROP IPv6 | `DROP_NETWORK` | `ROUTE_BLOCK` | 4 MiB / 30 000 |
| `cins` | CINS Army Badguys | `HOSTILE_SCANNER` | `CORRELATE_ONLY` | 4 MiB / 50 000 |
| `blocklist-de` | blocklist.de | `HOSTILE_SCANNER` | `CORRELATE_ONLY` | 4 MiB / 50 000 |
| `emerging-threats` | Emerging Threats Block IPs | `AGGREGATED_RISK` | `CORRELATE_ONLY` | 8 MiB / 80 000 |
| `ipsum` | IPsum (Score ≥ 3) | `AGGREGATED_RISK` | `CORRELATE_ONLY` | 8 MiB / 150 000 |
| `firehol-level1` | FireHOL Level 1 | `AGGREGATED_RISK` | `ROUTE_BLOCK` | 8 MiB / 80 000 |
| `tor-exits` | Tor Exit Nodes | `ANONYMIZER` | `ANNOTATE_ONLY` | 2 MiB / 20 000 |

Jeder Feed erzwingt HTTPS mit Host, ohne User-Info/Fragment, ein Refresh-Budget
(`minRefreshMinutes`) und ein Stale-Budget (`maxStaleMinutes`).

**Wichtig für TV:** Die Enforcement-Klassen sind Core-Metadaten. Die TV-App **durchsetzt nichts**;
`ROUTE_BLOCK` bedeutet hier nur, dass der Indikator als blockwürdig klassifiziert wäre – es gibt
keinen VPN-/Firewall-Datenpfad in V1.

### 8.2 Sync-Pipeline (App-Schicht)

```text
ThreatIntelApi.syncNow / Periodischer Job (TvThreatIntelJobService)
  → TvThreatIntelRepository
  → TvFeedDownloader (implementierte Limits: HTTPS-only, Proxy.NO_PROXY,
     max. 2 manuelle Redirects, jeweils same-host, Content-Length- und Streaming-
     Größenlimit gegen feed.maxDownloadBytes, 8 KiB Zeilenlimit, 16 KiB Scan-Chunk,
     Connect 10 s / Read 15 s, Content-Type-Aushandlung)
  → Core ThreatIntelParser/ThreatCacheStore (HMAC-authentifizierte Generationen,
     max. 2 Generationen je Feed, Clock-Skew 10 min)
  → FeedSnapshot je Feed (available, fresh, records, fetchedAt, enforcement)
```

`TvThreatIntelRepository` begrenzt die Parallelität auf **3** Downloads (fester Thread-Pool) und
speichert den Cache unter `filesDir/threat-intel/`. **Wichtig für die UI-Performance:**
`status()` ist **O(1)** – es liefert einen persistierten, bereits validierten Snapshot und löst
kein Datei-I/O/Parsen/Hashing auf dem aufrufenden Thread aus. Die Validierung läuft als
koaleszierte Hintergrundarbeit (`MIN_PRIORITY`, ~1,1 s) und aktualisiert den Snapshot für spätere
Aufrufe. Vor diesem Fix kostete `navigate(HOME)` **4.519 ms**, danach **118–135 ms**.

`ThreatIntelStatus` aggregiert `availableCount`, `freshCount`, `staleCount` und
`syncHealthy`; Stale-Daten bleiben nutzbar, aber immer als `STALE` gekennzeichnet. Offline-Betrieb
ist gültig (letzter Cache).

> **Belegt (Emulator 29.10.2026):** TI-Sync 9/9 Feeds aktuell; Feed-Liste mit Records/Modus;
> HMAC-Cache verifiziert. Offline-/Stale-Szenario: **NOT_TESTED**. Es wurden in dieser
> Dokumentationssitzung **keine** Feeds abgerufen.

### 8.3 IOC-Match-Grenze

`ThreatMatch` wird nur aus Daten gebildet, die die App legitim hält (z. B. eigene TLS-Endpunkte
oder lokal gecachte Indikatoren). Eine systemweite Domain-/Prozess-Zuordnung wird ausdrücklich
nicht behauptet.

---

## 9. Report-Export

- `SecurityReport` ist selbsttragend: `reportId`, `generatedAtMillis`, pseudonyme `deviceId`,
  `scan` (vollständiges `ScanResult`), `evidence` (`EvidenceHealth`), `threatIntel`
  (`ThreatIntelStatus`). Der Renderer darf nur formatieren, was im Report steht.
- Formate: deutscher Text (`renderText` mit `TextCatalog`) und deterministisches JSON
  (`renderJson`, stabile Schlüsselreihenfolge, locale-unabhängige Zahlen; Schema
  `gedefense-tv-report/1`).
- **Primärer Exportweg:** SAF `ACTION_CREATE_DOCUMENT` pro Format (Text/JSON), über einen
  headless `Fragment`-Host; Dateinamen `GeDefense-TV-Report-<yyyyMMdd-HHmmss>.txt`/`.json` (UTC).
- **TV-Realität — Fallback ohne DocumentsUI:** Viele Android-TV-/Google-TV-Images besitzen keinen
  nutzbaren SAF-Picker oder lösen auf einen Framework-`DocumentsStub` auf. Der Exporter prüft den
  Handler (`resolveActivity`, Stub-Erkennung) und schreibt bei fehlendem Picker selbst:
  - API 29+: MediaStore-`Downloads/GeDefenseTV` (keine Storage-Permission),
  - API 26–28: `getExternalFilesDir(DIRECTORY_DOCUMENTS)/GeDefenseTV` (permission-frei).
- Inhalt: Score, Findings, Coverage/Sichtbarkeit, Evidenz-Gesundheit, Feed-Status,
  Scope/Limitations. **Keine** Tokens, Secrets oder rohen Paketlisten im JSON.
- Jeder Report weist Umfang und Einschränkungen der Prüfung aus (Datenblatt-Anforderung).

> **Belegt (Emulator 29.10.2026):** SAF-Stub erkannt → Fallback schrieb
> `/sdcard/Download/GeDefenseTV/GeDefense-TV-Report-20261029-103244.txt` (**30.246 B**) und
> `.json` (**4.562 B**, valides JSON) ohne Storage-Permission. Der Datei-Nachweis stammt aus
> 10:32 UTC; ein separater Export-Retest nach dem letzten Redesign ist nicht belegt. Eine
> vollständige inhaltliche Prüfung durch das Dokumentationsteam erfolgte stichprobenartig (keine
> Tokens/Secrets, pseudonyme Geräte-ID, Scope/Limitations enthalten).

---

## 10. Datenfluss (End-to-End)

```text
1) App-Start
   TvApplication.onCreate → TvServicesBootstrap.create
     ├─ Settings (SharedPreferences "gedefense_tv")
     ├─ Device-ID: "tv_" + 32 hex (SecureRandom), persistent pseudonym
     ├─ Keystore-Gate → EvidenceStore (oder UnavailableEvidenceStore)
     ├─ EvidenceLedger.open()/verify()
     └─ TV-UI-Shell (TvMainActivity)

2) Scan
   siehe §5; alle Collector-Ergebnisse → Scoring → Coverage → ScanResult
   → UI-Snapshot, Evidence-Record(s), lastScanAt + Scan-Zusammenfassung (Settings)

3) TI-Sync
   manuell/periodisch → Download (HTTPS) → Parse/Validierung → Cache
   → persistierter ThreatIntelStatus-Snapshot (O(1)-Anzeige)

4) Report
   ScanResult + EvidenceHealth + ThreatIntelStatus → SecurityReport
   → Text/JSON → SAF (primär) oder MediaStore-Fallback (Downloads/GeDefenseTV)

5) Restart/Force-Stop
   Home/Check rekonstruieren die letzte Scan-Zusammenfassung aus Settings und
   kennzeichnen sie ehrlich als „letzter Lauf“ (Details ggf. nicht im Speicher).

6) Löschen/Aufbewahrung
   EvidenceApi.clear() löscht die Ledger-Datei (im Recovery-Pfad auch den Keyring);
   automatische Retention/Rotation ist V2 und in V1 nicht aktiv.
```

Gespeicherte Daten (lokal): Settings, pseudonyme Device-ID, TI-Cache unter
`filesDir/threat-intel/`, Evidenz unter `noBackupFilesDir/evidence/`. Es gibt **keinen**
Telemetrie- oder Cloud-Pfad in V1.

---

## 11. Trust Boundaries (Kurzfassung, Details im Threat Model)

| Grenze | Verlauf | Bewertung |
| --- | --- | --- |
| App ↔ Android-APIs | normale App-Rechte, keine privilegierten APIs | fremde/OEM-abhängige Daten, keine Integritätsgarantie |
| App ↔ Netzwerk | ausgehend HTTPS zu öffentlichen TI-Feeds | fremde, potenziell bösartige Payloads → harte Parser-/Größenlimits |
| App ↔ andere Apps | PackageManager/Visibility, Signatur-Digests | Metadaten anderer Apps sind untrusted; Labels/Installer-Angaben fälschbar |
| App ↔ Nutzer/SAF | Report-Export in nutzergewählten Speicherort; Fallback schreibt in öffentliches `Downloads/GeDefenseTV` | Report kann geteilt/gefunden werden → keine Secrets, minimierte Inhalte; Fallback ist explizit nutzerinitiiert |
| App ↔ vendored Core | statische API, byte-identische Provenienz | Manipulation der Kopie muss durch Fidelity-Gate auffallen |
| Build ↔ Runtime | Gradle-Abhängigkeiten, Wrapper, Signatur | Supply-Chain-Punkt; keine Runtime-Drittdeps reduziert Angriffsfläche |

---

## 12. Performance-Budgets und Nebenläufigkeit

| Budget | Wert | Herkunft / Status |
| --- | --- | --- |
| Collector-Timeout | 12 s je Collector (hart) | `ScanEngineConfig` (festgelegt) |
| Collector-Anzahl je Lauf | ≤ 32 | `ScanEngineConfig` (festgelegt) |
| Scan-Threading | 1 Thread für Collectoren; Progress/Listener auf Main | Implementierungsplan |
| Dauer-Polling | **keines**; ereignis-/nutzer-/job-basiert | Designprinzip „Low overhead“ |
| TI-Parallelität | max. 3 Downloads | Implementierungsplan |
| TI-Abrufgrößen | 2–8 MiB je Feed, Eintragslimits s. Tabelle | Core `ThreatFeed` |
| TI-Frische | Refresh ≥ 15 min … 24 h je Feed; Stale ≤ 14 Tage | Core `ThreatFeed` |
| Evidenzgröße | 16 MiB Default (Core), Bounded-Recovery ≤ 8 KiB Manifest | `EvidenceLedger` |
| UI-Animation | Focus-Scale 1.02 in 140 ms, Eingang 220 ms, Banner-Fades | `TvTheme.MOTION_*`, `TvMainActivity` |
| Kaltstart (Debug, Emulator, Software-GPU) | `am start -W` TotalTime **1,81–2,29 s**; Bootstrap 191–261 ms; `navigate(HOME)` 118–135 ms; ~1,4 s Window/Theme/Inflate | Projektteam-Messung 29.10.2026 (Emulator-Anteil) |
| Startzeit reale TV-Hardware | kein Messwert | **NOT_TESTED** |
| CPU/RAM/Frame-Zeit | kein Messwert | **NOT_TESTED** |

Bewusst **nicht** verwendet: dauerhafte Hintergrundschleifen, aggressives Polling,
Backdrop-Blur-Rendering, WebView, 3D/Canvas-Dekoration.

---

## 13. Abhängigkeits- und Supply-Chain-Politik

1. **Null Runtime-Drittabhängigkeiten** in `:app` und `:tv-core`; `:core` bringt selbst keine
   Drittanbieter-Libraries mit.
2. **Kein AndroidX, kein Compose, keine externen UI- oder Netzwerkbibliotheken.** Netzwerkzugriff
   erfolgt über `HttpsURLConnection`/Plattform-APIs.
3. **Vendored Core** mit Byte-Fidelity-Gate und dokumentierter Provenienz; kein Patchen der Kopie.
4. **Build-Inputs** ausschließlich AGP/Kotlin/Gradle von `google()`/`mavenCentral()` (bzw.
   optionalem lokalem Mirror). Gradle-Wrapper-Distribution ist per SHA-256 gepinnt.
5. **SBOM:** [SBOM.cdx.json](SBOM.cdx.json) listet nur real existierende Komponenten (App, Core,
   TV-Core). Es werden keine Drittanbieter-Komponenten erfunden.
6. **Keine Runtime-CDN-/Font-/Icon-Abhängigkeiten** in der UI; keine Analytics-SDKs.
7. Kein `QUERY_ALL_PACKAGES`; nur gezielte `<queries>`-Deklarationen.

Restrisiken: Kompromittierung von Build-Plugins/Repositories, Geräte-OEM-Firmware,
öffentliche Feed-Anbieter (Verfügbarkeit/Inhalt), Release-Signaturprozess (siehe §2).

---

## 14. Architektur-Invarianten (verbindlich)

1. Eine sichtbare Aussage über „sauber/vollständig“ ist nur bei `DataVisibility.FULL` zulässig.
2. `NONE`/`PARTIAL`/`STALE` dürfen nie als grün/clean gerendert werden.
3. Jeder Score-Punkt ist auf eine `ruleId` + Evidenz zurückführbar.
4. V1 führt keine automatische Durchsetzung aus (`PolicyAction` ohne Enforcement-Pfad).
5. Benutzertexte kommen aus `MessageRef`-Katalogen; keine hartkodierten UI-Texte in der
   Domänenlogik.
6. Collector werfen keine untypisierten Fehler in die UI; Fehler werden zu `FAILED` + `errorKey`.
7. Evidenz ist append-only und fail-closed; keine stillen Reparaturen ohne Protokoll.
8. Vendored Core wird nie in-place verändert.
9. Keine Telemetrie, kein stiller Upload, keine systemweite Überwachungsbehauptung.

---

## 15. Offene Architekturpunkte

| Punkt | Status |
| --- | --- |
| Finaler RC-Rebuild (Debug+Release mit dokumentiertem Stand) | **offen**; Release-Pipeline bereits Exit 0, Artefakt davor gebaut |
| Reale TV-Hardware (≥ 2 OEM-Profile) | **NOT_TESTED** |
| Security-Review / VGT-Sicherheitsprofil-Vollaudit, Fuzz-/Negativtests | **NOT_TESTED** |
| Produktions-Release-Signatur | **Blocker**; Alpha-Artefakt ist debug-signiertes Testartefakt |
| Automatische Retention/Rotation | **V2**; in V1 nicht aktiv, Einstellung wird nicht als wirksam dargestellt |
| Launcher-Visual auf provisioniertem TV | **NOT_TESTED** (Intent + Banner-Ressource statisch belegt) |
| Periodisches TI-Sync-Intervall (`JobService`) | implementiert; Intervall/Doze-Verhalten **NOT_TESTED** |
| Event-Persistenz `TV_CONNECTIVITY_STATE`/`TV_SENSOR_HEALTH` | Contract-Sink derzeit nicht vorgesehen; Ablage als Evidenzzeile geplant, final zu bestätigen |
| Performance auf realer TV-Hardware | **NOT_TESTED** |

---

## 16. V2-Erweiterung: On-Device-Loopback-VPN, Traffic, XDR-Light (Planungsstand)

**Status:** Architektur/Planung 29.10.2026 · **Implementierung in Arbeit** ·
**Evidenz: NOT_TESTED** (keine V2-Builds/-Läufe). Vollständige Beschreibung:
[docs/V2-ARCHITECTURE.md](docs/V2-ARCHITECTURE.md).

V2 ergänzt die V1-App um einen eigenen lokalen Netzwerk-Datenpfad. Die V1-Architektur
(Collectors, Scoring, Evidenz, TI, Report) bleibt bestehen; V2 kommt als zusätzliche Schicht
hinzu und nutzt dieselbe Evidenz-/Privacy-/Ehrlichkeits-DNA.

### 16.1 Modulgraph (V2-Ergänzungen)

```text
:app
 ├─ vpn/        TvVpnService (FGS, VpnService, specialUse) · NativeGaiaNet-Bridge
 │              TvVpnController (Consent/Start/Stop/Auto-Start/Recovery)
 ├─ traffic/    TvFlowTelemetryReader · TvTrafficStore (TrafficApi)
 ├─ geo/        TvGeoRepository (Offline-IP→Land, Herkunft aus Locale/Netz)
 ├─ contract/   V2Contracts: VpnControlApi · TrafficApi · VpnStartResult · VpnStateListener
 └─ ui/         V2-Routen ONBOARDING/PROTECTION/TRAFFIC/XDR · Sir Quacksec · TI-Sync-Modal
:tv-core
 ├─ model/      Traffic.kt (TrafficSnapshot/TrafficFlow/AppTraffic/CountryTraffic/
 │              DomainTraffic/OriginInfo/TrafficAction) · Vpn.kt (VpnState/VpnStatus/
 │              TvPrivacyProfile)
 ├─ xdr/        TvXdrEngine (TV-Regeln, Korrelation, Dedupe) — in Arbeit
 └─ privacy/    TvPrivacyPolicy (Profile/Kategorien) — in Arbeit
:app/src/main/jniLibs/{arm64-v8a,x86_64}/libgedefense_gaianet_v2.so (vendorter Helper)
```

`TvServices` erweitert den Container um `vpn: VpnControlApi` und `traffic: TrafficApi`;
`Contracts.kt` ergänzt Settings (u. a. `vpnAutoStart`, `privacyProfile`,
`protectionSetupDone`, `detailedTelemetryEnabled`, `uiScale`).

### 16.2 Datenfluss und Fail-Closed

```text
Consent → TvVpnService (TUN) → GaiaNet-Helper (DNS/Flow/Policy)
   ├─ Threat-/Privacy-Policy → ALLOW/ANNOTATE/CORRELATE/BLOCK
   └─ Telemetrie (bounded) → TvFlowTelemetryReader → TvTrafficStore → TrafficApi/UI
                                   └→ TvXdrEngine → Evidenz
Helper-/Policy-Ausfall → DEGRADED/FAILED, TUN-Anker bleibt; kein stiller Bypass.
```

`VpnStatus.isProtecting` ist nur bei `ACTIVE`/`DEGRADED` wahr; die UI darf außerhalb dieser
Zustände keinen Schutz behaupten. Details zu Telemetrie-Modellen, Geo, Profilen und XDR:
[docs/V2-ARCHITECTURE.md](docs/V2-ARCHITECTURE.md) §4–§9.

### 16.3 Native Helper und Build

- `libgedefense_gaianet_v2.so` ist **byte-identisch** aus dem Mobile-Dossier
  (`0.28.0-beta1/Source/app/src/main/jniLibs`) übernommen; SHA-256 (Dokumentationsteam):
  arm64-v8a `d34fda6f…26fd15e`, x86_64 `9f393ce4…2975394f3`.
- `abiFilters = arm64-v8a, x86_64`; `jniLibs.useLegacyPackaging = true` (ausführbare Datei in
  `nativeLibraryDir`), damit der Helper als Kindprozess startbar ist; `keepDebugSymbols`.
- Kein Root, kein Export, kein JNI im Paket-Hot-Path; Control-Socket/Token/`SCM_RIGHTS` nach
  Mobile-Muster. Details/offene Punkte: [SECURITY.md](SECURITY.md) §9.

### 16.4 Performance-/Ressourcenbudgets (V2, geplant)

| Budget | Ziel/Festlegung | Status |
| --- | --- | --- |
| VPN-Start | schnell und ehrlich (`PREPARING`→`ACTIVE`/Fehler) | **NOT_TESTED** |
| Telemetrie | bounded (2…1024 B/Frame), keine Polling-Schleife | Modell/Design; **NOT_TESTED** |
| Traffic-Snapshot | Apps ≤ 200, Länder ≤ 64, Domains ≤ 200, Top-Listen ≤ 12 | Modell erzwungen |
| Karte | statisches Bild 2560×1280, keine Dauer-Animation | Design; Performance **NOT_TESTED** |
| Akku/Thermik | Messung auf Emulator + realem TV | **NOT_TESTED** |
| APK-Größe | + zwei Helper-Binaries (~7,5 MB unkomprimiert) | Build-Ergebnis **NOT_TESTED** |

### 16.5 V2-Invarianten

1. Kein „geschützt“ ohne `ACTIVE`/`DEGRADED`; keine „sauber“-Aussage bei eingeschränkter Sicht.
2. Keine Traffic-Inhalte, kein TLS-MITM, keine Cloud-Telemetrie.
3. Kein stiller Fail-Open; Policy-/Helper-Fehler werden sichtbar und konservativ behandelt.
4. Traffic-Metadaten bleiben lokal und begrenzt; Export nur Nutzeraktion, minimierte Felder.
5. Vendorte Binaries nur byte-identisch mit Hash-Nachweis; Abweichung = offener Punkt.
6. V2-UI bleibt D-Pad-vollständig, ehrlich und GLASS-2100-konform.
