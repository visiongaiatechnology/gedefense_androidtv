# GeDefense TV — Security

**Version:** 0.1.0-alpha1 · **Stand:** 29. Oktober 2026 · **Profil:** VGT-100 `GEDEFENSE` ·
**Modus:** Dokumentation/Sicherheitsdesign mit realer Build-/Lint-/Emulator-Evidenz, **kein**
durchgeführtes Voll-Audit · **Belegter Stand:** GOLD / PARTIAL_VERIFIED (Security-Review offen)

> **Ehrlichkeitshinweis vorab:** Dieses Dokument beschreibt das Sicherheitsdesign und bewertet
> Gates anhand real vorhandener Belege. Build (Debug/Release), Lint, JVM-Harnesse (`:tv-core`,
> `:core` auf Linux-JVM) und zentrale Emulator-Pfade (Scan, TI, Evidenz, Export-Fallback,
> Restart-Summary, D-Pad) sind belegt. Ein vollständiges VGT-100-Audit, ein unabhängiges
> Security-Review sowie reale TV-Hardware stehen **aus**. Es wird **kein** „100 Prüfungen
> bestanden“- oder DIAMANT-Status behauptet.

---

## 1. Sicherheitsdesign

### 1.1 Prinzipien

| Prinzip | Umsetzung |
| --- | --- |
| Least Privilege | Standardbetrieb nur `INTERNET` und `ACCESS_NETWORK_STATE`; kein `QUERY_ALL_PACKAGES`, keine Accessibility-, Overlay-, Kamera-, Mikrofon-, Standort- oder Storage-Berechtigung. V3/Titan ergänzt **keine** Manifest-Rechte; der optionale privilegierte Pfad ist ein nutzerbestätigter `su`-Kanal mit allow-listeten, reversiblen Kommandos (§15 ff.). |
| Honest Visibility | Jede Collector-Aussage trägt `CapabilityState` + `DataVisibility`; `NONE`/`PARTIAL`/`STALE` dürfen nie „clean/grün“ werden. |
| Observe before Enforce | V1 beobachtet und empfiehlt; `PolicyAction` ohne Durchsetzungspfad, keine automatischen Konfigurationsänderungen. |
| Fail-closed Evidenz | Ohne Schlüsselhohheit wird der Evidenz-Store unverfügbar (keine Health-Lüge, keine Writes). |
| Fail-fast Start | `TvApplication.onCreate` beendet den Prozess, wenn der Service-Bootstrap scheitert – keine halb verdrahtete Sicherheits-App. |
| Keine Telemetrie | Keine Analytics-/Crash-/Werbe-SDKs, kein stiller Upload, kein Remote-Control-Kanal. |
| Kein MITM | Keine TLS-Interception, kein installiertes CA, kein VPN-Datenpfad in V1. |
| Bounded Input | Größen-, Zeit-, Zeilen-, Eintrags- und Redirect-Limits für alle fremden Daten. |
| Keine Secrets im Klartext | Keine Schlüssel/Tokens im Code, keine Secrets in Logs, Keystore statt Dateien. |

### 1.2 Manifest- und Komponentenhärtung (statisch geprüft)

| Eigenschaft | Wert | Bewertung |
| --- | --- | --- |
| Berechtigungen | `android.permission.INTERNET`, `android.permission.ACCESS_NETWORK_STATE` | **PASS (statisch)** – minimal für Feed-Abruf/Netzwerkstatus |
| Backup | `android:allowBackup="false"`, `android:fullBackupContent="false"` | **PASS (statisch)** – keine Cloud-Sicherung lokaler Evidenz |
| Klartext | `android:usesCleartextTraffic="false"`, `@xml/network_security_config` | **PASS (statisch)** – `res/xml/network_security_config.xml` vorhanden: `cleartextTrafficPermitted="false"`, ausschließlich `system`-TrustAnchors (keine User-CAs) |
| Exported Activity | nur `TvMainActivity` (LEANBACK_LAUNCHER/LAUNCHER), `singleTask` | **PASS (statisch)** – kein Deep-Link-Intent-Filter |
| Exported Service | `TvThreatIntelJobService`, `android:permission="android.permission.BIND_JOB_SERVICE"` | **PASS (statisch)** – Bindung nur für System |
| Provider/Receiver | keine | **PASS (statisch)** |
| Debugging | kein `android:debuggable`; Release `isDebuggable=false` | **PASS (statisch)** |
| Release-Härtung | R8 `isMinifyEnabled`/`isShrinkResources`, Line-Number-Table, keine Reflection-Serialisierung | **PASS (Build)** – `assembleRelease` Exit 0; `app-release.apk` 6.522.110 B, R8-minifiziert, **Alpha-signiert** (CN=VisionGaiaTechnology GeDefense TV Alpha) |
| Lint | `abortOnError=true`, `checkReleaseBuilds=true` | **PASS** – `lintDebug` Exit 0, **0 Errors / 305 Warnings** (`dist/lint-results-debug.txt`; Anstieg durch Titan-/V3-Ressourcen und -Tests, keine Errors) |
| Backup-Regeln | `allowBackup="false"`, `fullBackupContent="false"`; Lint `DataExtractionRules` | **PASS (statisch)** mit Hinweis: Für Android 12+ wäre `android:dataExtractionRules` ergänzend sauberer (nicht sicherheitskritisch bei `allowBackup=false`) |

### 1.3 Kryptografie und Evidenz

| Baustein | Design | Status |
| --- | --- | --- |
| Evidenz-Integrität | HMAC-SHA-256-Kette über append-only Records (Sequence + Prev-Hash), `EvidenceLedger` v3 | **Emulator-belegt:** Ledger „gesund“, 40 Einträge, 32 Zeilen (19.169 B) |
| Evidenz-Vertraulichkeit | AES-256-GCM pro Record (`EvidencePayloadProtector`), 96-bit Nonce, 128-bit Tag, AAD bindet Sequenz + Zeitstempel | implementiert; **NOT_TESTED** (kein Tamper-Test) |
| Schlüsselhohheit | `TvKeyCustody`: AndroidKeyStore AES-256-GCM KEK (`vgt.gedefense.tv.evidence.kek.v1`, StrongBox versucht) wrappt 256-bit-Zufallsroot in `no_backup/evidence/keyring.v1`; domain-separierte Software-Subkeys `evidence-hmac-v1`, `evidence-aes-v1`, `threatintel-hmac-v1` (SHA-256(root‖label), nur im Prozess) | **Emulator-belegt:** `keyring.v1` 61 B, Ledger gesund; Hardware-Backing wird **nicht** behauptet |
| Alt-Ledger-Behandlung | Unverifizierbares Legacy-Ledger wird nach `no_backup/evidence/legacy/` archiviert statt still gelöscht; bei bestehendem Keyring gilt ungesundes Ledger als Tamper-Indiz | **Emulator-belegt:** Legacy-Archiv 14.375 B |
| Opaque-/Provider-Keys | `AndroidKeystoreGate`/`BoundedSecretKeyCrypto`: Admission-Lock, Timeout, Circuit-Breaker; Software-Subkeys vermeiden den Single-Slot-Executor im Record-Pfad | implementiert; **NOT_TESTED** (adversarial) |
| Zufall | `SecureRandom` für Device-ID/Root/Nonces | implementiert; **NOT_TESTED** |
| Feed-Transport | HTTPS-only (`ThreatFeed` erzwingt Schema/Host, kein User-Info/Fragment) | **PASS (statisch, Core)** |
| Feed-Integrität | keine kryptografischen Feed-Signaturen; Abhängigkeit von TLS + Anbieter | **GAP** (VGT-058 offen) |
| Cache-Integrität | HMAC-authentifizierte Generationen mit Keyring-Subkey (`threatintel-hmac-v1`) | implementiert; Emulator TI 9/9; adversarial **NOT_TESTED** |
| TLS-Pinning | **nicht** umgesetzt (System-TrustStore, keine User-CAs) | bewusst; Restrisiko dokumentiert |
| Keine Hardcoded Keys | Secret-Muster-Grep ohne Treffer; Keyring/Root ausschließlich generiert und Keystore-gewrappt | **PASS (begrenzt, Grep+Design)** |

**Fail-closed-Verhalten:** Kann die Evidenz-Schlüsselhohheit nicht etabliert werden, liefert
`UnavailableEvidenceStore` `healthy=false` mit Fehlercode und akzeptiert keine Writes. Die App
bleibt nutzbar, aber ohne Evidenzfunktion – sie täuscht keine Intaktheit vor.

### 1.4 Netzwerk- und Parser-Härtung (TI)

| Kontrolle | Wert/Regel | Status |
| --- | --- | --- |
| Schema | ausschließlich `https`, Host erforderlich, kein User-Info/Fragment | Core **PASS (statisch)** |
| Redirects | max. 2 manuelle Hops, jeweils same-host; kein automatisches Folgen | implementiert (`TvFeedDownloader.MAX_REDIRECTS = 2`); **NOT_TESTED** |
| Größe | Streaming-Limit + `Content-Length`-Prüfung, `maxDownloadBytes` 2–8 MiB je Feed | implementiert; **NOT_TESTED** |
| Zeilenlänge | 8 KiB Limit (Scan-Chunk 16 KiB) | implementiert; **NOT_TESTED** |
| Content-Type | Aushandlung auf `text/plain`/`application/json`/`application/octet-stream`; HTML wird nicht als Feed akzeptiert | implementiert; **NOT_TESTED** |
| Timeouts | Connect 10 s / Read 15 s | implementiert (`CONNECT_TIMEOUT_MS`, `READ_TIMEOUT_MS`); **NOT_TESTED** |
| Parallelität | max. 3 Downloads, fester Thread-Pool | implementiert (`MAX_PARALLEL_DOWNLOADS = 3`); **NOT_TESTED** |
| Einträge | harte Kataloglimits 20 000–150 000, `truncated` wird signalisiert | Core-Parser vorhanden – **NOT_TESTED** |
| Cache | max. 2 Generationen je Feed, HMAC-authentifiziert über Keyring-Subkey `threatintel-hmac-v1`, Clock-Skew 10 min | implementiert; Emulator TI 9/9 – adversarial **NOT_TESTED** |
| Proxy | `Proxy.NO_PROXY` (kein System-Proxy) | implementiert; **NOT_TESTED** |
| TrustAnchors | nur System-CAs; keine nutzerinstallierten CAs (kein lokales MITM-Zertifikat) | **PASS (statisch)** |
| Export primär | SAF `ACTION_CREATE_DOCUMENT` pro Format; Nutzer wählt Ziel | implementiert; Picker auf TV-Images oft nicht verfügbar |
| Export-Fallback | Erkennung von fehlendem DocumentsUI/Framework-Stub; MediaStore `Downloads/GeDefenseTV` (API 29+) bzw. app-spezifisches Dokumentverzeichnis (API 26–28), keine Storage-Permission | **Emulator-belegt:** 30.246 B Text + 4.562 B JSON, valides JSON |
| Export-Inhalt | keine Tokens/Secrets/rohen Paketlisten; pseudonyme Geräte-ID; Scope/Limitations | stichprobenartig geprüft (**PASS begrenzt**) |
| Export-Restrisiko | Fallback schreibt in öffentliches `Downloads`; Datei bleibt nach App-Löschung bestehen | dokumentiert, Nutzer muss selbst löschen |

### 1.5 Datenhaltung und Aufbewahrung

- Evidenz: `noBackupFilesDir/evidence/events.v3.log`, max. 16 MiB (Core-Default).
- TI-Cache: `filesDir/threat-intel/`, Generationen begrenzt.
- Settings/Device-ID: `SharedPreferences "gedefense_tv"`.
- **Aufbewahrung:** bis zur manuellen Löschung (`EvidenceApi.clear()` bzw. App-Daten
  löschen/deinstallieren). Automatische Retention/Rotation ist **V2** und in V1 **nicht aktiv**;
  `retentionDays` wird nicht als wirksame Automatik dargestellt (kein Fake-Control).
  → Bekannte, dokumentierte Produktgrenze (VGT-029).

---

## 2. Statische Sicherheitsbefunde

| ID | Befund | Schwere | Status |
| --- | --- | --- | --- |
| F-01 | Release-Signatur: Der frühere Debug-Key-Fallback ist **aus dem Code entfernt** (nur noch `signingConfig = signingConfigs.findByName("release")`; fehlende `GEDEFENSE_RELEASE_*`-Konfiguration erzeugt kein debug-signiertes Release). Das 0.3.0-alpha1-Release ist mit einem **Alpha-Zertifikat** signiert (CN=VisionGaiaTechnology GeDefense TV Alpha, nicht Debug-Key). | **mittel-hoch (Produktions-Blocker)** | **PARTIAL** – Kein Debug-Key mehr; ein **Produktions-/Upload-Zertifikat** und Signatur-Policy sind weiterhin offen. |
| F-02 | `core/PROVENANCE.md` liegt in `core/`, ist aber nicht Teil von `SOURCE-MANIFEST.sha256` (dokumentierte TV-Ausnahme). Fidelity-Skript behandelt sie als bewusste Ausnahme. | niedrig (Prozess) | dokumentiert; Lead-Entscheidung zur Ablage offen |
| F-03 | Automatische Retention fehlt in V1 (`retentionDays` vorhanden, aber nicht wirksam) | mittel (Datenschutz) | **DEFERRED (V2)**, dokumentiert; Einstellung darf nicht als wirksam dargestellt werden |
| F-04 | `@xml/network_security_config` | **behoben (statisch)** | Ressource existiert: `cleartextTrafficPermitted="false"`, nur System-TrustAnchors; kein User-CA-Vertrauen. |
| F-05 | Öffentliche Feeds ohne Signatur; TLS schützt Transport, nicht Inhalt | mittel | **GAP**, akzeptiert mit Restrisiko |
| F-06 | Git-Repository vorhanden (`master`, Baseline-Commit `fe555cd`); Teammate-Arbeit zum Doku-Zeitpunkt uncommitted; kein reproduzierbarer Byte-Build belegt | Prozess | **PARTIAL** – Provenienz über Commit erst nach RC-Commit vollständig |
| F-07 | Keine Fuzz-/Negativtests der Parser/JSON-/Feed-Pfade | mittel | **NOT_TESTED** |
| F-08 | Lint: **0 Errors / 305 Warnings** (`dist/lint-results-debug.txt`, V3-Stand; Anstieg durch Titan-/V3-Ressourcen/-Tests); `warningsAsErrors=false`, `abortOnError=true` | niedrig | akzeptiert für Alpha; Warnungen dokumentiert, keine Errors |
| F-09 | Umgebung: cmdline-tools `23.0.0`; `sdkmanager --list` endet nach Ausgabe abnorm (`-1073740791`) | niedrig | dokumentiert im Emulator-Guide |
| F-10 | Fokusring-Token: `TvTheme.FOCUS_STROKE_DP = 4` == `dimens.xml tv_focus_stroke = 4dp` | niedrig | **behoben/aligned** |
| F-11 | Export-Fallback schreibt bei fehlendem SAF-Picker nach öffentlichem `Downloads/GeDefenseTV` (API 29+). Datei bleibt außerhalb der App-Verwaltung und wird bei `clear()`/Deinstallation nicht gelöscht. | niedrig-mittel (Vertraulichkeit) | dokumentiert; Inhalt minimiert (keine Secrets), Nutzer-initiiert; Löschhinweis in Doku |
| F-12 | Unabhängiges Security-Review / VGT-100-Vollaudit steht aus; Lint ist kein Security-Scan | mittel | **offen (Release-Blocker für Produktion)** |
| F-13 | Lint `QueryPermissionsNeeded` (2 Warnungen) betrifft `getInstalledPackages` – erwartete Package-Visibility-Grenze, durch `PARTIAL`-Modell abgedeckt | niedrig | akzeptiert, in UI/Report ehrlich ausgewiesen |

---

## 3. Security-Gates — Status

Bewertung nach VGT-Gate-Reihenfolge. **PASS** nur mit realem Beleg; **NOT_TESTED** ohne Lauf;
**FAIL/OFFEN** für erkannte Lücken.

| # | Gate | Status | Beleg / Lücke |
| --- | --- | --- | --- |
| 1 | Source Identity + Scope + Dirty-Baseline | **PARTIAL** | Git-Repo `master`, Baseline `fe555cd`; Version/Dateien konsistent; Teammate-Arbeit vor RC-Commit uncommitted |
| 2 | Architekturpfad + Trust Boundaries | **PASS** | [ARCHITECTURE.md](ARCHITECTURE.md), [THREAT-MODEL.md](THREAT-MODEL.md); Codebasis gebaut und auf Emulator getestet |
| 3 | Syntax/Typen/Lint | **PASS** | `compileDebugKotlin` Exit 0; `lintDebug` Exit 0, **0 Errors / 305 Warnings** (V3-Stand, `dist/lint-results-debug.txt`) |
| 4 | Unit/Integration/Negative/Edgecases | **PASS (PARTIAL)** | `:tv-core:tvCoreCheck` Exit 0 (554/0, 35 Tests); `tvTitanCheck` Exit 0 (**6624/0, 17 Tests**), Regression tvV2Check 4398/0, tvKineticCheck 3025/0 in einem Lauf Exit 0; `:core:coreCheck` Linux-JVM Exit 0 (Win32 BLOCKED); Emulator-Funktionstests PASS/PARTIAL; App-Unit-Tests / Fuzz / Adversarial **NOT_TESTED** |
| 5 | Security Fusion + VGT-100 | **PARTIAL** | Profil-Mapping (§5) + statische Manifest-/Secret-Prüfung + Emulator-Evidenz; kein Vollaudit/Review |
| 6 | Persistenz/Migration/Rollback/Fehlerzustände | **PARTIAL** | Ledger gesund (40 Einträge), Keyring/Alt-Archiv belegt, Restart-Summary belegt; Tamper-/Fail-closed-Test **NOT_TESTED** |
| 7 | Performance | **PASS (Emulator)** | Kaltstart 1,81–2,29 s, Bootstrap 191–261 ms, `navigate(HOME)` 118–135 ms; TI-Status O(1) (vorher 4.519 ms); reale TV-Hardware **NOT_TESTED** |
| 8 | UX / GLASS 2100 / A11y | **PASS (Emulator)** | Screenshots 80–97 (1080p), D-Pad-Pfad, kein Touch-Zwang, Fokus sichtbar, Status Glyph+Label, Text Weiß-Familie (≥ 4,5:1); reale TV-Hardware **NOT_TESTED** |
| 9 | Build/Release-Artefakt | **PASS (Alpha-Release) / BLOCKED (Produktion)** | Debug/Release Exit 0; Debug-APK 8.811.121 B; Release-APK 6.522.110 B (SHA-256 `da4110…f2934`), **Alpha-signiert** (CN=VisionGaiaTechnology GeDefense TV Alpha, nicht Debug-Key), auf Emulator gestartet; Produktions-/Upload-Signatur offen (F-01) |
| 10 | Next.md/Handoff | **Lead-owned** | `Next.md` mit Checkpoints 001–003 vorhanden; nicht Teil dieses Tasks |

**Release-Gate-Urteil: BLOCKED für Produktion, RC-Kandidat GOLD / PARTIAL_VERIFIED.** Gründe:
Produktions-/Upload-Signatur fehlt (Alpha-Zertifikat, F-01), unabhängiges Security-Review/
Fuzz-Tests offen (F-07/F-12), reale TV-Hardware **NOT_TESTED**, Sicherheits-Meldeweg und
Datenschutzerklärung offen. Die fehlende Retention-Automatik ist **kein** Produktions-Blocker,
sondern eine bewusst auf V2 verschobene Produktgrenze.

---

## 4. Sicherheits-Meldeweg (Responsible Disclosure)

- Ein **öffentlicher** Meldeweg (Security-Policy, dedizierte Mailadresse, PGP-Key) ist im
  Projekt noch **nicht festgelegt**. Dieser Zustand ist bewusst dokumentiert und keine stille
  Auslassung.
- Bis zur Festlegung gilt: Sicherheitsbefunde **nicht** in öffentlichen Issues/Tickets posten,
  sondern über den internen VGT-Projektkanal an die Projektleitung melden.
- Als Meldeinhalte hilfreich: betroffene Version/Build, Gerät/API-Level, Reproduktionsschritte,
  erwartetes vs. beobachtetes Verhalten, relevante Logauszüge **ohne** personenbezogene Daten.
- Es existiert kein Bug-Bounty-Programm; es werden keine Prämien zugesagt.

---

## 5. VGT-100-Profil-Mapping (Summary, kein Vollaudit)

Profil `GEDEFENSE`, Scope: TV-App inkl. vendored Core. Statuslegende:
`PASS` = real belegt (Build/Emulator/statisch/Design), `NOT_TESTED` = vorgesehen, aber nicht
geprüft, `GAP` = Kontrolle fehlt, `N/A` = für diese Architektur nicht anwendbar.
**Diese Tabelle ersetzt keinen Audit-Bericht; die 100 IDs wurden nicht einzeln tiefen-geprüft.**

| ID | Grenze | Status | Kurzbegründung |
| --- | --- | --- | --- |
| VGT-001 | Asset-/Vertrauensgrenzeninventar | **PASS** | [THREAT-MODEL.md](THREAT-MODEL.md) §2–3 |
| VGT-002 | Deny-by-default für sensible Operationen | **PASS (Design)** | Export nur nutzerinitiiert, kein Auto-Enforcement, fail-fast Start |
| VGT-003 | Objektbezogene Zugriffskontrolle | **N/A** | Keine Multi-User-/Objekt-API |
| VGT-004 | Funktionsbezogene Berechtigungen | **PASS (statisch)** | Minimale Permissions, keine privilegierten Rollen |
| VGT-005 | Feldebene/Mass Assignment | **NOT_TESTED** | Settings/SAF-Pfade ungetestet |
| VGT-006 | Sitzungs-/Tokenlebenszyklus | **N/A** | Keine Authentisierung/Sitzungen |
| VGT-007 | MFA/Recovery | **N/A** | Kein Konto |
| VGT-008 | Mandanten-/Editionsisolation | **N/A** | Ein Produkt, eine Edition |
| VGT-009 | Service-zu-Service-Vertrauen | **N/A** | Keine Backend-Services |
| VGT-010 | Privilegieneskalation/Confused Deputy | **NOT_TESTED** | Exported Service statisch geprüft, keine dynamische Prüfung |
| VGT-011–014 | Injection/XSS/Template | **N/A** | Kein SQL/Shell/HTML/DOM-Sink in der App |
| VGT-015 | Path Traversal | **NOT_TESTED** | Private Pfade + Core-Helfer; App-Nutzung ungeprüft |
| VGT-016 | TOCTOU/Symlink-Races | **NOT_TESTED** | `DurableAtomicFiles` vorhanden; App-Nutzung ungeprüft |
| VGT-017 | Unsichere Deserialisierung | **PASS (Design)** | Nur eigener Format-Parser, JSONL-Decode→null; keine Java-Serialisierung |
| VGT-018 | Archive/ZIP-Slip | **N/A** | Keine Archive |
| VGT-019 | Datei-Uploads | **N/A** | Kein Upload |
| VGT-020 | Ressourcenlimits Parser | **PASS (Design)** | Größen-/Zeilen-/Eintragslimits in Core/Downloader; **NOT_TESTED** |
| VGT-021 | Krypto-Algorithmen/Modi | **PASS (Design)** | AES-256-GCM, HMAC-SHA-256, SecureRandom; keine schwachen Modi |
| VGT-022 | Schlüsselverwaltung/Rotation | **PASS (Design + Emulator)** | `TvKeyCustody`: Keystore-gewrappter 256-bit-Root, domain-separierte Subkeys, `keyring.v1` belegt; formale Rotation/adversarialer Test offen |
| VGT-023 | Passwort-Hashing/Secrets | **PASS (begrenzt)** | Keine Passwörter/Secrets im Code (Grep); kein vollständiges Audit |
| VGT-024 | Transportverschlüsselung | **PASS (statisch)** | HTTPS-only-Feeds, `usesCleartextTraffic=false`; Cert-Gültigkeit über Plattform |
| VGT-025 | Signaturen/Anti-Rollback | **GAP** | Keine Feed-Signaturen; APK-Signatur abhängig vom Release-Prozess |
| VGT-026 | Zufall/Nonce/Entropie | **PASS (Design + Emulator)** | `SecureRandom` für Device-ID/Root/Nonces; Keyring/Ledger funktionieren im Emulator |
| VGT-027 | Datenminimierung/Klassifikation | **PASS** | [PRIVACY.md](PRIVACY.md), minimale Permissions, kein Upload |
| VGT-028 | Schutz ruhender Daten | **PARTIAL** | AES-GCM-Evidenz + noBackup; Emulator-Ledger gesund; Tamper-Test offen |
| VGT-029 | Löschung/Aufbewahrung/Recovery | **DEFERRED (V2)** | Automatische Retention in V1 nicht aktiv (dokumentiert, kein Fake-Control); manuelle Löschung und Core-Recovery vorhanden |
| VGT-030 | Error-/Log-Leakage | **PASS (Design)** | UI nutzt `MessageRef`/errorKey statt roher Exceptions; Runtime **NOT_TESTED** |
| VGT-031–032 | CSRF/CORS/Web-Header | **N/A** | Keine Web-Oberfläche |
| VGT-033 | SSRF/Redirect-Ketten | **NOT_TESTED** | max. 2 same-host Redirects geplant; kein Test |
| VGT-034 | Open Redirect/URL-Schemata | **PASS (Design)** | Feed-URLs fix im Katalog, HTTPS erzwungen |
| VGT-035 | API-Inventar/Versionierung | **PARTIAL** | Interne Contract-Interfaces dokumentiert; kein externes API |
| VGT-036 | GraphQL/gRPC/WebSocket | **N/A** | Nicht verwendet |
| VGT-037 | Business-Flow-Missbrauch | **NOT_TESTED** | Scan-/Sync-Serien ungetestet |
| VGT-038 | Rate Limits/Missbrauch | **PARTIAL** | Refresh-Budgets, max. 3 parallele Downloads; kein serverseitiger Missbrauch |
| VGT-039 | Cache/CDN/Partitionierung | **N/A** | Kein CDN/Shared-Cache |
| VGT-040 | Webhooks/externe Integrationen | **N/A** | Keine |
| VGT-041 | Least Privilege OS | **PASS (statisch)** | Minimale Permissions; keine privilegierten APIs |
| VGT-042 | Sandbox-/Prozessisolierung | **PASS (Plattform)** | Normale App-Sandbox; kein eigener Prozess |
| VGT-043 | IPC-/Localhost-Authentisierung | **N/A** | Kein IPC/Localhost |
| VGT-044 | Netzwerkausgang/Ost-West | **PARTIAL** | Nur ausgehende HTTPS-Feeds; kein Flow-Monitor |
| VGT-045 | Service-Bindings/Exposition | **PASS (statisch)** | Nur JobService mit BIND_JOB_SERVICE |
| VGT-046 | Container-/Build-Isolation | **N/A** | Kein Container |
| VGT-047 | Cloud-IAM/Metadata | **N/A** | Kein Cloud-Compute |
| VGT-048 | DNS/TLS/Reverse-Proxy-Trust | **PASS (statisch)** | System-TrustAnchors only, keine User-CAs, kein Pinning (bewusst), kein Proxy |
| VGT-049 | Filesystem-Permissions/Tempfiles | **PARTIAL** | Private Verzeichnisse, Keyring/Ledger nur `no_backup`, Atomic Files; Emulator-Dateirechte belegt; adversarialer Symlink/TOCTOU-Test offen |
| VGT-050 | OS-Sicherheitsdefaults/Portabilität | **PARTIAL** | Android-Defaults, `minSdk 26`; keine OEM-Verifikation |
| VGT-051 | Dependency-Inventar/SBOM | **PASS** | [SBOM.cdx.json](SBOM.cdx.json), keine Runtime-Drittdeps |
| VGT-052 | CVE-/KEV-Triage | **N/A (Produkt)** | Keine Drittdeps; Patch-Kontext nur Anzeige |
| VGT-053 | Dependency Confusion/Typosquatting | **PASS (begrenzt)** | Keine Drittdeps zur Laufzeit; Build-Plugins von offiziellen Repos |
| VGT-054 | CI/CD-Secrets/Workflow-Rechte | **N/A / NOT_TESTED** | Keine CI-Konfiguration im Projekt |
| VGT-055 | Build-Provenance/Reproduzierbarkeit | **PARTIAL** | Git-Baseline `fe555cd`, Wrapper-SHA-256, Core-Manifest; reproduzierbarer Byte-Build und RC-Commit offen |
| VGT-056 | Code-Signing/Release-Artefakte | **PARTIAL** | Debug-Key-Fallback aus dem Code entfernt; Release mit Alpha-Zertifikat signiert — Produktions-/Upload-Zertifikat weiterhin **GAP** (F-01) |
| VGT-057 | Updater-Authentizität | **N/A** | Kein eigener Updater (Store-/Sideload-Update) |
| VGT-058 | Signierte Threat Feeds/Policy | **GAP** | Feeds nur TLS-geschützt, nicht signiert |
| VGT-059 | Release-Kanal-/Editionsisolation | **N/A** | Ein Kanal in 0.1.0-alpha1 |
| VGT-060 | Supply-Chain-Incident/Key-Rotation | **NOT_TESTED** | Kein Prozess dokumentiert |
| VGT-061 | Fail-Secure State Machine | **PASS (Design + Emulator)** | `UnavailableEvidenceStore`, fail-fast Start, `ScanState.FAILED`; Alt-Ledger archiviert statt verworfen; adversariale Custody-Fehler nicht getestet |
| VGT-062 | Transaktions-/Datenintegrität | **PARTIAL** | Atomic Files/HMAC-Kette; Emulator-Ledger gesund; Tamper-Test offen |
| VGT-063 | Race Conditions | **PARTIAL** | Single-Scan-Lock, 1-Thread-Executor; JVM-Tests decken Cancel/Failure ab; Thread-Race-Adversarialtest offen |
| VGT-064 | DoS/Backpressure | **PASS (Design)** | Bounded Pools/Limits; Lasttest **NOT_TESTED** |
| VGT-065 | Retry-Stürme/Abhängigkeitsausfall | **PARTIAL** | Refresh-Budgets; kein Retry-/Offline-Test |
| VGT-066 | Konfigurationsintegrität/Defaults | **PASS (Design)** | Sichere Defaults (kein Auto-Sync, Retention V2/ohne Scheinregler); Runtime teils belegt |
| VGT-067 | Rollback-/Recovery-Integrität | **PARTIAL** | Keyring-/Ledger-Recovery implementiert (Legacy-Archiv); gezielter Recovery-Test offen |
| VGT-068 | Offline/Airgap | **PASS (Design)** | Letzter Feed bleibt nutzbar, Stale-Status; Offline-Szenario **NOT_TESTED** |
| VGT-069 | Uhrzeit/Ablauf/Replay | **PARTIAL** | Plausibilitäts-/Skew-Regeln; kein Replay-Schutz nötig (keine Transaktionen) |
| VGT-070 | Ressourcenerschöpfung Sekundärsysteme | **PARTIAL** | Ledger-/Cache-Limits; kein Lasttest |
| VGT-071 | Security-Event-Vollständigkeit | **PARTIAL** | Event-Schema + 7 Klassen; 32 Evidenz-Einträge im Emulator; Persistenzpfad z. T. offen |
| VGT-072 | Logintegrität/-vertraulichkeit | **PARTIAL** | HMAC/AES-Evidenz, Emulator „gesund“, keine externen Logs; Tamper-Test offen |
| VGT-073 | Alert-Lifecycle/Entdoppelung | **NOT_TESTED** | Finding-Identität deterministisch; Lifecycle ungeprüft |
| VGT-074 | Detection Evasion/Normalization | **NOT_TESTED** | Kein adversarialer Test |
| VGT-075 | Quarantäne/Autopunisher | **N/A** | Keine Durchsetzung in V1 |
| VGT-076 | Threat-Feed-Freshness/Herkunft | **PASS (Design)** | Quelle, fetchedAt, fresh/stale, Attribution im Katalog |
| VGT-077 | Control-Plane-/Agent-Vertrauen | **N/A** | Kein Agent/Backend |
| VGT-078 | Admin-Dashboard/Telemetrie | **N/A** | Kein Dashboard/Telemetrie |
| VGT-079 | Incident-Response-Readiness | **PARTIAL** | Report/Evidenz vorhanden; Prozess nicht definiert |
| VGT-080 | False-Positive/-Negative-Bilanz | **NOT_TESTED** | Keine Messung |
| VGT-081–082 | WordPress | **N/A** | Nicht WordPress |
| VGT-083 | Desktop-IPC/Webviews | **N/A** | Kein WebView/IPC |
| VGT-084 | Lokale Dokumente/Office | **N/A** | Keine Dokumentverarbeitung |
| VGT-085 | Mobile-Stores/Berechtigungen | **PASS (statisch)** | Minimale Permissions, keine gefährlichen Gruppen; Store-Policy-Prüfung offen |
| VGT-086 | Plugin-/Erweiterungsarchitektur | **N/A** | Keine Plugins |
| VGT-087–089 | KI-Prompt/Output/Modell | **N/A** | Keine KI im Produkt |
| VGT-090 | A11y-/UX-Sicherheits-Bypass | **PASS (Emulator)** | D-Pad-vollständig, Fokus sichtbar, keine Touch-Abhängigkeit, Status Glyph+Label (Screenshots 80–97); reale TV-Hardware offen |
| VGT-091 | Cross-Component Attack-Path-Graph | **PARTIAL** | Chain-Skizzen C-01…C-04 im Threat Model |
| VGT-092 | Combination Bugs/Preconditions | **NOT_TESTED** | Keine systematische Kombinationsprüfung |
| VGT-093 | Privilege/Integrity Pivot | **NOT_TESTED** | Keine privilegierten Pfade vorhanden, aber nicht adversarial geprüft |
| VGT-094 | Cross-Layer Input Transformation | **NOT_TESTED** | Feed→Parser→Event→Report-Kette ungetestet |
| VGT-095 | Patch-Vollständigkeit/Root Cause | **N/A** | Kein Patch-Auftrag |
| VGT-096 | Negative/Property-/Fuzz-Tests | **NOT_TESTED** | Keine Fuzz-/Propertytests vorhanden |
| VGT-097 | SAST/DAST/SCA-Fundabgleich | **PARTIAL** | Lint (0 Errors/305 Warnings) als statischer Check; kein SAST/DAST/SCA-Tool gelaufen |
| VGT-098 | Performance-/Availability-Regression | **PARTIAL** | Kaltstart 1,81–2,29 s, TI-Status O(1) im Emulator gemessen; reale TV-Hardware/Regressionstest offen |
| VGT-099 | Release-Blocker/Risk Acceptance | **PASS (dieses Dokument)** | Release-Gate BLOCKED, Restrisiken §6 dokumentiert |
| VGT-100 | Langfristige Security-Regressionsbasis | **PARTIAL** | Test-Plan + Fidelity-Gate + Doku als Basis; CI/Regressionstests fehlen |

**Zählung der Summary:** 100 IDs wurden auf Anwendbarkeit geprüft; `PASS` nur für real belegte/
design-erzwungene Kontrollen, `GAP` für VGT-025/056/058, `DEFERRED` für VGT-029, überwiegend
`PARTIAL`/`NOT_TESTED`/`N/A`. Damit wird ausdrücklich **kein** vollständiger Audit-Status
beansprucht. Der belegte Gesamtstand ist **GOLD / PARTIAL_VERIFIED**, nicht PLATIN oder DIAMANT.

---

## 6. Restrisiken und Release-Blocker (Kurzliste)

| ID | Risiko | Einstufung | Nächster Schritt |
| --- | --- | --- | --- |
| R-01 | Reale TV-Hardware fehlt | **Produktions-Blocker** | ≥ 2 reale TV-Profile testen (RC-Rebuild 0.3.0-alpha1 vorhanden) |
| R-02 | Release-Signatur (F-01) | **Produktions-Blocker** | Debug-Key-Fallback entfernt, Release mit Alpha-Zertifikat signiert; Produktions-/Upload-Signatur und Signatur-Policy fehlen |
| R-03 | Feeds ohne Signatur (F-05) | mittel | Signatur-/Digest-Pinning oder dokumentierte Risikoübernahme |
| R-04 | Retention-Automatik fehlt (F-03) | niedrig-mittel | **V2**; bis dahin nicht als wirksam darstellen, manuelle Löschung dokumentieren |
| R-05 | Keine Fuzz-/Negativtests (F-07) | mittel | Parser-/Event-/Report-Pfade fuzzen |
| R-06 | Build-Provenance: Teammate-Arbeit uncommitted | mittel | RC-Commit + reproduzierbarer Build |
| R-07 | Visuelle/A11y-QA auf realer Hardware | mittel | Emulator-Nachweis vorhanden; reale TV-Screenshots/Contrast-Check nachholen |
| R-08 | Sicherheits-Meldeweg fehlt | niedrig-mittel | Policy/Adresse festlegen (Produktions-Blocker) |
| R-09 | Export-Fallback in öffentlichem Downloads (F-11) | niedrig-mittel | Nutzerhinweis/Löschkonzept; optional SAF-only auf zertifizierten TV-Geräten |
| R-10 | Unabhängiges Security-Review offen (F-12) | **Produktions-Blocker** | Read-only-Titan-Audit ohne Blocker vorhanden; VGT-100-Vollaudit/Laufzeitprüfung vor Freigabe |

---

## 7. Verhältnis zu anderen Dokumenten

- Architektur und Trust Boundaries: [ARCHITECTURE.md](ARCHITECTURE.md)
- Bedrohungen, STRIDE, TV-Risiken: [THREAT-MODEL.md](THREAT-MODEL.md)
- Datenschutz/Telemetrie: [PRIVACY.md](PRIVACY.md), [DATA-SAFETY.md](DATA-SAFETY.md)
- Abnahme/Evidenz: [TEST-PLAN.md](TEST-PLAN.md)

---

# V2-Sicherheit: On-Device-Loopback-VPN, Traffic, XDR-Light

**Status:** Planungsstand 29.10.2026 · **Evidenz: NOT_TESTED** (V2-Implementierung in Arbeit;
keine V2-Builds/-Läufe). V2-Architektur: [docs/V2-ARCHITECTURE.md](docs/V2-ARCHITECTURE.md).

## 8. V2-Berechtigungen und -Deklarationen

| Berechtigung/Deklaration | Zweck | Begründung / Grenze |
| --- | --- | --- |
| `FOREGROUND_SERVICE` | VPN-Dienst läuft als Vordergrunddienst | notwendig für dauerhaften `VpnService` |
| `FOREGROUND_SERVICE_SPECIAL_USE` | targetSdk 36 verlangt deklarierten FGS-Typ | Subtyp-Property beschreibt „Local loopback VPN … no external server“; **Play-Deklaration erforderlich** |
| Service-Permission `BIND_VPN_SERVICE` | Schutz vor fremdem Binden an `TvVpnService` | System bindet als VPN-Owner; andere Apps nicht |
| `POST_NOTIFICATIONS` | FGS-Benachrichtigung sichtbar | nur Statusanzeige, kein Werbe-/Push-Kanal |
| `VpnService`-Intent-Filter + `SUPPORTS_ALWAYS_ON=true` | System-VPN-Integration, Always-On-Unterstützung | kein Root/System-App-Recht |
| **unverändert nicht** | `ACCESS_FINE_LOCATION`/`COARSE`, `QUERY_ALL_PACKAGES`, Accessibility, Overlay, Kamera, Mikrofon, Kontakte, SMS, Storage | Herkunftsland über Locale/Netz, kein GPS |
| **neu nicht** | `WRITE_SECURE_SETTINGS`, `INTERACT_ACROSS_USERS`, Root | nicht vorgesehen, nicht angefordert |

**Konsequenz:** Alle neuen Rechte sind funktional begründet; es gibt **keine** Standort-,
Accessibility- oder All-Packages-Berechtigung. Für Google Play sind FGS-Typ-Deklaration und
VPN-Erklärung vor Veröffentlichung zu prüfen.

## 9. Native-Helper-Supply-Chain

| Aspekt | Beleg/Status |
| --- | --- |
| Quelle | `GeDefense/Mobile/0.28.0-beta1/Source/app/src/main/jniLibs` (byte-identisch) |
| ABIs | `arm64-v8a`, `x86_64` (keine 32-bit-Auslieferung) |
| SHA-256 (berechnet/verifiziert) | arm64: `d34fda6f06ed7809c386af243b55e55cadd20794f1413b94ada3a729b26fd15e`; x86_64: `9f393ce49032a84f75717174b09748c08e86ff831886a38f68d0ac12975394f3` |
| Byte-Identität | **verifiziert** (Größe + SHA-256 gleich zu Mobile-Originalen, 29.10.2026) |
| Packaging | `jniLibs.useLegacyPackaging = true` (ausführbare Datei in `nativeLibraryDir`); `keepDebugSymbols` |
| Ausführung | Kindprozess der App, kein Root, kein Shell-Spawn, kein Export |
| Laufzeit-Integritätsprüfung | nicht implementiert/nachgewiesen → **NOT_TESTED** |
| Lead-Endledger | finaler SHA-256-Eintrag/Release-Bestätigung ausstehend |

**Bewertung:** Die Byte-Identität zum auditierten Mobile-Binary ist der zentrale
Vertrauensanker. Sie ersetzt **kein** Laufzeit-Self-Check- oder Signaturverfahren; ein solches ist
für eine spätere Härtung vorzusehen.

## 10. Control-Socket, Telemetrie-Pipe und Policy-Integrität

**Soll-Anforderungen (Design, NOT_TESTED):**

1. Privater Unix-Socket im App-Datenverzeichnis, zufälliger 32-Byte-Token-Handshake (Mobile-Muster),
   `SCM_RIGHTS` nur für File-Descriptors; keine Kommandos mit freien Strings.
2. Telemetrie-Frames strikt begrenzt (2…1024 B), Länge/Struktur validieren, Unbekanntes verwerfen;
   keine Rückkanal-Payloads, die Filterverhalten ändern können.
3. Keine DNS-Namen, Domains, IPs oder Traffic-Details in `Logcat`/Crash-Reports; Fehler nur als
   stabile Codes (Redaktionspflicht, Testplan-Prüfung).
4. Policy-/Geo-Artefakte vor Nutzung integritätsprüfen; derzeit **keine Signatur** dokumentiert →
   offener Härtungspunkt (F-16).
5. Fail-Closed: Policy-/Helper-Fehler → keine stille Freigabe; Zustand `DEGRADED`/`FAILED` mit
   ehrlicher Ursache.

## 11. V2-Befunde (statisch/Planung)

| ID | Befund | Schwere | Status |
| --- | --- | --- | --- |
| F-14 | V2-Implementierung (VPN/Telemetrie/XDR/UI) ist ungetestet; Manifest/Build-Vorbereitung vorhanden | **hoch (GOLD-Gate)** | **NOT_TESTED** |
| F-15 | Helper-Binary-Provenienz: byte-identisch + SHA-256 verifiziert; Laufzeit-Self-Check und Lead-Ledger-Eintrag offen | mittel | teilweise belegt |
| F-16 | Policy-/Geo-Integrität ohne Signatur/Prüfmechanismus | mittel-hoch | **GAP** |
| F-17 | Fail-Closed/Recovery/Always-On nur als Design; reale TV-/OEM-Verifikation fehlt | hoch | **NOT_TESTED** |
| F-18 | Keine garantierte DNS-Domain-Sicht bei DoT/DoH; UI muss das ehrlich sagen | niedrig-mittel | Design |
| F-19 | FGS-Typ `specialUse` + VPN-Deklaration erfordern Play-Policy-Prüfung | mittel | offen |
| F-20 | Traffic-Metadaten-Retention/Persistenzdauer noch nicht final; Datenschutztext muss folgen | mittel | offen |
| F-21 | Streaming-/DRM-/Update-Fehlblockungen bei strengen Profilen möglich | mittel | **NOT_TESTED** |
| F-22 | Akku-/Thermik-Last des FGS+Paketpfads ungemessen | mittel | **NOT_TESTED** |

## 12. V2-Security-Gates

| # | Gate | Status | Beleg/Lücke |
| --- | --- | --- | --- |
| V2-1 | Consent-/VPN-Lifecycle (Start/Stop/Ablehnung) | **NOT_TESTED** | nur Verträge/Manifest |
| V2-2 | Fail-Closed bei Helper-/Policy-Ausfall | **NOT_TESTED** | Design dokumentiert |
| V2-3 | Datenpfad-Korrektheit (DNS/Flow/Block) | **NOT_TESTED** | keine Läufe |
| V2-4 | Telemetrie-Bounds/Fuzzing | **NOT_TESTED** | keine adversarialen Tests |
| V2-5 | Helper-Provenienz | **PARTIAL** | SHA-256 verifiziert; Laufzeitprüfung offen |
| V2-6 | Policy-Integrität | **GAP** | keine Signatur |
| V2-7 | Datenschutz/Logs/Export | **NOT_TESTED** | Redaktions-/Upload-Tests fehlen |
| V2-8 | Always-On/Restart/Recovery | **NOT_TESTED** | reale Geräte/Emulator fehlen |
| V2-9 | Performance/Akku | **NOT_TESTED** | keine Messung |
| V2-10 | Play-/FGS-Policy | **OFFEN** | Deklaration/Review ausstehend |

## 13. V2-VGT-100-Ergänzungen (Summary)

| ID | Grenze | Status | Kurzbegründung |
| --- | --- | --- | --- |
| VGT-022 | Schlüsselverwaltung | **unverändert PASS (Design+Emulator V1)** | V2 nutzt bestehende Key-Custody; keine neuen Langzeitkeys behauptet |
| VGT-024 | Transportverschlüsselung | **PASS (statisch)** | Kein externer VPN-Server; TLS-Inhalte unangetastet |
| VGT-025/056 | Signaturen/Release | **GAP** | Helper-/APK-Signaturprozess unverändert offen |
| VGT-033/034 | SSRF/Redirect | **unverändert** | Feeds wie V1; V2-Datenpfad hat keine URL-Eingaben |
| VGT-041/045 | Least Privilege/Bindings | **PARTIAL** | neue FGS-/VPN-Deklarationen begründet; Play-Prüfung offen |
| VGT-044/048 | Netzwerkausgang/Trust | **NOT_TESTED** | lokaler Filterpfad; kein externer Tunnel |
| VGT-049 | Filesystem/Temp | **NOT_TESTED** | Helper-/Policy-Pfade ungeprüft |
| VGT-058 | Policy-/Feed-Integrität | **GAP** | Feeds ohne Signatur; Policy ohne Signatur |
| VGT-061/064/067 | Fail-Secure/DoS/Recovery | **NOT_TESTED** | Design vorhanden, keine Läufe |
| VGT-069/071/072 | Zeit/Events/Logintegrität | **NOT_TESTED** | XDR-/Traffic-Evidenz nur geplant |
| VGT-076 | Threat-Feed-Freshness | **PASS (V1)** | unverändert |
| VGT-080 | False-Positive-Bilanz | **NOT_TESTED** | Profile/Allowlists ungetestet |
| VGT-085 | Store-/Berechtigungs-Policy | **PARTIAL** | neue FGS/VPN-Deklarationen noch nicht Play-geprüft |
| VGT-090 | A11y/UX-Bypass | **NOT_TESTED (V2-UI)** | V2-Screens/Onboarding fehlen |
| VGT-096/097 | Fuzz/SAST | **NOT_TESTED** | keine V2-Tests |
| VGT-098 | Performance-Regression | **NOT_TESTED** | keine V2-Messung |

## 14. V2-Release-Blocker (zusätzlich zu R-01…R-10)

| ID | Risiko | Einstufung |
| --- | --- | --- |
| R-11 | V2-Laufzeittests, Emulator-Evidenz und Screenshots fehlen | **Produktions-Blocker** |
| R-12 | Fail-Closed/Always-On/Recovery auf realen TVs ungeprüft | **Produktions-Blocker** |
| R-13 | Policy-/Geo-Integrität ohne Signatur/Prüfung | hoch |
| R-14 | Play-FGS-/VPN-Deklaration und Datenschutztext für Traffic-Metadaten offen | hoch |
| R-15 | Helper-Laufzeit-Self-Check und finaler Hash-Eintrag im Ledger offen | mittel |
| R-16 | Streaming-/DRM-Fehlblockungen, Akku/Thermik ungemessen | mittel-hoch |

---

# Titan/V3-Sicherheit: privilegienabhängige Sicht und Active Response

**Status:** Code integriert (31.10.2026) · **Evidenz: Laufzeit/Build/Tests NOT_TESTED** ·
**kein Produktionsanspruch.** Architektur: [docs/TITAN-TV-ARCHITECTURE.md](docs/TITAN-TV-ARCHITECTURE.md);
Threat-Model: [THREAT-MODEL.md](THREAT-MODEL.md) §16 ff.

V3 führt eine bewusste Ausnahme vom bisherigen „keine privilegierten APIs“-Prinzip ein — aber nur
**optional, nutzerbestätigt und allow-listet**. Ohne bestätigten Kanal bleibt die Sicherheitslage
von V1/V2 unverändert; Titan-Capabilities sind dann leer.

## 15. Sicherheitsmodell des privilegierten Pfads

| Prinzip | Umsetzung im Code |
| --- | --- |
| Kein stilles Root | Nur `TitanApi.activate()` (explizite Nutzeraktion) darf den Root-Bestätigungs-`id`-Probe ausführen; Scans/Anzeigen tun das nie |
| Level nur mit bestätigtem Kanal | Datenmodell-Invarianten: `ROOT` ⇒ `rootShellConfirmed`, `SHIZUKU` ⇒ `shizukuBridgeAvailable`; Marker einer `su`-Datei schalten nichts frei |
| Nur effektive Fähigkeiten | UI/Report/Evidenz konsumieren `TitanCapabilityMatrix.effectiveCapabilities`, nie die theoretische Menge |
| Dirty Root ist Befund | `dirtyRootSuspected` wird gemeldet, nicht als Freigabe genutzt |
| Package Visibility | gezielte `<queries>`-Pakete für bekannte Root-Manager und Shizuku; **kein** `QUERY_ALL_PACKAGES`; „nicht sichtbar“ wird nicht als „nicht vorhanden“ ausgegeben |
| Kein freies Kommando | `TitanShellCommand`: feste Programm-Whitelist (`pm`, `am`, `iptables`, `setprop`, `stop`, `kill`, `chmod`, `mv`, `mkdir`, `cmd`, `getprop`, `id` + rein lesende `find`, `stat`, `sha256sum`, `cat`, `ls` für FIM-/`/proc`-Collector), Argument-Charset `[A-Za-z0-9_./:@+=,%-]+`, max. 16 Argumente, kein generisches `exec`; **keine** destruktiven Werkzeuge (`rm`, `dd`, `mkfs`, `mount`, `sh`) in der Allowlist |
| Keine zerstörenden Aktionen | Command-Factory enthält **kein** Delete/Format/Mount/Partitionsschreiben; Vault = `mv` + `chmod 000` |
| Fail-Safe vor Ausführung | `TitanContainmentPolicy`: Capability-, Ziel-, Schutz-, Mengen- und Rate-Gate; geschützte System-/Launcher-/Settings-/IME-Pakete, UID ≥ 10 000, PID ≠ 1/Selbst |
| Reversibel by design | jedes `FREEZE_APP` hat `RESTORE_APP`, jede UID-Quarantäne ein `RELEASE_NETWORK_UID`; ADB-Lockdown ist explizit und nicht still |
| Bounded Evidenz | `TitanEventFactory`: secret-freie, gekürzte Attribute (160/256 Zeichen), keine Dateiinhalte/Socket-Tabellen; `TitanEvidenceRecorder` mit Per-Scan-Cap, wirft nie in den Scan-Pfad |
| Ehrliche Gesamt-Sichtbarkeit | `TitanStatusComposer`: Gesamt-Sichtbarkeit ist das **schwächste** erfolgreich gelaufene Modul (ein `PARTIAL`-Modul kann kein `FULL` erzeugen) |
| Cold-Start ohne Root-Vertrauen | Persistierter ROOT-Status wird beim Kaltstart auf `STANDARD` zurückgesetzt; erneute Aktivierung durch den Nutzer nötig |
| Recovery nie blockiert | `RESTORE_APP`/`RELEASE_NETWORK_UID` sind von Aktiv-/Rate-Limits ausgenommen (sonst wäre eine eingefrorene App ohne adb unerreichbar) |
| Plattform-Zielguard | `TitanTargetGuard`: System-UID < 10 000, aufgelöster Launcher, Settings- und IME-Paket werden abgelehnt — zusätzlich zur Domänenliste (OEM-Schutz) |
| Vault-Pfad-Guard | `TitanVaultGuard` prüft vor dem ersten Root-Kommando per `ls`, dass der feste Vault-Pfad fehlt oder ein echtes Verzeichnis ist (kein Symlink); Rest-TOCTOU dokumentiert |
| Prozess-Absenz | `TitanProcessProbe`: `/proc/<pid>/status` wird gelesen; nur echtes ENOENT gilt als „Prozess weg“ (nicht jeder Non-Zero-Exit) |

## 16. Härtung der Einzelpfade

| Pfad | Kontrolle | Status |
| --- | --- | --- |
| Command-Building | Factory-Validierung + `TitanShellCommand.init`-Requires (Programm/Argument/Tag) | **PASS (JVM-Harness)**; Teil der 6624/0-Assertions |
| Kanal-Executor (`TitanShell`) | feste `su`-Kandidatenliste statt `PATH`; `su -c <line>`; Timeout 5 s Probe/8 s Ausführung (Clamp 250 ms–30 s); Output-Cap 64 KiB (Tabelle 256 KiB, Clamp 512 B–512 KiB); Rohausgabe/Argumente nie im Log; Fehler ⇒ `TitanShellResult` ohne Exception | Code vorhanden; JVM-Anteile belegt, **Gerätelauf Level 3 NOT_TESTED** |
| Prozess-Chokepoint (`TitanBoundedProcess`) | exakt drei erlaubte Aufruf-Formen (`su -c` mit Re-Check von Charset/Allowlist/8192 Zeichen/4 argv, `getenforce`, `getprop <property>`); alles andere wird vor `ProcessBuilder` abgelehnt; Drain-Thread, harter Output-Cap, forcierter Kill bei Timeout | Code vorhanden; **NOT_TESTED** |
| Zielvalidierung | Paket-Regex, UID ≥ 10 000, PID ≥ 2, Vault-Quelle nur Watch-Root, Dateiname `[A-Za-z0-9._-]{1,128}`; Plattform-Zielguard für System-UID/Launcher/Settings/IME | **PASS (JVM-Harness)**; Plattformguard Laufzeit **NOT_TESTED** |
| FIM-Walker | feste Roots, `maxDepth ≤ 6`, 512 Dateien/Root, 2048 gesamt, 64 MiB Hash-Cap; `isSafeAbsolutePath` (kein `..`, keine Metazeichen); Pfade außerhalb des Roots werden verworfen; Wall-Clock-Budget; unvollständige Listings ⇒ `truncated`/`PARTIAL` | Engine **PASS (JVM-Harness)**; Collector-Laufzeit **NOT_TESTED** |
| Socket-Parser | harte Caps (`maxSockets 4096`, `maxProcessEntries 4096`, `maxObservations 512`), `UNKNOWN` statt Raten, `truncated`-Signal; `File`-Fallback auf `/proc/net/*` nur ohne Kanal und dann explizit `PARTIAL` | **PASS (JVM-Harness)**; Collector-Laufzeit **NOT_TESTED** |
| Privileg-Snapshot | `suPaths ≤ 16`, Manager-IDs per Regex, SELinux-Rohwert ≤ 32 Zeichen | **PASS (JVM-Harness)**; passive Detektion auf Emulator belegt (keine Marker) |
| Witness | Digest/MAC als 64-Hex validiert; `PAIRED` nie ohne Gegenpart; nur lokale Checkpoints | **PASS (Runtime, lokal)** – `READY`, `checkpoints=1`, Ledger 9 Records; Tamper-Test **NOT_TESTED**; Mobile-Push **nicht ausgeliefert** |
| Evidenz | Titan-Events über bestehende HMAC-Kette (Core), append-only; bounded Recorder | **PARTIAL (Emulator: Ledger gesund, 9 Records inkl. Witness-Event)**; vollständige Titan-Event-Matrix Level 3 **NOT_TESTED** |
| Non-Root-Fall | Level 1: keine Capability, keine Aktion, kein Crash-Pfad | **PASS (Emulator)** – Level 1, 7× „Unavailable“, `caps=0`, kein Crash; keine `su`-Prompts |

## 17. Titan-Befunde (Code-Review + unabhängiges Read-only-Audit, 31.10.2026)

**Audit-Urteil:** **kein kritischer Befund und kein Shell-Injection-Blocker**; der privilegierte
Kanal ist durch Program-Allowlist + Argument-Charset eingegrenzt (`TitanShellCommand`-Requires,
`TitanCommandFactory`-Validierung, `TitanBoundedProcess`-Re-Check). Die folgenden Befunde sind
**Alpha-Grenzen** und als solche zu dokumentieren; mehrere davon haben bereits einen Code-Fix,
dessen **Laufzeitwirksamkeit aber NOT_TESTED** ist.

| ID | Befund (Audit) | Schwere | Status |
| --- | --- | --- | --- |
| F-23 | Privilegierter `su`-Kanal ist die höchste neue Angriffsfläche; Sicherheit hängt an Whitelist/Charset und am bestätigten Kanal | **hoch** | Audit: kein Injection-Blocker; Laufzeit Level 3 **NOT_TESTED** |
| F-24 | Laufzeit-/Root-Geräte-Evidenz für Titan | **hoch** | **PARTIAL** – Domain-Harness PASS (6624/0), Build/Lint/Release Exit 0, Level-1-Emulatorlauf PASS, Witness-Runtime PASS; Root-Gerät **NOT_TESTED** |
| F-25 | Level 2 (Shizuku) ist detection-only; keine Binder-Kommando-Bridge | mittel | bewusst, dokumentiert |
| F-26 | Witness ohne Mobile-Pairing/Push; keine Fernzustellung | mittel | bewusst (Alpha-Gap) |
| F-27 | Vault-Binärdaten nicht verschlüsselt (nur Metadaten-MAC-Kette) | mittel | Design-Grenze, dokumentiert |
| F-28 | FIM-/`/proc`-Sichtbarkeit ist plattform-/ROM-abhängig; `UNATTRIBUTED`/`UNREADABLE` bleiben Lücken | mittel | ehrlich modelliert; Level 1 belegt, Level 3 **NOT_TESTED** |
| F-29 | Fuzz-/Negativtests für `/proc`-Parser, Ledger-Tail, Command-Factory fehlen | mittel | **PARTIAL** – JVM-Assertions (6624) vorhanden, Fuzzing **NOT_TESTED** |
| F-30 | Unabhängiges Security-Review der Laufzeitpfade | **hoch (Produktions-Blocker)** | Read-only-Audit erfolgt (kein Blocker); Vollprüfung der Laufzeit **OFFEN** |
| TF-01 | FIM: ungewöhnliche Dateinamen konnten still übersprungen werden → Coverage-Gap muss als `truncated`/`PARTIAL` sichtbar sein | mittel | Fix im Code (Listing-Completeness, `rejectedLines`/`truncated`); Verhalten **NOT_TESTED**, laut Lead „Fix in Arbeit“ |
| TF-02 | Socket-Parser: Parse-Fehler durfte nicht wie „keine Verbindungen“ aussehen → leerer `PARTIAL`-Snapshot mit Note | mittel | Fix im Code (unvollständiger Read ⇒ `PARTIAL`); **NOT_TESTED** |
| TF-03 | Kill-Verifikation wertete jeden Non-Zero-Exit als „Prozess weg“ | mittel | Fix: `TitanProcessProbe` liest `/proc/<pid>/status`, nur ENOENT = weg; **NOT_TESTED** |
| TF-04 | „Full visibility“ konnte mit `PARTIAL`-Modulpässen überzeichnen | mittel | **behoben:** Gesamt-Sichtbarkeit = schwächstes Modul (`TitanStatusComposer`); JVM-Assertions belegt |
| TF-05 | Recovery-Aktionen (Restore/Release) waren Aktiv-/Rate-Limits unterworfen | mittel | **behoben:** ausgenommen (`TitanContainmentPolicy`); JVM-Assertions belegt |
| TF-06 | Geräte-Policies mit „einmaliger“ `su`-Freigabe können während eines FIM-Passes mehrere Superuser-Prompts auslösen | niedrig | Geräte-/Policy-Grenze, dokumentiert; praktisch **NOT_TESTED** |
| TF-07 | Quarantäne-Vault: Symlink/TOCTOU latent | mittel | `TitanVaultGuard` (Symlink-Vorprüfung) vorhanden; Rest-TOCTOU (Prüfung und `mkdir` sind zwei Kommandos) **dokumentiert**, Laufzeit **NOT_TESTED**; Quarantäne hat in dieser Alpha **keinen UI-Aufrufer** |
| TF-08 | Persistierter ROOT-Status konnte einen Kaltstart überdauern | **hoch** | **behoben:** Kaltstart fällt ehrlich auf `STANDARD` zurück, erneute Aktivierung nötig |
| TF-09 | Leere `find`-Ausgabe konnte als „Root fehlt“ missverstanden werden | mittel | Fix im Code (nur echtes ENOENT = Root abwesend, sonst Coverage-Gap); **NOT_TESTED** |
| TF-10 | `QUARANTINE_VAULT` kann „aktiv“ erscheinen, obwohl dieser Alpha-Build keine UI-Move-Aktion anbietet; `CLOSE_ADB_PORT` ist die einzige irreversible Aktion und im UI nicht exponiert | niedrig-mittel | dokumentiert (Alpha-Grenze/UI) |
| TF-11 | Shared-UID-Misattribution (mehrere Apps unter einer UID) | mittel | deterministische Paketwahl (lexikografisch) + `UNATTRIBUTED`-Modell; Fix/Verifikation laut Lead in Arbeit, **NOT_TESTED** |
| TF-12 | OEM-Systempakete fehlten in der Freeze-Blocklist | mittel | `TitanTargetGuard`: System-UID < 10 000 sowie aufgelöster Launcher/Settings/IME werden abgelehnt; Laufzeit **NOT_TESTED** |

## 18. Titan-Security-Gates

| # | Gate | Status | Beleg/Lücke |
| --- | --- | --- | --- |
| V3-1 | Privileg-Invarianten (Level ⇒ bestätigter Kanal) | **PASS (JVM-Harness)** | Datenmodell-Requires + Capability-Matrix, Teil der 6624/0-Assertions |
| V3-2 | Effektiv-vs-theoretisch-Gating in UI/Report | **PASS (JVM + Emulator Level 1)** | Composer/Matrix geprüft; Emulator: `caps=0`, 7× „Unavailable“ |
| V3-3 | Command-Injection-Unabhängigkeit | **PARTIAL** | Whitelist/Charset + `TitanShellCommand`-Requires + `TitanBoundedProcess`-Chokepoint + JVM-Assertions; Fuzz-/Adversarialtest **NOT_TESTED** |
| V3-4 | Fail-Safe-Policy (geschützte Ziele, Limits) | **PASS (JVM-Harness)** | `TitanContainmentPolicy` (inkl. Recovery-Ausnahme); Plattformguard-Laufzeit **NOT_TESTED** |
| V3-5 | Reversibilität (Freeze↔Restore, UID↔Release) | **PASS (JVM-Harness)** | Command-Factory/Policy-Assertions; Gerätelauf **NOT_TESTED** |
| V3-6 | Level-1-Nicht-Root-Verhalten (keine Crashs/Prompts) | **PASS (Emulator)** | Level 1, kein Aktivierungs-Button, Scan `STANDARD caps=0`, kein AndroidRuntime-Crash, keine `su`-Prompts |
| V3-7 | Root-Gerätelauf (Magisk/KernelSU/APatch) | **NOT_TESTED** | kein Root-Gerät belegt (Emulator ohne `su`; Produktions-Google-TV ohne `adb root`) |
| V3-8 | FIM-/Socket-Parser adversarial | **PARTIAL** | JVM-Assertions für Parser/Engine; Fuzzing **NOT_TESTED** |
| V3-9 | Evidenz-/Witness-Integrität | **PASS (Runtime, lokal) / PARTIAL** | Witness-Runtime PASS (`READY`, `checkpoints=1`, Ledger 9 Records); Tamper-Test **NOT_TESTED** |
| V3-10 | Unabhängiges Security-Review | **PARTIAL** | Read-only-Audit ohne kritischen Befund/Injection-Blocker; Laufzeit-Vollprüfung **OFFEN** (Produktions-Blocker) |
| V3-11 | Cold-Start-Root-Vertrauen | **behoben (Code)** | Kaltstart fällt auf `STANDARD`; Verhalten im Emulator nicht als Root-Fall prüfbar → **NOT_TESTED** |

## 19. Titan-VGT-100-Ergänzungen (Summary)

| ID | Grenze | Status | Kurzbegründung |
| --- | --- | --- | --- |
| VGT-006/041 | Least Privilege | **PARTIAL** | optionaler privilegierter Pfad nur mit Consent; Standard bleibt Level 1 |
| VGT-022 | Schlüsselverwaltung | **unverändert** | Titan nutzt bestehende Key-Custody; keine neuen Langzeitkeys |
| VGT-024 | Transportverschlüsselung | **unverändert** | Titan hat keinen Netzwerk-Upload; Witness nur lokal |
| VGT-033/034 | Injection/Redirect | **PARTIAL** | Command-Charset/Whitelist vorhanden; Fuzz fehlt (VGT-096/097) |
| VGT-044/048 | Trust/Netzwerkausgang | **PARTIAL** | `/proc`-/Feed-Daten untrusted; keine Nutzungsbehauptung |
| VGT-049 | Filesystem/Temp | **NOT_TESTED** | Vault/FIM-Pfade ungeprüft |
| VGT-055/056 | Signatur/Release | **GAP** | unverändert offen (F-01) |
| VGT-061/064/067 | Fail-Secure/DoS/Recovery | **PARTIAL/NOT_TESTED** | Policy-Design vorhanden; Laufzeit fehlt |
| VGT-069/071/072 | Zeit/Events/Logintegrität | **PARTIAL** | Titan-Events in HMAC-Kette; Laufzeit fehlt |
| VGT-085 | Store-/Berechtigungs-Policy | **unverändert** | keine neuen Manifest-Rechte durch Titan |
| VGT-090 | A11y/UX-Bypass | **NOT_TESTED** | TITAN-LIVE-D-Pad nicht erprobt |
| VGT-096/097 | Fuzz/SAST | **NOT_TESTED** | keine Titan-Fuzztests |
| VGT-098 | Performance-Regression | **NOT_TESTED** | keine V3-Messung |

## 20. Titan-Release-Blocker (zusätzlich zu R-01…R-16)

| ID | Risiko | Einstufung |
| --- | --- | --- |
| R-17 | Keine V3-Level-3-Root-Evidenz (Non-Root-Matrix ist belegt) | **PARTIAL** – Domain-Harness, Build/Lint/Release, Level-1-Emulator und Witness-Runtime belegt; **Root-Matrix fehlt** (**Produktions-Blocker** für Level 3) |
| R-18 | Kein unabhängiges Security-Review der Titan-Pfade (Command-Factory, Policy, Parser) | **PARTIAL** – Read-only-Audit ohne Blocker; Laufzeit-/Vollprüfung offen (**Produktions-Blocker**) |
| R-19 | Privilegierter Kanal ohne Fuzz-/Negativtests | hoch (JVM-Assertions vorhanden, Fuzzing **NOT_TESTED**) |
| R-20 | Shizuku-Kommando-Bridge und Mobile-Witness-Pairing fehlen (Alpha-Gap, muss ehrlich kommuniziert bleiben) | mittel |
| R-21 | Quarantäne-Vault ohne UI-Aufrufer und ohne Binärverschlüsselung; Vault-Rest-TOCTOU | mittel (dokumentiert, Alpha-Grenze) |
| R-22 | Witness-Runtime | **behoben/verifiziert** – lokale Checkpoints PASS (Emulator); Mobile-Zustellung bleibt nicht ausgeliefert |
