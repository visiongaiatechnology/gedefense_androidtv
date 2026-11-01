# GeDefense TV — Test- und Abnahmeplan

**Version:** 0.3.0-alpha1 („Titan Engine“, V3) · **Stand:** 31. Oktober 2026 · **Status:**
Abnahmematrix mit realer Build-/Lint-/Emulator-Evidenz für V1–V3 übernommen
(**GOLD / PARTIAL_VERIFIED**); reale TV-Hardware, Level-3-Root-Lauf und Security-Vollprüfung
**NOT_TESTED**; 0.3.0-alpha1-Artefakte gebaut (Debug 8.811.121 B, Release 6.522.110 B,
Alpha-signiert, Exit 0) und auf dem Emulator gestartet.

Dieser Plan übersetzt die Abnahmematrix aus dem technischen Datenblatt (§11) in konkrete,
nachweisbare Testfälle. Er legt außerdem die Voraussetzungen, die Testmittel und die
Evidenzanforderungen fest. **Es werden keine Testergebnisse behauptet, die nicht real ausgeführt
wurden.**

---

## 1. Evidenzregeln (verbindlich)

Jeder als PASS dokumentierte Test braucht:

| Feld | Inhalt |
| --- | --- |
| Test-ID | z. B. `T-04` |
| Datum/Uhrzeit | inkl. Zeitzone |
| Umgebung | Gerät/AVD, Android-API-Level, Build-Variante, APK-Version/Commit (falls vorhanden) |
| Befehl(e) | exakt ausgeführt, inkl. Arbeitsverzeichnis |
| Ergebnis | beobachtetes Verhalten, Screenshot/ADB-Ausgabe/Logdatei |
| Exitcode | nur bei Kommandozeilentests; sonst „n/a (manuell)“ |
| Bewertung | PASS / FAIL / BLOCKED / NOT_TESTED |
| Einschränkungen | was der Test **nicht** abdeckt |

Regeln:

- `NOT_EXECUTED` niemals als PASS umdeuten.
- Fehlende Berechtigungen/APIs sind **erwartetes** Verhalten, kein Testfehler, solange die UI die
  Einschränkung korrekt ausweist.
- Screenshots/Video sind für UI-/D-Pad-Tests Pflicht.
- Ein Test, der nur „App startet“ prüft, belegt keine Sicherheitsaussage.

---

## 2. Bereits real durchgeführte Prüfungen (statisch, JVM-Harness, Build, Emulator)

Alle folgenden Ergebnisse sind real belegt (Lead-Endledger 29.10.2026, teils read-only durch das
Doku-Team gegengeprüft). Reale TV-Hardware, Doze-/Offline-/IOC-/Tamper-Szenarien und App-Unit-Tests
bleiben ausstehend.

| ID | Prüfung | Befehl / Methode | Ergebnis | Bewertung |
| --- | --- | --- | --- | --- |
| S-01 | Quellentreue vendored Core | `.\tools\verify-source-fidelity.ps1` (PowerShell 5.1, 29.10.2026) | „ERGEBNIS: PASS – 26 Dateien byte-identisch zum Manifest“, Exitcode **0**; eine dokumentierte Ausnahme: `core/PROVENANCE.md` (nicht Teil des Mobile-Quellstands) | **PASS** |
| S-02 | Manifest-Berechtigungen/Komponenten | statische Sichtprüfung `app/src/main/AndroidManifest.xml` | nur `INTERNET`, `ACCESS_NETWORK_STATE`; `allowBackup=false`; `usesCleartextTraffic=false`; Activity nur Launcher; Service mit `BIND_JOB_SERVICE`; keine Provider/Receiver | **PASS (statisch)** |
| S-03 | Secret-Musterprüfung | Grep nach Private-Key-/Token-/Passwort-/AWS-Key-Mustern über `*.kt,*.kts,*.xml,*.pro,*.properties,*.md` | keine Treffer (kein vollständiges Secret-Audit) | **PASS (begrenzt)** |
| S-04 | SDK-/Emulator-Verfügbarkeit | `sdkmanager --list`, Verzeichnisinventur, `emulator -list-avds`, `adb devices` | TV-Image `android-36;google-tv;x86_64` **installiert**; AVD **`gedefense_tv`** vorhanden; Emulator läuft (`emulator-5554 device`); `sdkmanager --list` endete nach Ausgabe abnorm (`-1073740791`, alte cmdline-tools) | **PASS (Inventur)** |
| S-05 | Modul-/Versionskonsistenz | `settings.gradle.kts`, `build.gradle.kts`, `VERSION`, `VERSION_CODE` | Module `:core,:tv-core,:app`; Version 0.3.0-alpha1 / VC 4; minSdk 26, target/compile 36 | **PASS (statisch)** |
| S-06 | TLS-Konfiguration | `res/xml/network_security_config.xml` | `cleartextTrafficPermitted="false"`, nur `system`-TrustAnchors (keine User-CAs) | **PASS (statisch)** |
| S-07 | SBOM/Doku-Links | `SBOM.cdx.json` via JSON-Parser; relative Links per Skript | CycloneDX 1.5, 2 Komponenten, 3 Dependencies gültig; alle relativen Markdown-Links auflösbar | **PASS (statisch)** |
| S-08 | Vollständigkeit der Codebasis | Datei-Inventur `app/src/main/java`, `res/` | `ui/ScreenRegistry` und alle 10 Screens (Home, Check, Findings, FindingDetail, Apps, Hardening, ThreatIntel, Evidence, Settings, About), UI-Komponenten, Brand-PNGs und Ressourcen vorhanden; Compile/Build siehe S-11/S-12 | **PASS** |
| S-09 | `:tv-core:tvCoreCheck` | Lead-Lauf (29.10.2026) | Exitcode **0**, `PASS 554 / FAIL 0`, `TESTS: 35 passed, 0 failed`, `BUILD SUCCESSFUL` (nach DeCatalog-Sonderzeichenfix `[{]`/`[}]`) | **PASS (Lead-verifiziert)** |
| S-10 | `:core:coreCheck` (vendored Core) | Lead-verifiziert; Plattformunterscheidung | Windows-Host: **BLOCKED** – Verzeichnis-`fsync` über `FileChannel` unter Win32 nicht unterstützt (Upstream-Limitierung). Linux-JVM (WSL Ubuntu 24.04, OpenJDK 17.0.20.1): `CORE_TESTS_PASS`, Exitcode **0** | **PASS (Linux-JVM) / BLOCKED (Win32)** |
| S-11 | App-Compile + Lint | Lead-Ledger (29.10.2026) | `:app:compileDebugKotlin` Exit 0; `:app:lintDebug` Exit 0, **0 Errors / 169 Warnings** (131 `UnusedResources`, 22 `PluralsCandidate`, 4 `DrawAllocation`, 2 `QueryPermissionsNeeded`, 2 `ApplySharedPref`, je 1 `TranslucentOrientation`/`ObsoleteSdkInt`/`DiscouragedApi`/`DataExtractionRules`) | **PASS** |
| S-12 | Debug-Build + Artefakt | Lead-Ledger (29.10.2026) | `:app:assembleDebug` Exit 0; `app-debug.apk` **2.860.091 B** (~2,86 MB) | **PASS** |
| S-13 | Release-Pipeline | Lead-Ledger (29.10.2026) | `:app:assembleRelease` Exit 0; `app-release.apk` **1.626.209 B**, R8-minifiziert, **debug-signiert** (Produktions-Blocker F-01); installiert/gestartet (Smoke-Test); Artefakt vor letztem Redesign → finaler RC-Rebuild erfolgt (1.626.209 B, debug-signiert, Emulator-Smoke-Test) | **PASS (Pipeline), Produktions-Blocker** |
| S-14 | Emulator-Funktionstests | Emulator Android 16 Google TV, API 36, AVD `gedefense_tv`, 1920×1080 | Scan per D-Pad → `PARTIAL`/„Teilweise abgeschlossen“/„Teilweise Sicht“, 3 Befunde, 6 Prüfbereiche, kein Crash; TI 9/9 Feeds; Evidenz „gesund“ (40 Einträge, HMAC-Kette); Export-Fallback 30.246 B Text + 4.562 B JSON (valides JSON); Restart-Summary; D-Pad/kein Touch; Logcat clean | **PASS (PARTIAL_VERIFIED)** |
| S-15 | Kaltstart/Performance | Lead-Ledger, Emulator Software-GPU | `am start -W` TotalTime **1,81–2,29 s** (vorher 6,7 s); App-Bootstrap 191–261 ms; `navigate(HOME)` 118–135 ms; vorher 4.519 ms (TI-Status O(1)-Fix); ~1,4 s Window/Theme/Inflate (Emulator-GPU-Anteil) | **PASS (Emulator), reale HW NOT_TESTED** |
| S-16 | Screenshots/visuelle QA | 1080p-Renderings, `docs/screenshots/` | Screens 80–96 (RC-Stand): Home/Check/Findings/Apps/Hardening/TI/Evidence/Export; keine Raster/Neon; Logo/Brand sichtbar; Fokusringe sichtbar | **PASS (Emulator)** |

Nicht durchgeführt: reale TV-Hardware (≥ 2 OEM-Profile), Doze-/Reboot-Volltest, Offline/Stale-Test,
synthetischer IOC-Match, Tamper-/Fail-closed-Test, Collector-Timeout/Cancel-Adversarialtest,
Fuzz-/Negativtests, App-Unit-Tests, finaler RC-Rebuild. Der Windows-Host kann `:core:coreCheck`
nicht ausführen (Win32-Limitierung); die Verifikation erfolgt auf Linux-JVM.

---

## 3. Voraussetzungen

### 3.1 Emulator und JVM-Testumgebung

- Android SDK mit `platform-tools`, `emulator`, aktuellen `cmdline-tools`; TV-System-Image
  `system-images;android-36;google-tv;x86_64` (**installiert**).
- AVD **`gedefense_tv`** (Android 16 Google TV, API 36, 1920×1080) – im Projekt real vorhanden;
  alternative AVD-Namen über `-AvdName` im Helper möglich. Anleitung:
  [docs/TV-EMULATOR-TESTING.md](docs/TV-EMULATOR-TESTING.md).
- Debug-APK (`:app:assembleDebug`).
- `adb` im PATH bzw. SDK-Pfad.
- Hardware-Virtualisierung (WHPX/HAXM) oder ausreichend schneller ARM-Host.
- **JVM-Harnesse:** `:tv-core:tvCoreCheck` läuft plattformunabhängig (JDK 17). `:core:coreCheck`
  benötigt ein POSIX-/Linux-JVM (z. B. WSL Ubuntu + OpenJDK 17), da der vendored Core
  Verzeichnis-`fsync` über `FileChannel` nutzt; unter Win32 ist der Lauf **BLOCKED**.
  `tools/test.ps1` überspringt den Schritt unter Windows sichtbar (Status UEBERSPRUNGEN, nicht
  PASS); `-ForceCoreCheck` versucht ihn dennoch.

### 3.2 Reale TV-Hardware (Release-Gate)

- Mindestens **zwei** reale Profile mit unterschiedlichem OEM und Android-Release
  (Datenblatt §11 „Empfohlene Testgeräte“).
- Ein Gerät mit eingeschränkter Paket-Sichtbarkeit bzw. abgelehntem optionalem Zugriff.
- Normale Streaming-/Update-Szenarien, damit Fehlalarme sichtbar werden.
- Dokumentierte Wiederherstellungs-/Reset-Möglichkeit; kein aggressives Hardening zuerst am
  Alltagsfernseher.

### 3.3 Testdaten (IOC/Feeds)

- Feed-Tests dürfen **keine** produktiven Feeds manipulieren. Für IOC-Matches sind synthetische
  Indikatoren aus den Dokumentationsnetzen nach RFC 5737 zu verwenden
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) und/oder ein lokaler Test-Double.
- Der aktuelle Katalog enthält ausschließlich öffentliche HTTPS-Feeds; ein lokaler Testpfad muss
  über eine testbare Downloader-Abstraktion erfolgen (Designvoraussetzung, **NOT_TESTED**).
- TI-Stale-Tests benötigen kontrollierbare Zeitstempel (Test-Double/Fake-Clock), nicht das
  Warten auf echte Ablauffristen.

---

## 4. Abnahmematrix (Datenblatt §11)

Status-Spalte: **PASS (Emulator)** = real auf dem Emulator beobachtet; **PARTIAL** = Teilaspekt
belegt, Rest offen; **NOT_TESTED** = nicht ausgeführt. Reale TV-Hardware ist grundsätzlich
**NOT_TESTED**.

### T-01 Frische Installation

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | sauberes Gerät/AVD, keine App-Daten |
| Schritte | APK installieren → App starten → Onboarding/HOME prüfen |
| Erwartet | Capability-/Ausgangsprofil wird erstellt; keine falsche Aussage bei fehlenden Permissions; kein Absturz; sichtbarer Fokus; 8 Rail-Ziele erreichbar |
| Abnahmekriterium | Kein „sauber/vollständig“-Claim ohne Daten; alle Status als `UNKNOWN`/`PARTIAL` korrekt; D-Pad bedienbar |
| Evidenz | Screenshot(s), Logcat ohne Crash, ggf. `adb shell am start` |
| Status | **PASS (Emulator, PARTIAL)** – Debug-APK installiert, App-Start ohne Crash, Rail/Screens in Screenshots 70/80; reale TV-Hardware **NOT_TESTED** |

### T-02 Android-Version / Patch-Level

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | Gerät mit bekanntem Build/`SECURITY_PATCH` |
| Schritte | App starten → Scan → Posture-Ansicht öffnen |
| Erwartet | Metadaten mit Quelle/Zeit; Patch-Status `CURRENT/AGING/OUTDATED/CRITICALLY_OUTDATED/UNKNOWN` gemäß Datum; unbekannte Werte bleiben `UNKNOWN` |
| Abnahmekriterium | Angezeigter Wert entspricht `Build.VERSION`/`Build.VERSION.SECURITY_PATCH`; keine Aussage „verwundbar“ aus reinem Datum |
| Evidenz | Screenshot + `adb shell getprop ro.build.version.security_patch` |
| Status | **PASS (Emulator)** – Android 16/API 36, Fingerprint dev-keys, `security_patch=2026-04-01`; Report/UI weisen Patch-Stand als veraltet (211 Tage) aus, ohne „verwundbar“-Behauptung |

### T-03 Sichtbares App-Inventar

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | Gerät mit mehreren sichtbaren Launcher-Apps |
| Schritte | Scan → APPS-Ansicht; Paketliste mit Version/Signatur prüfen |
| Erwartet | sichtbare Pakete erfasst; Einschränkungen benannt; `coverage.total` bleibt `null` (kein Vollständigkeitsanspruch) |
| Abnahmekriterium | Keine Behauptung vollständiger Abdeckung; UI-Text nennt Einschränkung |
| Evidenz | Screenshot, Vergleich mit `adb shell pm list packages` (nur als Referenz, nicht als Erwartungswert) |
| Status | **PASS (Emulator, PARTIAL)** – sichtbares Inventar mit 66 Apps, Sichtbarkeit „Teilweise“; keine Vollständigkeitsbehauptung; Screenshot Apps |

### T-04 Package Visibility eingeschränkt

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | API 30+; `<queries>`-Filter aktiv |
| Schritte | Scan → Abdeckungs-/Sichtbarkeitsanzeige prüfen |
| Erwartet | Capability `PARTIAL`; Scanner und Gesamtbewertung weisen Einschränkung klar aus |
| Abnahmekriterium | Keine grüne Vollständigkeitsaussage; Gesamtscore wird gekappt (`capReason`) oder bleibt ohne Wert |
| Evidenz | Screenshot, ggf. Logcat |
| Status | **PASS (Emulator)** – Scan-Status „Teilweise abgeschlossen“ / „Teilweise Sicht“, Score gekappt; Einschränkung in UI und Report sichtbar |

### T-05 Usage Access verweigert (V1: kein Usage-Modul)

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | Installation ohne `PACKAGE_USAGE_STATS` |
| Schritte | App starten → alle Ansichten durchlaufen |
| Erwartet | kein Crash; optionales Modul nicht aktiv; Kern-App funktionsfähig; kein Hinweis, der Usage Access verlangt |
| Abnahmekriterium | Keine Berechtigungsanforderung, keine Fehlfunktion |
| Evidenz | Screenshots, Logcat |
| Status | **PASS (Emulator)** – keine Usage-Access-Anforderung, kein Berechtigungsdialog, Kern-App funktionsfähig |

### T-06 TI-Feed offline / veraltet

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | Feed-Cache vorhanden; Netzwerk deaktiviert bzw. Feed über Stale-Budget gealtert |
| Schritte | TI-Ansicht öffnen; Sync versuchen |
| Erwartet | letzter Feed bleibt verfügbar, klar als `STALE` markiert; Sync-Fehler ehrlich gemeldet |
| Abnahmekriterium | Keine unbemerkte Verwendung veralteter Daten; keine stillen Fehler |
| Evidenz | Screenshot, Logcat, `adb shell svc wifi disable`/`svc data disable` |
| Status | **NOT_TESTED** – nur der Online-Fall (9/9 Feeds aktuell) ist belegt; Offline/Stale nicht separat getestet |

### T-07 IOC-Testmatch

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | synthetischer Testindikator aus RFC-5737-Netz bzw. Test-Double |
| Schritte | Test-Feed mit definiertem Indikator laden → lokalen Abgleich auslösen |
| Erwartet | Quelle, Konfidenz, Zeit und Evidenz erscheinen; Match reproduzierbar; **keine** automatische Blockierung |
| Abnahmekriterium | Match nachvollziehbar; identischer Lauf liefert identische Bewertung; kein Enforcement |
| Evidenz | Screenshot, JSON-Export des Reports, Wiederholungslauf |
| Status | **NOT_TESTED** – kein synthetischer IOC-Testfall ausgeführt |

### T-08 Background / Doze / Neustart

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | Scan durchgeführt; App in Hintergrund; Doze/Neustart |
| Schritte | Gerät in Doze versetzen (`adb shell dumpsys deviceidle force-idle`), App erneut öffnen; danach Reboot |
| Erwartet | Scanstatus und letzter erfolgreicher Lauf bleiben korrekt; keine Behauptung kontinuierlicher Überwachung |
| Abnahmekriterium | `lastScanAt` korrekt; kein „läuft weiter“-Eindruck; Evidenz konsistent |
| Evidenz | Screenshot, `dumpsys`-Ausgabe, Logcat |
| Status | **PARTIAL (Emulator)** – `force-stop` + Neustart getestet: Home zeigt persistierte Scan-Summary (Score/Band/Status + ehrlicher Neustart-Hinweis), Check „Letzter Lauf“; Doze/Reboot nicht separat getestet |

### T-09 Local-VPN-Prototyp

| Feld | Inhalt |
| --- | --- |
| Umfang | **Nicht V1** (Datenblatt §7.2 optional/später) |
| Erwartung | In V1 existiert kein VPN-Service, keine `VpnService`-Deklaration, kein TUN-Pfad |
| Abnahmekriterium | Statisch: keine VPN-Komponente im Manifest; keine VPN-Berechtigung |
| Evidenz | Manifest-Inspektion (statisch bestätigt: keine VPN-Deklaration) |
| Status | **N/A in V1** (bei späterer Freigabe: eigenes Design + Testmatrix für Routing/DNS/IPv4-IPv6/Fail-open/-closed/Streaming/DRM/VPN-Konflikt) |

### T-10 Export und Löschen

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | Scan mit Findings; Evidenz vorhanden |
| Schritte | Report als Text und JSON exportieren; Inhalte prüfen; Evidenz über UI löschen; App neu starten |
| Erwartet | Datei wird über SAF erzeugt; keine Tokens/unnötigen IDs; Scope/Limitations enthalten; Löschung wirkt und wird reflektiert |
| Abnahmekriterium | Export ohne Secrets; `clear()` entfernt Ledger; `EvidenceHealth` danach korrekt |
| Evidenz | Exportdateien, Screenshot, Logcat, Dateisystemprüfung |
| Status | **PARTIAL (Emulator)** – Export-Fallback erzeugt Text (30.246 B) und JSON (4.562 B, valides JSON) unter `/sdcard/Download/GeDefenseTV/`; keine Storage-Permission; Löschdialog zweistufig sichtbar. Vollständiger Clear-/Reflexions-Test und Retest nach Redesign offen |

### T-11 TV-UX / D-Pad

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | TV-Emulator/Gerät mit D-Pad |
| Schritte | alle Ziele per D-Pad erreichen; OK/Back in jeder Ansicht; Fokus sichtbar; tiefe Verschachtelung prüfen |
| Erwartet | alle Aktionen per D-Pad bedienbar; Fokus bleibt sichtbar; Back-Hierarchie korrekt (screen-lokal → Stack → Home) |
| Abnahmekriterium | Keine Fokusfalle, kein unsichtbarer Fokus, kein Touch-Zwang |
| Evidenz | Screenshots je Ansicht, ggf. Video |
| Status | **PASS (Emulator)** – alle Screens per D-Pad erreichbar, Listen fokussierbar/scrollbar, LEFT zur Rail, BACK korrekt, Focus-Scale/Ring sichtbar (Screenshots 80–97; Lead-Ledger) |

### T-12 Keine Touch-Abhängigkeit

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | Emulator/Gerät ohne Touch-Eingabe (TV-Profil) |
| Schritte | gesamten Fluss nur mit D-Pad/OK/Back durchlaufen |
| Erwartet | keine Funktion erfordert Touch, Hover, Maus oder Gesten |
| Abnahmekriterium | vollständiger Fluss remote-only möglich |
| Evidenz | Screenshots/Video, `adb shell input keyevent`-Protokoll |
| Status | **PASS (Emulator)** – kompletter Fluss remote-only; keine Touch-/Hover-Abhängigkeit festgestellt |

### T-13 Scan-Grenzen (Inventory-/Budget-Limits)

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | viele sichtbare Pakete; langsame Collector-Simulation im Test-Double |
| Schritte | Scan mit erzwungenem Timeout/Fehler eines Collectors; 32-Collector-Grenze prüfen |
| Erwartet | Timeout → `FAILED` + `collector.timeout`; übrige Collectoren laufen weiter; Cancel funktioniert |
| Abnahmekriterium | ein fehlerhafter Collector bricht den Scan nicht ab; Ergebniszustand `PARTIAL`/`FAILED` korrekt |
| Evidenz | Testharness-Log, Exitcodes, Screenshot |
| Status | **PARTIAL** – Timeout-/Failure-Isolation/Cancel sind im `:tv-core`-Harness (35 Tests, 554 Checks) abgedeckt; End-to-End-Scan mit künstlich langsamem Collector im Emulator **NOT_TESTED** |

### T-14 Evidenz-Integrität / Fail-closed

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | Ledger vorhanden |
| Schritte | 1 Byte im Ledger manipulieren → Verify/Report; Keystore-Zugriff simulieren/entziehen (Test-Double) |
| Erwartet | Manipulation wird erkannt; bei fehlender Schlüsselhohheit `UnavailableEvidenceStore`, keine Health-Lüge |
| Abnahmekriterium | Verify erkennt Tamper; keine Writes bei fehlender Custody; UI zeigt Fehlerstatus |
| Evidenz | Testharness-Log, Screenshot |
| Status | **NOT_TESTED** – gesunder Ledger (40 Einträge, HMAC-Kette, „gesund“) ist belegt; Tamper-/Fail-closed-Adversarialtest fehlt |

### T-15 Startzeit / Performance-Budget

| Feld | Inhalt |
| --- | --- |
| Vorbedingung | Debug-APK auf Emulator/Gerät |
| Schritte | Startzeit messen (`adb shell am start -W`), Scan-Dauer, Frame-/Jank-Prüfung (`dumpsys gfxinfo`) |
| Erwartet | keine messbaren Long Tasks, kein ANR; Startzeit dokumentiert |
| Abnahmekriterium | Werte werden gemessen und dokumentiert (kein Zielwert erfinden) |
| Evidenz | Kommandoausgaben mit Werten |
| Status | **PASS (Emulator, Software-GPU)** – TotalTime 1,81–2,29 s; Bootstrap 191–261 ms; `navigate(HOME)` 118–135 ms; erster Frame sichtbar; ~1,4 s Window/Theme/Inflate (Emulator-GPU-Anteil). Reale TV-Hardware **NOT_TESTED** |

---

## 5. Kriterien für PASS je Testfall

Ein Testfall gilt nur als PASS, wenn:

1. das erwartete Verhalten am **Release-nächsten** Artefakt beobachtet wurde (Debug-APK nur für
   UI-Tests; Release-Build für Release-Gates),
2. die Evidenz (Screenshot/Log/Exitcode) vorliegt,
3. keine ungeklärte Abweichung offen bleibt,
4. Einschränkungen (nicht getestete OEMs/Varianten) dokumentiert sind.

---

## 6. Exit-Kriterien für den Release (Stand 29.10.2026)

- Build: `:app:assembleRelease` **Exit 0 belegt** (0.3.0-alpha1, 6.522.110 B,
  SHA-256 `da4110…f2934`), **Alpha-signiert** (CN=VisionGaiaTechnology GeDefense TV Alpha, nicht
  Debug-Key); Produktions-/Upload-Signatur **offen**. Debug-APK 8.811.121 B.
- Tests: `:tv-core:tvCoreCheck` Exit 0 (belegt), `:core:coreCheck` Linux-JVM Exit 0 (belegt,
  Win32 BLOCKED); App-Unit-Tests nicht vorhanden; **Lint 0 Errors / 305 Warnings (V3-Stand)**.
  **V3/Titan (31.10.2026):** `:tv-core:tvTitanCheck` Exit 0, PASS 6624/0 (17 Tests); Regression
  tvCoreCheck/tvV2Check/tvKineticCheck/tvTitanCheck in einem Lauf Exit 0; `compileDebugKotlin`,
  `lintDebug` (0 Errors / 305 Warnings), `assembleDebug`/`assembleRelease` Exit 0 (§9.4).
  Level-3-Root-Lauf und reale TV-Hardware **offen**; Release ist mit Alpha-Zertifikat signiert
  (nicht Debug-Key, aber auch nicht Produktions-/Upload-Key).
- Abnahme: T-01 bis T-15 auf Emulator weitgehend **PASS/PARTIAL** (siehe §4); auf mindestens zwei
  realen TV-Profilen **NOT_TESTED**.
- Security: Release-Blocker offen (Produktions-Signatur, Security-Review, Sicherheits-Meldeweg,
  DSE) – siehe [SECURITY.md](SECURITY.md) §6.
- Datenschutz: Retention (V2) klar als „bis manuelle Löschung“ kommuniziert; Datenschutzerklärung/
  Data-Safety finalisiert (**offen**).
- Dokumentation: Evidenz-Ledger übernommen, [CHANGELOG.md](CHANGELOG.md) aktuell.

**Urteil:** Emulator-/RC-Reifegrad **GOLD / PARTIAL_VERIFIED**; Produktions-Release-Gate
**BLOCKED**. Kein DIAMANT-Anspruch.

---

## 7. Übernommenes Lead-Endledger (29.10.2026)

Emulator: Android 16 Google TV, API 36, AVD `gedefense_tv`, 1920×1080, Software-GPU.

1. `:tv-core:tvCoreCheck` → **Exit 0**, `BUILD SUCCESSFUL`, `PASS 554 / FAIL 0`, 35 Tests (nach
   DeCatalog-Sonderzeichenfix `[{]`/`[}]` erneut grün).
2. `:core:coreCheck` → Win32 **BLOCKED** (Verzeichnis-`fsync` via `FileChannel`); Linux-JVM
   (WSL Ubuntu 24.04, OpenJDK 17.0.20.1) → `CORE_TESTS_PASS`, **Exit 0**.
3. `:app:compileDebugKotlin` → **Exit 0**; `:app:lintDebug` → **Exit 0**, **0 Errors / 169 Warnings**.
4. `:app:assembleDebug` → **Exit 0**, `app-debug.apk` **2.860.091 B** (~2,86 MB, Brand-PNGs inkl.).
5. `:app:assembleRelease` → **Exit 0**, `app-release.apk` **1.626.209 B**, R8-minifiziert, mit
   **Debug-Zertifikat** signiert (Produktions-Blocker F-01); installiert/gestartet (Smoke-Test);
   Artefakt vor letztem Redesign → finaler RC-Rebuild erfolgt (1.626.209 B, debug-signiert, Emulator-Smoke-Test).
6. Kaltstart (Debug): `am start -W` TotalTime **1,81–2,29 s**; App-Bootstrap 191–261 ms;
   `navigate(HOME)` 118–135 ms; erster sichtbarer Frame ohne schwarzen Screen; ~1,4 s
   Window/Theme/Inflate (Emulator-Software-GPU). Vor Performance-Fix: `navigate` 4.519 ms;
   nachher 118–135 ms (TI-Status O(1), persistierter Snapshot, Hintergrund-Validierung ~1,1 s).
7. Scan per D-Pad: `PARTIAL` / „Teilweise abgeschlossen“ / „Teilweise Sicht“, 3 Befunde,
   6 Prüfbereiche, Daueranzeige; kein Crash (Logcat clean).
8. TI-Sync: 9/9 Feeds aktuell, Feed-Liste mit Records/Modus; HMAC-Cache verifiziert.
9. Evidenz: „Evidenzspeicher gesund“, 40 Einträge, HMAC-Kette; `TvKeyCustody` (Keystore-gewrappter
   256-bit-Root + domain-separierte Software-Subkeys); Keyring
   `no_backup/evidence/keyring.v1`; Alt-Ledger in `no_backup/evidence/legacy/` archiviert.
10. Export: SAF-Stub erkannt → MediaStore-Fallback schreibt
    `/sdcard/Download/GeDefenseTV/GeDefense-TV-Report-<UTC>.txt` + `.json` (**30.246 B** /
    **4.562 B**, valides JSON), keine Storage-Permission.
11. Restart (`force-stop` + Start): Home zeigt persistierte Summary (Score/Band/Status + ehrlicher
    Neustart-Hinweis), Check „Letzter Lauf“; Apps/Härtung summary-aware „Details nicht im Speicher“.
12. D-Pad: alle Screens erreichbar, Listen fokussierbar/scrollbar, Delete zweistufig, LEFT zur
    Rail, BACK korrekt, keine Touch-Abhängigkeit; Text Weiß-Familie (Kontrast ≥ 4,5:1), Gold nur
    Brand/Primary/Warning, Blau live/info, Grün verifiziert, Rot kritisch.
13. Redesign: Original-GeDefense-Logo (Rail, Settings/About, Launcher-Banner `tv_banner.png`
    640×360, App-Icon `ic_tv_launcher.png` 512×512, Hero-Watermark); Screenshots 80–96
    (1920×1080) in `docs/screenshots/`.

**Eigene read-only Gegenprüfung (Doku-Team, 29.10.2026):** Emulator `emulator-5554` aktiv;
`ro.build.version.sdk=36`, `release=16`, Fingerprint `…:user/dev-keys`,
`security_patch=2026-04-01`; App installiert (`versionName=0.1.0-alpha1`, versionCode 1,
DEBUGGABLE); Dateien im Download-Ordner (30.246 B/4.562 B) und im privaten
`no_backup/evidence` (Ledger 19.169 B, 32 Zeilen, `keyring.v1` 61 B, Legacy-Archiv 14.375 B)
per `adb shell`/`run-as` verifiziert. Keine eigenen Gradle-Builds ausgeführt.

---

## 8. V2-Abnahmematrix (Loopback-VPN, Traffic, XDR, Onboarding)

**Status: ALLE V2-Tests NOT_TESTED** (Stand 29.10.2026; V2-Implementierung in Arbeit, keine
V2-Builds/Läufe/Screenshots). Die Fälle werden erst mit dem Lead-V2-Ledger auf PASS/PARTIAL
gesetzt. Architektur: [docs/V2-ARCHITECTURE.md](docs/V2-ARCHITECTURE.md); Karte:
[docs/TRAFFIC-MAP.md](docs/TRAFFIC-MAP.md); Onboarding: [docs/ONBOARDING.md](docs/ONBOARDING.md).

### 8.1 Voraussetzungen und Umgebung

- Emulator: Android 16 Google TV, API 36, AVD `gedefense_tv`, 1920×1080 (V1-Umgebung).
- V2-Debug-APK mit Helper-Binaries (`arm64-v8a`/`x86_64`); `jniLibs.useLegacyPackaging=true`.
- `adb` und D-Pad-Eingaben (`adb shell input keyevent …`).
- Für Konsistenz: App-Daten vor Onboarding-Tests löschen (`adb shell pm clear
  de.visiongaia.gedefense.tv`) – **nur Testgerät**.
- Für Always-On/Restart: Test-AVD darf ohne Netzwerkfolgen neu gestartet werden.
- Keine produktiven Feed-/echten Nutzerdaten in Testberichten.

### 8.2 Testfälle

| ID | Testfall | Vorbedingung/Schritte | Erwartet / Abnahmekriterium | Reproduktion (Auszug) | Status |
| --- | --- | --- | --- | --- | --- |
| V2-T-01 | Erststart/Onboarding vollständig | App-Daten löschen, App starten | Assistent erscheint, alle Schritte per D-Pad, Abschluss führt zu Home; kein Crash | `adb shell pm clear …`; `adb shell am start -n de.visiongaia.gedefense.tv/.TvMainActivity`; `adb logcat -s GeDefenseTv:* AndroidRuntime:E` | **NOT_TESTED** |
| V2-T-02 | Sir-Quacksec-Animation/Skip | Erststart oder App-Start | Animation einmal pro Start, überspringbar (OK/BACK), kein Endlos-Loop, keine Audio-/Netzwerkpflicht | Screenshot/`screenrecord`; `input keyevent KEYCODE_DPAD_CENTER`/`BACK` | **NOT_TESTED** |
| V2-T-03 | VPN-Consent ablehnen | Onboarding/Protection, System-Dialog ablehnen | Status `OFF`/`UNSUPPORTED`, keine „geschützt“-Anzeige, App bleibt nutzbar, erneuter Versuch möglich | Screenshots; `adb shell dumpsys activity services de.visiongaia.gedefense.tv` | **NOT_TESTED** |
| V2-T-04 | VPN-Consent zustimmen/Start | Consent zustimmen | Status `PREPARING`→`ACTIVE` (oder ehrlicher Fehler), TUN sichtbar, FGS-Benachrichtigung sichtbar | `adb shell ip addr show tun0`; `adb shell dumpsys connectivity` (VPN-Eintrag); `adb shell dumpsys activity services …` | **NOT_TESTED** |
| V2-T-05 | VPN stoppen | Aktives VPN stoppen | Datenpfad endet, Status `OFF`, keine Schutzbehauptung; danach wieder startbar | `adb shell ip addr show tun0`; Status-Screenshot | **NOT_TESTED** |
| V2-T-06 | Fail-Closed bei Helper-Ausfall | Aktives VPN, Helper beenden/Fehler provozieren | Status `DEGRADED`/`FAILED` mit Ursache, kein stiller Bypass, TUN-Anker bleibt; Recovery möglich | Prozess-/Fehlerinjektion (Test-Double oder `run-as`-Pfad); Logcat; `dumpsys` | **NOT_TESTED** |
| V2-T-07 | DNS/Tracker-Block positiv | Aktives VPN, Tracker-Ziel im Profil blockiert | Ziel erscheint als `BLOCK`, Zähler steigt, Evidenz/Regel sichtbar | Test-Domain/Ziel aus lokalem Katalog; Screenshot; Logcat | **NOT_TESTED** |
| V2-T-08 | DNS/Tracker-Block negativ (kein Fehlblock) | Aktives VPN, legitimes Ziel (Update/Streaming) | Ziel `ALLOW`; kein Fehlblock bei Default-Profil; Fehlblock-Report möglich | Test-URL/Ziel; Screenshot; Logcat | **NOT_TESTED** |
| V2-T-09 | Fail-open-Kontrolle | Policy-/Profilfehler erzwingen | Keine stille Freigabe; block/korrelierte Aktion bzw. `DEGRADED` | Fehlerinjektion; Logcat; Status-Screenshot | **NOT_TESTED** |
| V2-T-10 | Telemetrie-Aufzeichnung | Aktiver Verkehr durch mehrere Apps | Snapshot zeigt App/Land/evtl. Domain, Bytes, Aktion; Caps eingehalten | `dumpsys`; App-Screenshots; Logcat | **NOT_TESTED** |
| V2-T-11 | Traffic-Map-Routen | Aktiver Verkehr | Karte zeigt plausible Länder/Bögen, Legende, Block-Markierung; keine erfundenen Punkte | Screenshot Traffic; optional Proxy-/Zielvergleich | **NOT_TESTED** |
| V2-T-12 | Traffic-Map-Grenzen | DoT/DoH-App + CDN-Ziel | UI erklärt „Domain nicht sichtbar“/Länder-Schätzung; keine falsche Tracker-Behauptung | Screenshot; Test-App mit DoH | **NOT_TESTED** |
| V2-T-13 | XDR-Korrelation/Dedupe | Gemischte Ereignisse (Block/TI/Sensor) | Erklärbare Findings, keine Duplikate, Quelle/Konfidenz/Zeit sichtbar; keine Malware-Behauptung aus Einzelmerkmal | Screenshots XDR; Evidenz-Ansicht; Logcat | **NOT_TESTED** |
| V2-T-14 | TI-Sync-Modal | TI-Sync starten | Fortschritt completed/total, Logo, Erfolg/Fehler/Stale ehrlich; kein Fake-Fortschritt | Screenshot; `adb logcat`; Netzwerk aus für Fehlerfall | **NOT_TESTED** |
| V2-T-15 | Restart-Persistenz | Scan + VPN + Traffic, danach `force-stop`/Neustart | Status/letzte Prüfung/Traffic-Snapshot gemäß Design, ehrlicher Neustart-Hinweis; Auto-Start nur mit Consent | `adb shell am force-stop …`; `adb reboot`; Screenshots | **NOT_TESTED** |
| V2-T-16 | Always-On/Recovery | Always-On setzen, Emulator neu starten | VPN startet/bleibt gemäß System, kein stiller ungefilterter Zustand, Status ehrlich | `adb shell settings get secure always_on_vpn_app`; `get secure always_on_vpn_lockdown`; `adb reboot`; `dumpsys` | **NOT_TESTED** |
| V2-T-17 | Notification/FGS-Sichtbarkeit | VPN aktiv | Dauerhafte Benachrichtigung sichtbar; ohne Erlaubnis ehrlicher Hinweis, Dienst funktioniert gemäß Android-Regeln | `adb shell dumpsys notification --noredact` (nur Status); Screenshot | **NOT_TESTED** |
| V2-T-18 | Privacy/No-Upload | Laufzeit mit aktivem VPN + Onboarding/Sync | Keine Uploads von Traffic-/App-Metadaten; nur Feed-HTTPS; Code-/Netzwerknachweis | Netzwerk-Mitschnitt/Proxy (Methode festzulegen); Code-Review | **NOT_TESTED** |
| V2-T-19 | Akku/Thermik/Performance | VPN + Traffic 10–15 min, Kaltstart | Keine ANRs/Crashes, Kaltstart- und Frame-Budget dokumentiert, kein Dauer-Polling | `adb shell am start -W`; `dumpsys gfxinfo`; `dumpsys batterystats` vor/nach | **NOT_TESTED** |
| V2-T-20 | App-Wiederherstellung/Deinstallation | App-Daten löschen, neu installieren | Onboarding erneut, keine verwaisten Traffic-/VPN-Zustände, Consent erneut erforderlich | `pm clear`; `adb uninstall`/`install`; Screenshots | **NOT_TESTED** |
| V2-T-21 | Helper-Provenienz im Artefakt | V2-APK entpacken | Beide `.so` vorhanden, Größen/Hashes = dokumentierte Mobile-Werte; Legacy-Packaging | `unzip -l`/`7z l`; `Get-FileHash`/`sha256sum` auf extrahierte `.so` | **NOT_TESTED** |
| V2-T-22 | Policy-Integrität | Policy-/Geo-Datei manipulieren | Manipulation erkannt/abgelehnt oder konservativ behandelt; kein stiller Allow | Test-Double/manipuliertes Asset; Logcat; Status | **NOT_TESTED** |

### 8.3 Zusätzliche Evidenzanforderungen (V2)

1. **Kommando + Exitcode** für alle ADB-Schritte; Rohausgabe oder Screenshot.
2. **Statusbeleg** für VPN (`dumpsys`, `ip addr`, Logcat) inkl. Zustandsübergängen.
3. **D-Pad-Pfad** für Onboarding/Traffic/XDR (Screenshots je Schritt).
4. **Fail-Closed-Beleg**: herbeigeführter Helper-/Policy-Fehler mit beobachtetem, nicht stillem
   Verhalten.
5. **Negativtests**: Fehlblock, DoH-DNS, CDN-Ziel, Consent-Ablehnung.
6. **Privacy-Beleg**: keine Uploads/DNS-Logs; Export enthält keine Roh-Flows/Payloads.
7. **Artefakt-Beleg**: `.so`-Hashes im gebauten APK.
8. **Performance-Beleg**: Kaltstart, Frame-/ANR-Verhalten, Akku-Delta über definiertes Fenster.

**Aktueller Stand:** Keiner dieser V2-Fälle ist ausgeführt; alle bleiben **NOT_TESTED**, bis der
Lead ein V2-Ledger liefert. Es werden **keine** VPN-/Blocking-/Map-Ergebnisse vorweggenommen.

## 8.1 Verified V2 evidence (2026-10-29, Lead smoke run)

Status of this section: **VERIFIED on the Android TV emulator** (Google TV API 36, AVD `gedefense_tv`, 1920x1080 @ 320 dpi, debug build `de.visiongaia.gedefense.tv`). Real TV hardware, production signing and independent audit remain NOT_TESTED.

| Check | Command / method | Result |
|---|---|---|
| tv-core V2 harness | `.\gradlew.bat :tv-core:tvV2Check --console=plain` | exit 0, `PASS 4398 / FAIL 0`, 28 tests |
| V1 regression harness | `.\gradlew.bat :tv-core:tvCoreCheck --console=plain` | exit 0, `PASS 554 / FAIL 0`, 35 tests |
| App build | `.\gradlew.bat :app:assembleDebug --console=plain` | exit 0, APK ~7.72 MB (incl. GaiaNet arm64/x86_64) |
| VPN consent automation | `adb shell cmd appops set de.visiongaia.gedefense.tv ACTIVATE_VPN allow` | `ACTIVATE_VPN: allow`; VpnService start without dialog |
| Local TUN established | `adb shell ip -o addr` | `tun0 inet 10.253.0.2/32`, `inet6 fd7a:4744::2/128` |
| Helper process alive | `adb shell ps -A` (Ausgabe nach `gaianet` gefiltert) | `libgedefense_gaianet_v2.so` child process of app UID |
| VPN state ACTIVE | logcat `GeDefenseTvVpn` | `VPN state=ACTIVE threatRecords=54689 freshAnchor=true`, telemetry first flow observed |
| Honest degraded state | first start with empty TI cache | `VPN state=DEGRADED threatRecords=0`, onboarding label „Eingeschränkt“; after TI sync refresh → ACTIVE |
| DNS/tracker blocking | `adb shell ping -c 1 doubleclick.net` / samsungads.com / samba.tv / inscape.tv / alphonso.tv | all `ping: unknown host` (NXDOMAIN); `example.com` resolves |
| Blocked-flow telemetry | `run-as de.visiongaia.gedefense.tv cat shared_prefs/gedefense_tv_traffic.xml` | `blockedFlows=6`, history entries `doubleclick.net` / `BLOCK` / `udp`, domain counters `blockedQueries=1` each |
| Geo country attribution | Traffic screen + store | country `US` resolved from offline geo generation after first sync (`files/geo-country/generations/...`), routes drawn US→US; unknown owners remain „Nicht zuordenbar“ |
| Traffic map | route `TRAFFIC` | live HUD (bytes/flows/blocked), map routes, top destinations, per-app cards |
| XDR incidents | route `XDR` after ≥3 blocked flows | 2–3 explainable incidents (`xdr-new-app`, `xdr-correlated`) with score, signals, context panel; empty delta no longer erases cached incidents |
| TI sync popup | Threat Intel → „Jetzt synchronisieren“ | overlay with logo + progress; `threatintel.sync ms=3322 ok=true available=9` |
| First-run onboarding | `pm clear` + launch | 6 steps, primary action focus, prefs `vpn.protection_setup_done=true`, `onboarding.done=true`, HOME with rail |
| Auto-start after restart | force-stop + relaunch | `VPN start requested` + TUN re-established within ~4 s; protection widget „Schutz aktiv“ |
| Sir Quacksec welcome | force-stop + relaunch | animated overlay visible, auto-dismiss/skippable, no crash |
| Startup time | logcat `GeDefenseTv` | `shell=62ms navigate=170ms firstFrameQueued=385ms` |
| Crash-free smoke | `adb logcat` filter `FATAL EXCEPTION` | none during onboarding, protection, traffic, XDR, TI sync, restart |

Screenshots (Lead QA): `docs/screenshots/` — onboarding `W01…X10`, protection `Y01`, traffic `Y02/Z05/Z07/Z09`, XDR `Z06/Z08`, TI modal `V26/V27`, welcome `V30`.

Known limitations in this evidence run: shell/netd DNS owners resolve to `uid-unresolved` (displayed as „Nicht zuordenbar“, not as a fake app); map origin comes from TV locale (US emulator, no GPS); first geo sync downloads public CSV datasets in the background and can take minutes; ICMP echo itself is not a reachability test through the userspace stack.

---

## 9. V3-Abnahmematrix (Titan Engine, 0.3.0-alpha1)

**Status: Domain-, Build-, Lint-, Level-1- und Witness-(lokal-)Tests verifiziert; Level 3 (Root),
reale TV-Hardware und Produktions-Signatur offen.** Belegt (Lead-Lauf 31.10.2026):
`:tv-core:tvTitanCheck` PASS 6624 / FAIL 0 (17 Tests, Exit 0), Regression in einem Lauf
(tvCoreCheck 554/0, tvV2Check 4398/0, tvKineticCheck 3025/0, tvTitanCheck 6624/0, Exit 0),
`compileDebugKotlin`/`assembleDebug`/`assembleRelease` Exit 0, `lintDebug` 0 Errors / 305 Warnings,
Level-1-Emulatorlauf inkl. D-Pad-Navigation/Onboarding/Home-Strip, Witness-Runtime PASS (lokal) und
Übersetzungsprüfung PASS. Witness-Mobile-Push, Shizuku-Ausführung und Quarantäne-UI sind **nicht
ausgeliefert**; Level 3 (Root-Kanal) ist auf dem Emulator nicht prüfbar. Architektur:
[docs/TITAN-TV-ARCHITECTURE.md](docs/TITAN-TV-ARCHITECTURE.md); Threat-Model:
[THREAT-MODEL.md](THREAT-MODEL.md) §16 ff.; Security-Gates: [SECURITY.md](SECURITY.md) §18.

### 9.1 Voraussetzungen und Umgebung

- **Level-1-Umgebung:** bestehender TV-Emulator (Android 16 Google TV, API 36, AVD
  `gedefense_tv`) **ohne** Root/Shizuku; Debug-APK mit Titan-Code.
- **Level-3-Umgebung:** separates Testgerät/TV-Box mit **Magisk/KernelSU/APatch** und
  nutzerbestätigtem `su`; ausschließlich Testgerät, keine produktiven Daten.
- **Level-2-Umgebung:** Gerät mit installierter Shizuku-App (nur Erkennung zu prüfen).
- `adb`, D-Pad-Eingaben (`adb shell input keyevent …`), Zugriff auf `logcat`.
- V3-Debug-APK; für die Root-Matrix vor jedem Test **Ausgangszustand dokumentieren**
  (deaktivierte Apps, iptables-Regeln, ADB-Port), damit Restore belegbar ist.

### 9.2 Testfälle

| ID | Testfall | Vorbedingung/Schritte | Erwartet / Abnahmekriterium | Status |
| --- | --- | --- | --- | --- |
| V3-T-01 | Build/Lint | `:app:assembleDebug`, `:app:lintDebug`, `:app:assembleRelease` | Exit 0, Lint-Report ohne Errors; Artefaktgröße protokolliert | **PASS** – compileDebugKotlin/assembleDebug/assembleRelease Exit 0; `lintDebug` 0 Errors / 305 Warnings; Release-APK 6.522.110 B, Debug-APK 8.811.121 B |
| V3-T-02 | `:tv-core` Titan-Harness | Lead-Lauf des Titan-JVM-Harness | Exit 0, PASS-Zahl/FAIL 0 protokolliert | **PASS** – 6624 / FAIL 0, 17 Tests, Exit 0 |
| V3-T-03 | Non-Root Level 1 ohne Crash | Level-1-Gerät, App starten, TITAN LIVE öffnen, Scan starten | Level `STANDARD`, Capabilities leer, keine Aktion möglich, keine `su`-Prompts, kein Crash, ehrliche Hinweise | **PASS (Emulator)** – Level 1, 7 Capabilities „Unavailable“, Scan `ms=754 level=STANDARD caps=0`, kein AndroidRuntime-Crash |
| V3-T-04 | Passive Privilegdetektion | Level-1-/Level-3-Gerät, Scan | `su`-Pfade/Manager/SELinux/test-keys/ADB-Flag korrekt erkannt oder `UNKNOWN`; Dirty Root als Befund angezeigt | **PASS (PARTIAL, Emulator)** – keine `su`/Shizuku-Marker → kein Aktivierungs-Button; marker-positive Erkennung **NOT_TESTED** |
| V3-T-05 | Aktivierung mit Consent | Level-3-Gerät, „Titan aktivieren“ bestätigen | `id`-Probe über bestätigten Kanal, Level `ROOT`, Capabilities effektiv sichtbar | **NOT_TESTED** (kein Root-Image; nur JVM-Pfad) |
| V3-T-06 | Aktivierung abgelehnt | Level-3-Gerät, Root-Prompt ablehnen | Level bleibt `STANDARD`, Capabilities leer, kein Crash, erneuter Versuch möglich | **NOT_TESTED** (kein Root-Image) |
| V3-T-07 | Capability-Gating | Level 1/2/3 vergleichen | UI/Report zeigen nur effektive Fähigkeiten; theoretische Menge nicht sichtbar | **PASS (JVM + Emulator Level 1)** – Harness prüft effektive Menge; Emulator zeigt 7× „Unavailable“, `caps=0` |
| V3-T-08 | Socket-Provenance | Level-3-Gerät mit Test-Verbindung, Scan | Endpunkt→PID→Paket korrekt oder `UNATTRIBUTED`; Caps/`truncated` respektiert; kein „clean“ | **NOT_TESTED** |
| V3-T-09 | ADB-Port-Erkennung | ADB-over-TCP aktiv | Erkennung als `ADB_EXPOSED`/`titan-adb-exposed` | **NOT_TESTED** |
| V3-T-10 | FIM-Baseline/Delta | Level-3, Baseline erzeugen; Datei in `/data/local/tmp` anlegen/ändern | `BASELINE_CREATED` → `NEW_FILE`/`MODIFIED`; unlesbare Datei `UNREADABLE` | **NOT_TESTED** |
| V3-T-11 | Freeze/Restore | Test-Medien-App (nicht geschützt) einfrieren, dann wiederherstellen | App deaktiviert/reaktiviert, Evidenz je Aktion, keine System-App betroffen | **NOT_TESTED** |
| V3-T-12 | UID-Quarantäne/-Freigabe | Test-App mit eigener UID isolieren, dann freigeben | Outbound der UID blockiert/frei, Regel verifiziert, Rest-TV ungestört | **NOT_TESTED** |
| V3-T-13 | Prozess-Kill | harmlosen Testprozess beenden | Prozess beendet, Verifikation dokumentiert; PID 1/eigene PID unmöglich | **NOT_TESTED** |
| V3-T-14 | ADB-Lockdown | ADB-Port offen, Aktion bestätigen | Port geschlossen/`adbd` gestoppt, Evidenz; kein stiller Eingriff | **NOT_TESTED** |
| V3-T-15 | Policy-Ablehnungen | geschütztes Systempaket, UID < 10 000, PID 1, eigene UID/PID, Rate-Limit, Mengenlimit | Jeweils `PROTECTED_TARGET`/`INVALID_TARGET`/`NOT_AUTHORIZED`/`RATE_LIMITED`/`LIMIT_REACHED`, keine Ausführung | **NOT_TESTED** |
| V3-T-16 | Injection-Negativtest | manipulierte Ziele/Pfade/Dateinamen | Validierung lehnt ab; keine Shell-Metazeichen, kein `..`, kein freies Kommando | **NOT_TESTED** |
| V3-T-17 | Evidenz-Ereignisse | alle Titan-Pfade einmal auslösen | Einträge mit `titan-*`-IDs, secret-frei, HMAC-Kette gesund | **NOT_TESTED** |
| V3-T-18 | Witness-Checkpoint | Checkpoint erzeugen/neu berechnen | Sequenz/Digest/MAC valide, Status `READY` mit Note „nicht gekoppelt“, `PAIRED` nie ohne Gegenpart | **PASS (Runtime, Emulator)** – `state=READY`, `checkpoints=1`, `prefix=82b6992b31d31034`, `sequence=1`; neues `witness-checkpoint`-Event, Ledger gesund (9 Records); UI zeigt „Checkpoints: 1 · Last checkpoint: just now“ + Unpaired-Note. Mobile-Push weiterhin **nicht ausgeliefert** |
| V3-T-19 | TITAN-LIVE-UI/D-Pad | alle Zustände per D-Pad durchlaufen | Fokus sichtbar, keine Touch-Abhängigkeit, ehrliche Zustände, Screenshots | **PASS (PARTIAL, Emulator)** – Level 1: LEFT → Rail, DOWN×7 → „Titan Live“ (content-desc „Privilege level, socket radar and quarantine“), OK → Screen; Home-Strip „Titan · Level 1 · Standard“/„Open Titan“; Onboarding per D-Pad abgeschlossen; Screenshots `titan-02…05`, `titan-13…15`. Level-3-Containment-Dialoge **NOT_TESTED** |
| V3-T-20 | Restart/Persistenz | Scan, `force-stop`, Neustart | Status/Baseline gemäß Design, ehrlicher Neustart-Hinweis, keine erfundene Historie | **NOT_TESTED** |
| V3-T-21 | Performance/Akku | Titan-Scan mehrfach, Messfenster | Kein Dauer-Polling, Scanzeit/Budget dokumentiert, keine ANRs | **NOT_TESTED** |
| V3-T-22 | No-Upload/Datenschutz | Titan-Pfade mit lokalem Mitschnitt | Keine ausgehenden Titan-Daten, keine Secrets in Logs/Export | **NOT_TESTED** |

### 9.3 Zusätzliche Evidenzanforderungen (V3)

1. **Kommando + Exitcode** für Build/Lint/Harness; Rohausgabe oder Logdatei.
2. **Vorher-/Nachher-Beleg** für Containment (deaktivierte Pakete, iptables-Regeln, ADB-Property) —
   inklusive dokumentiertem Restore.
3. **Negativbelege:** abgelehnter Consent, geschützte Ziele, Injection-Versuche, unlesbare FIM-Datei.
4. **Level-1-Schutzbeleg:** keine `su`-Prompts, keine Crashes, keine Capability-Behauptung.
5. **Evidenz-/Witness-Beleg:** Ledger-Einträge und HMAC-Kette geprüft.
6. **Screenshot/Video** für TITAN LIVE und alle Containment-Bestätigungsdialoge.
7. **Privacy-Beleg:** keine Uploads, keine Secrets in Logs/Export.
8. **Ehrlichkeits-Beleg:** Report/UI behaupten nirgends „geschützt/clean“ ohne `FULL`+bestätigte
   Capability.

**Aktueller Stand:** Domain-/Harness-, Build-, Lint-, Level-1- und Witness-(lokal-)Ebene sind
verifiziert (§9.4). Offen bleiben **Level 3 (Root-Kanal)** (nur JVM-verifiziert; Emulator ohne `su`,
produktives Google-TV ohne `adb root`), reale TV-Hardware, Produktions-/Upload-Signatur und die
nicht ausgelieferten Alpha-Gaps (Shizuku-Ausführung, Mobile-Witness-Push, Quarantäne-UI). Die
verbindliche Zusammenfassung steht in [CHANGELOG.md](CHANGELOG.md) `[0.3.0-alpha1]`.

### 9.4 Verifizierte V3-Evidenz (Lead-Lauf 31.10.2026, finale Zahlen)

Umgebung: Windows-Host, JDK 17, Gradle-Wrapper; Emulator Android 16 Google TV (API 36), AVD
`gedefense_tv`, 1920×1080 (320 dpi), Debug-/Release-Build.

| Prüfung | Befehl / Methode | Ergebnis |
| --- | --- | --- |
| Titan-JVM-Harness | `.\gradlew.bat :tv-core:tvTitanCheck --console=plain` | Exit 0, `PASS 6624 / FAIL 0`, 17/17 Tests, `BUILD SUCCESSFUL` |
| Regression (ein Lauf) | `tvCoreCheck` + `tvV2Check` + `tvKineticCheck` + `tvTitanCheck` | Exit 0; 554/0 (35), 4398/0 (28), 3025/0 (23), 6624/0 (17) |
| App-Compile | `:app:compileDebugKotlin` | `BUILD SUCCESSFUL`, Exit 0 (nur Deprecation-Warnungen) |
| Lint | `:app:lintDebug` | `BUILD SUCCESSFUL`, Exit 0, **0 Errors / 305 Warnings** (`dist/lint-results-debug.txt`; Anstieg durch Titan-/V3-Ressourcen/-Tests) |
| Debug-Build | `:app:assembleDebug` | `BUILD SUCCESSFUL`, Exit 0; `app-debug.apk` **8.811.121 B**, SHA-256 `2fb107bb473bff4c6bcdbe8ed97605d057bd7e18b404bf80561331a25087b2d4` |
| Release-Build | `:app:assembleRelease` | `BUILD SUCCESSFUL`, Exit 0; `app-release.apk` **6.522.110 B**, SHA-256 `da4110eb18ed9376b2c16ad70065c9f39a1f7592865b612a469e969b0f3f2934`, signiert **CN=VisionGaiaTechnology GeDefense TV Alpha, OU=Android TV, O=VisionGaiaTechnology** (nicht Debug-Key); installiert/gestartet (Onboarding, kein Crash) |
| Staging | `dist/` | `VGT_GeDefense_TV_0.3.0-alpha1_VC4_debug.apk`, `…_VC4_release-signed.apk`, `SHA256SUMS` ergänzt |
| TITAN LIVE Level 1 | App starten, Reiter TITAN, Scan per D-Pad | Level `STANDARD`, alle **7 Capability-Schilder „Unavailable“**, ehrliche Passivmodus-Erklärung, **kein Aktivierungs-Button** (kein `su`-/Shizuku-Marker) |
| Passiver Titan-Scan | Controller-Log (`GeDefenseTv`) | `titan scan ms=754 level=STANDARD caps=0`; Status in app-privaten Prefs persistiert; kein AndroidRuntime-Crash |
| Erststart/Onboarding | D-Pad | Onboarding abgeschlossen; APP danach im Home mit Titan-Strip |
| D-Pad-Navigation | `input keyevent` | LEFT → Rail; DOWN×7 → „Titan Live“ (content-desc „Privilege level, socket radar and quarantine“); OK → Titan-Screen |
| Home-Titan-Strip | Home-Screen | „Titan · Level 1 · Standard“, „Open Titan“ sichtbar |
| Witness (Runtime) | Titan-Scan + Ledger | `state=READY`, `checkpoints=1`, `prefix=82b6992b31d31034`, `sequence=1`; `witness-checkpoint`-Event, Ledger gesund (9 Records); UI „Checkpoints: 1 · Last checkpoint: just now“ + Unpaired-Note |
| Übersetzungen | `tools/check_translations.py --include-plurals` | **PASS** – 0 Probleme, 6 Locales, je 890 String-Keys, je 9 Plural-Gruppen |
| Multi-Resolution | Density 426 (2K-äquivalent) / 640 (4K-äquivalent) | Rendering korrekt; Framebuffer blieb 1920×1080 → **echtes 2K/4K-Framebuffer NOT_TESTED** |
| Screenshots | `docs/screenshots/` (Lead-Verifikation Level 1) | TITAN-LIVE-/Home-Zustände Level 1 |

**Nicht belegt / offen:** Level-3-Lauf (Emulator-Image ohne `su`; produktives Google-TV-Image
erlaubt kein `adb root` — Kommandopfad nur JVM-Harness-verifiziert), freiwilliger Root-Prompt
(Ablehnung/Zustimmung) auf realem Gerät, reale TV-Hardware, echtes 2K-/4K-Framebuffer-Rendering,
Produktions-/Upload-Signatur (Alpha-Zertifikat), Shizuku-Ausführung, Mobile-Witness-Push und
Quarantäne-UI (read-only Vault).
