# GeDefense TV — Build-Runbook

> **Release-Tree 0.2.0-alpha1:** Dieses Dokument ist für den Quellstand `0.2.0-alpha1` (VersionCode 2) kuratiert. Evidenzangaben mit Datum 29.10.2026 beziehen sich auf den jeweils genannten Build; V2/V2.1-Funktionen sind Alpha und nicht vollständig auf realer TV-Hardware abgenommen.


**Version:** 0.2.0-alpha1 · **Stand:** 29. Oktober 2026 · **Status:** Runbook vollständig;
Build-/Lint-/Emulator-Evidenz übernommen (PARTIAL_VERIFIED); finaler RC-Rebuild erfolgt (1.626.209 B, debug-signiert, Emulator-Smoke-Test)

Dieses Runbook beschreibt die realen Build-/Testbefehle, Umgebungsannahmen, Artefaktpfade und
Fehlerbehebung. Es dient dazu, jeden Lauf reproduzierbar und mit ehrlicher Evidenz zu protokollieren.

---

## 1. Voraussetzungen

| Komponente | Anforderung | Status in der Referenzumgebung (29.10.2026) |
| --- | --- | --- |
| JDK | 17 (Temurin/Android Studio JBR) | `%JAVA_HOME%` vorhanden |
| Android SDK | Plattform `android-36`, Build-Tools `36.0.0` | installiert |
| SDK-Pfad | `local.properties` `sdk.dir` oder `ANDROID_HOME` | `%ANDROID_HOME%` |
| Gradle | 8.7 via Wrapper, Distribution-SHA-256 gepinnt | `gradle/wrapper/gradle-wrapper.properties` |
| Kotlin/AGP | Kotlin 1.9.24, AGP 8.5.2 | `build.gradle.kts` |
| Netzwerk | `google()`, `mavenCentral()` erreichbar; optional lokaler Mirror | `settings.gradle.kts` |
| Plattform-Tools | `adb` (für Installation/Emulator) | `platform-tools` installiert (37.0.0) |

Der Wrapper ist eingecheckt (`gradlew`, `gradlew.bat`, `gradle/wrapper/*`); es ist **kein**
separat installiertes Gradle nötig.

---

## 2. Umgebung setzen (PowerShell)

```powershell
# JDK 17 (Android Studio JBR)
$env:JAVA_HOME = '%JAVA_HOME%'

# optional: SDK explizit setzen (sonst greift local.properties)
$env:ANDROID_HOME = '%ANDROID_HOME%'
$env:ANDROID_SDK_ROOT = $env:ANDROID_HOME

# optional: lokaler Maven-Mirror (wird in settings.gradle.kts beruecksichtigt)
# $env:VGT_LOCAL_MAVEN = 'C:\pfad\zu\maven-mirror'
```

Prüfen:

```powershell
& "$env:JAVA_HOME\bin\java.exe" -version
& "$env:ANDROID_HOME\platform-tools\adb.exe" version
```

> Die Skripte `tools/build.ps1` und `tools/test.ps1` setzen `JAVA_HOME` auf den Android-Studio-JBR
> und lesen `sdk.dir` aus `local.properties`, wenn die Variablen fehlen.

---

## 3. Build-Befehle

### 3.1 Direkt über den Wrapper

```powershell
# Debug-APK
.\gradlew.bat :app:assembleDebug --console=plain

# Release-APK (benoetigt Release-Signatur, siehe §5)
.\gradlew.bat :app:assembleRelease --console=plain

# Lint
.\gradlew.bat :app:lintDebug --console=plain

# Alle Module bauen
.\gradlew.bat assembleDebug --console=plain

# Sauberer Lauf
.\gradlew.bat clean :app:assembleDebug --console=plain
```

### 3.2 Über das dokumentierte Skript (mit Evidenz-Log)

```powershell
.\tools\build.ps1                                  # assembleDebug
.\tools\build.ps1 -Release                         # assembleRelease
.\tools\build.ps1 -Tasks assembleDebug,lintDebug
.\tools\build.ps1 -Clean -NoDaemon
.\tools\build.ps1 -Tasks :app:assembleDebug -LogPath .output\build-verify.log
```

Das Skript schreibt pro Lauf ein Log nach `.output/build-<Zeitstempel>.log` (gitignoriert) mit
Zeitpunkt, Befehl, Umgebung, Exitcode und Rohausgabe. Es interpretiert das Ergebnis **nicht** um.

### 3.3 Testharnesses

| Task | Modul | Zweck |
| --- | --- | --- |
| `:core:coreCheck` | `:core` | JavaExec-Harness des vendored Mobile-Core (`CoreTestMainKt`); benötigt ein POSIX-/Linux-JVM (nutzt Verzeichnis-`fsync` via `FileChannel`). Unter Win32 **BLOCKED**; auf Linux (WSL/CI) verifiziert. |
| `:tv-core:tvCoreCheck` | `:tv-core` | JavaExec-Harness der TV-Domäne (`TvCoreTestMainKt`); plattformunabhängig. |
| `:app:testDebugUnitTest` | `:app` | lokale JVM-Unit-Tests der App (falls vorhanden) |

```powershell
.\gradlew.bat :core:coreCheck --console=plain        # nur auf Linux-JVM / WSL
.\gradlew.bat :tv-core:tvCoreCheck --console=plain
.\tools\test.ps1 -IncludeAppTests -Lint
```

> **Belegter Stand (29.10.2026, Verifikationsprotokoll):**
> `:tv-core:tvCoreCheck` → Exit 0, `PASS 554 / FAIL 0`, 35 Tests, `BUILD SUCCESSFUL`.
> `:core:coreCheck` auf Linux-JVM (WSL Ubuntu 24.04, OpenJDK 17.0.20.1) → `CORE_TESTS_PASS`,
> Exit 0; auf dem Windows-Host BLOCKED (Win32-`fsync`-Limitierung).
> `:app:compileDebugKotlin` → Exit 0; `:app:lintDebug` → Exit 0, **0 Errors / 169 Warnings**;
> `:app:assembleDebug` → Exit 0 (`app-debug.apk` **2.860.091 B** ≈ 2,86 MB);
> `:app:assembleRelease` → Exit 0 (`app-release.apk` **1.626.209 B**, R8-minifiziert,
> **debug-signiert**; offener Punkt für die Produktion F-01); Release installiert/gestartet (Smoke-Test,
> Artefakt vor letztem Redesign → finaler RC-Rebuild erfolgt (1.626.209 B, debug-signiert, Emulator-Smoke-Test)).
> Kaltstart (Debug, Emulator, Software-GPU): `am start -W` TotalTime **1,81–2,29 s**,
> App-Bootstrap 191–261 ms, `navigate(HOME)` 118–135 ms; TI-Status O(1) (vorher 4.519 ms).
> App-Unit-Tests: **NOT_TESTED**.

Das Test-Skript weist jeden Schritt einzeln mit Exitcode aus und liefert nur dann Gesamt-PASS,
wenn **alle** ausgeführten Schritte Exitcode 0 haben. Auf einem Windows-Host überspringt es
`:core:coreCheck` und weist den Schritt ausdrücklich als **UEBERSPRUNGEN** aus (nicht als PASS);
mit `-ForceCoreCheck` wird der Lauf versucht (erwartbar BLOCKED).

---

## 4. Artefakte und Logs

| Artefakt | Pfad (typisch) |
| --- | --- |
| Debug-APK | `app/build/outputs/apk/debug/app-debug.apk` – zuletzt **2.860.091 B** (29.10.2026 12:11) |
| Release-APK | `app/build/outputs/apk/release/app-release.apk` – zuletzt **1.626.209 B**, R8, **debug-signiert** (29.10.2026 11:27) |
| Lint-Berichte | `app/build/reports/lint-results-debug.html` (bzw. `.txt`/`.xml`) – **0 Errors / 169 Warnings** |
| Test-Berichte | `*/build/reports/tests/` |
| Evidenz-Logs der Skripte | `.output/build-*.log`, `.output/test-*.log` |
| Vendored-Core-Prüfung | Ausgabe von `tools/verify-source-fidelity.ps1` |

> Die APK-Hashes ändern sich mit dem finalen RC-Rebuild und werden deshalb hier **nicht** als
> Release-Hashes festgeschrieben. Für den aktuellen Build können sie mit `Get-FileHash` gelesen
> werden (siehe §5).

Keystores aus. **Keine** Keystores/Passwörter committen.

---

## 5. Release-Signatur (wichtig)

Die Release-Signatur wird in `app/build.gradle.kts` nur dann konfiguriert, wenn **alle vier**
Umgebungsvariablen gesetzt sind:

```powershell
$env:GEDEFENSE_RELEASE_STORE_FILE     = 'C:\sicher\gedefense-release.jks'
$env:GEDEFENSE_RELEASE_STORE_PASSWORD = '<Store-Passwort>'
$env:GEDEFENSE_RELEASE_KEY_ALIAS      = 'gedefense'
$env:GEDEFENSE_RELEASE_KEY_PASSWORD   = '<Key-Passwort>'
```

**Offener offener Punkt:** Fehlen die Variablen, fällt die `release`-Konfiguration
auf die **Debug-Signatur** zurück. Ein so signiertes 0.2.0-alpha1-APK ist ausdrücklich ein
**debug-signiertes Testartefakt**, kein veröffentlichungsfähiges Release. Vor einer
Veröffentlichung muss der Build ohne echte Release-Signatur abbrechen
(Konfigurationsänderung durch den Projektteam). Dieser Punkt ist in [SECURITY.md](SECURITY.md) als F-01
dokumentiert.

Prüfung des erzeugten Artefakts:

```powershell
& "$env:ANDROID_HOME\build-tools\36.0.0\apksigner.bat" verify --print-certs app\build\outputs\apk\release\app-release.apk
Get-FileHash app\build\outputs\apk\release\app-release.apk -Algorithm SHA256
```

---

## 6. Emulator und APK-Installation

```powershell
# nur Diagnose (veraendert nichts)
.\tools\run-tv-emulator.ps1

# TV-Image installieren (in der Referenzumgebung bereits installiert)
.\tools\run-tv-emulator.ps1 -Install

# AVD anlegen und Emulator starten (Referenz-AVD heisst "gedefense_tv")
.\tools\run-tv-emulator.ps1 -AvdName gedefense_tv -CreateAvd
.\tools\run-tv-emulator.ps1 -AvdName gedefense_tv -Start -WaitForBoot

# APK installieren
.\tools\run-tv-emulator.ps1 -ApkPath app\build\outputs\apk\debug\app-debug.apk
```

Belegter Emulator: **Android 16 Google TV, API 36, AVD `gedefense_tv`, 1920×1080**, Software-GPU;
Debug-APK installiert und gestartet; Scan/TI/Evidenz/Export/Restart/D-Pad verifiziert. Reale
TV-Hardware: **NOT_TESTED**.

Vollständige Anleitung inklusive D-Pad-Bedienung und Screenshots:
[docs/TV-EMULATOR-TESTING.md](docs/TV-EMULATOR-TESTING.md).

---

## 7. Fehlerbehebung

| Symptom | Ursache | Lösung |
| --- | --- | --- |
| `JAVA_HOME is not set` / `java: command not found` | JDK fehlt/ falsch | `JAVA_HOME` auf JBR/JDK 17 setzen; `java -version` prüfen |
| `SDK location not found` | `local.properties` fehlt / `ANDROID_HOME` falsch | `sdk.dir` korrekt setzen (Backslashes escapen) |
| `Failed to find target with hash string 'android-36'` | Plattform fehlt | `sdkmanager "platforms;android-36"` |
| `Could not resolve ...` / Timeout | Netzwerk/Repository | Netzwerk prüfen; optional `VGT_LOCAL_MAVEN` setzen |
| `Unsupported compileSdk 36` (Warnung) | AGP-Version | bereits per `android.suppressUnsupportedCompileSdk=36` unterdrückt; AGP-Upgrade langfristig |
| Build hängt / Lock-Konflikte | parallele Gradle-Läufe | Builds serialisieren; keine parallelen Implementierungs-Builds |
| `sdkmanager` endet mit abnormem Code | sehr alte cmdline-tools (23.0.0) | `sdkmanager --install "cmdline-tools;latest"` (neues Verzeichnis, alten Pfad anpassen) |
| `avdmanager` verweigert TV-Image | alte cmdline-tools/ fehlende `tv_1080p`-Definition | cmdline-tools aktualisieren; `-Device` anpassen |
| `:core:coreCheck` schlägt unter Windows fehl (z. B. `fsync`/`FileChannel`-Fehler) | Win32 unterstützt Verzeichnis-`fsync` nicht; Upstream-Limitierung des vendored Mobile-Core | Lauf auf Linux-JVM (WSL Ubuntu/CI) ausführen; **nicht** den Core patchen |
| Emulator startet nicht | Virtualisierung/HAXM/WHPX | BIOS-Virtualisierung, Windows-Hypervisor-Plattform prüfen |
| `network_security_config` fehlt | Ressource nicht vorhanden (Stand 29.10.2026: vorhanden) | `res/xml/network_security_config.xml` prüfen/neu anlegen |

---

## 8. Evidenz-Disziplin

1. Jeden Lauf mit Befehl, Arbeitsverzeichnis, Zeitstempel und Exitcode protokollieren (Skripte
   erledigen das automatisch).
2. Rohausgabe aufbewahren; Zusammenfassungen sind kein Ersatz.
3. Build-Erfolg ≠ Test-Erfolg ≠ Release-Freigabe. Diese drei Stufen getrennt ausweisen.
4. Keine Ergebnisse aus früheren Sessions als aktuellen Stand ausgeben.
5. Bei Abbruch/Timeout (`[exit code: 1]` ohne Signal) den Lauf als abgebrochen, nicht als
   fehlgeschlagene Assertion behandeln.

---

## 9. Reproduzierbarkeit und Grenzen

- Gradle-Wrapper-Distribution ist per SHA-256 gepinnt; Wrapper-JAR ist eingecheckt.
- Runtime-Abhängigkeiten: keine Drittanbieter-Libraries → kleine Supply-Chain-Fläche.
- Der vendored Core ist per Manifest prüfbar (`tools/verify-source-fidelity.ps1`).
- Git-Repository mit Baseline-Commit `fe555cd`; der RC-Commit erfolgt nach der
  Doku-Evidenzübernahme.
- **Grenzen:** kein reproduzierbarer Byte-für-Byte-Build nachgewiesen; Gradle-/AGP-/Kotlin-Versionen
  sind gepinnt, aber nicht als Lockfile im Gradle-Sinne fixiert; APK-Hashes sind bis zum finalen
  RC-Rebuild vorläufig.
