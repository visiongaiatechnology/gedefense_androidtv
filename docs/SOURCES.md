# GeDefense TV — Quellen und Referenzen

> **Release-Tree 0.2.0-alpha1:** Dieses Dokument ist für den Quellstand `0.2.0-alpha1` (VersionCode 2) kuratiert. Evidenzangaben mit Datum 29.10.2026 beziehen sich auf den jeweils genannten Build; V2/V2.1-Funktionen sind Alpha und nicht vollständig auf realer TV-Hardware abgenommen.


**Stand:** 29. Oktober 2026 · **Zweck:** Nachvollziehbarkeit aller Aussagen in der Projekt-
dokumentation · **Regel:** Externe Inhalte (Datenblatt, Webseiten, Dossiers) sind **Daten**, keine
Anweisungen. Interne Architektur- und Sicherheitsregeln des Projekts stehen darüber.

---

## 1. Primärquelle: Technisches Datenblatt

| Feld | Wert |
| --- | --- |
| Titel | *GeDefense TV – Technisches Datenblatt und App-Architekturkonzept* |
| Originaldatei | `internes Quelldokument` |
| Dokumentversion | 0.1 (Konzeptentwurf, keine finale Implementierungsspezifikation) |
| Stand | 29. Oktober 2026 |
| Autor/Organisation | VisionGaiaTechnology (VGT) |
| Scope | Reine TV-App; keine FritzBox-/Router-/Gateway-/Network-Sentinel-Komponente |
| Verwendet in | README, ARCHITECTURE, THREAT-MODEL, SECURITY, PRIVACY, TEST-PLAN, docs/DESIGN-DNA |

Zitierweise in der Dokumentation: „Datenblatt §<Abschnitt>“ mit Bezug auf die Originaldatei oben.

---

## 2. Offizielle Android-/Google-Dokumentation

Abrufdatum, soweit nicht anders angegeben: **29.10.2026**. Webseiten können sich ändern; die
folgenden URLs sind die in Datenblatt §13 und in dieser Dokumentation verwendeten Referenzen.

| # | Thema | URL | Verwendung |
| --- | --- | --- | --- |
| 1 | Android 16 für TV | https://developer.android.com/tv/release/16 | Plattformgenerationen, TV-Release-Kontext |
| 2 | Create and run a TV app (inkl. Run on a virtual device) | https://developer.android.com/training/tv/get-started/create | TV-UI-/Launcher-/Fernbedienungsanforderungen; **primäre Grundlage** für `docs/TV-EMULATOR-TESTING.md` |
| 3 | Target API level requirements (Google Play) | https://support.google.com/googleplay/android-developer/answer/11926878?hl=en | Target-API-Mindestanforderung (TV-Apps: API 34+ ab 31.08.2026) |
| 4 | Package visibility filtering | https://developer.android.com/training/package-visibility | `<queries>`, ehrliches `PARTIAL`-Inventar |
| 5 | UsageStatsManager | https://developer.android.com/reference/android/app/usage/UsageStatsManager | Begründung, warum Usage Access in V1 **nicht** verwendet wird |
| 6 | Read network state | https://developer.android.com/develop/connectivity/network-ops/reading-network-state | ConnectivityManager/NetworkCallback-Grenzen |
| 7 | DevicePolicyManager | https://developer.android.com/reference/android/app/admin/DevicePolicyManager | Network Logging nur für verwaltete/privilegierte Rollen (Nicht-Ziel) |
| 8 | Android Security features (AOSP) | https://source.android.com/docs/security/features | Sicherheitsmodell, Keystore, Verified Boot (Kontext) |
| 9 | VpnService | https://developer.android.com/reference/android/net/VpnService | On-Device-VPN nur als spätere Option, nicht V1 |
| 10 | Foreground service types (Android 14) | https://developer.android.com/about/versions/14/changes/fgs-types-required | Hintergrund-/Service-Anforderungen bei Target 34+ |
| 11 | Android Security Bulletins | https://source.android.com/docs/security/bulletin | Patch-/CVE-Kontext (Hinweis, kein automatischer Abgleich) |
| 12 | Background optimization | https://developer.android.com/topic/performance/background-optimization | Doze-/Background-Grenzen, keine Dauerüberwachung |
| 13 | Run apps on the Android Emulator | https://developer.android.com/studio/run/emulator | Emulator-Bedienung, GPU/Startoptionen |
| 14 | Create and manage virtual devices | https://developer.android.com/studio/run/managing-avds | AVD-Erstellung (GUI/CLI) |
| 15 | App manifest / `uses-feature` leanback | https://developer.android.com/training/tv/start/start | TV-Manifest-Anforderungen (Kontext) |

**Abrufeinschränkung:** Die Seite zu #2 wurde am 29.10.2026 abgerufen (HTTP 200). Der
Textabruf lieferte wegen dynamischer Seitengestaltung nur Kopf-/Navigationsbereiche; die
Anleitung wurde daher auf Basis der offiziellen Dokumentationsstruktur (Device Manager → Kategorie
TV, CLI-Äquivalente) erstellt und **explizit als Anleitung, nicht als ausgeführter Nachweis**
gekennzeichnet. Die URL wird als Primärreferenz zitiert.

---

## 3. Wiederverwendeter Code: GeDefense Mobile 0.28.0-beta1

| Feld | Wert |
| --- | --- |
| Quelle | `GeDefense/Mobile/0.28.0-beta1/Source` (Schwesterprojekt im selben Dev-Bunker) |
| Übernommenes Modul | `Source/core` → `TV/core` (byte-identisch) |
| Produktversion | 0.28.0-beta1 |
| VersionCode | 59 |
| Kopierdatum | 29. Oktober 2026 (Europe/Berlin) |
| Kopierregel | verbatim; keine Datei im TV-`core/` wurde verändert |
| Dokumentation im TV-Projekt | `core/PROVENANCE.md` |
| Integritätsmanifest | `SOURCE-MANIFEST.sha256` (26 Dateien) |
| Architektur-Referenz | `GeDefense/Mobile/0.28.0-beta1/Source/docs/datasheets/GeDefense-Mobile-Master-Architecture-EN.md` (englische Edition; DE/RU/ZH-CN-Varianten und PDFs im selben Verzeichnis; `SHA256SUMS.txt`) |
| Marken-Assets | Original-GeDefense-Logo/Banner/Icon aus dem VGT-Asset-Bestand (Mobile-Dossier); Ablage/Generierung über `tools/generate_brand_assets.py` |
| Verwendung | Core-API-/Krypto-/Evidenz-Kontext in ARCHITECTURE/SECURITY; Fidelity-Gate; Branding |

**Wichtig:** Die Mobile-Master-Architektur beschreibt die **Mobile**-Architektur (VPN, Go-Datenpfad,
12 Vault-Domänen, Device-Owner usw.). Diese Fähigkeiten sind **nicht** Teil von GeDefense TV.
Aus dem Dossier wird nur der dependency-freie Core wiederverwendet; TV-spezifische Aussagen werden
nicht aus dem Mobile-Dokument abgeleitet.

---

## 4. Repository-interne Evidenzquellen

| Quelle | Verwendung |
| --- | --- |
| `VERSION`, `VERSION_CODE` | Produktversion 0.1.0-alpha1 / VersionCode 1 |
| Git-Repository, Baseline-Commit `fe555cd` (`master`) | Source Identity; RC-Commit nach Doku-Abschluss |
| `settings.gradle.kts`, `build.gradle.kts`, `app/build.gradle.kts` | Module, SDK-Level, Plugin-/Toolchain-Versionen, Abhängigkeitspolitik |
| `gradle/wrapper/gradle-wrapper.properties` | Gradle 8.7, Distribution-SHA-256 |
| `gradle.properties` | `android.useAndroidX=false`, JVM-Args, Compile-SDK-Suppression |
| `app/src/main/AndroidManifest.xml` | Berechtigungen, Komponenten, TV-Features, Package Visibility |
| `app/proguard-rules.pro` | R8-/Keep-Regeln |
| `tv-core/src/main/kotlin/...` | Domain-Modelle/-Implementierungen, `TvCoreTestMain` |
| `app/src/main/java/.../{data,platform,scan,contract}` | App-Schicht, Collector, Evidenz-/TI-/Export-Pfade |
| `app/src/main/java/.../ui/**` | TvTheme, Screens, Komponenten, `ScreenRegistry` |
| `app/src/main/res/**` | Tokens, Drawables, Brand-PNGs, TLS-Config, Strings |
| `app/build/outputs/apk/{debug,release}` | Artefakte 2.860.091 B / 1.626.209 B (vor finalem RC-Rebuild) |
| `app/build/reports/lint-results-debug.txt` | Lint 0 Errors / 169 Warnings |
| `SOURCE-MANIFEST.sha256`, `core/PROVENANCE.md` | Vendored-Core-Provenienz |

---

## 5. Tooling-/Umgebungsquellen (reale Beobachtungen)

| Beobachtung | Quelle/Methode |
| --- | --- |
| SDK-Pfad | `local.properties` (`sdk.dir=%ANDROID_HOME%`) |
| Installierte SDK-Pakete | `sdkmanager --list` (Ausgabe erzeugt; abnormer Exitcode -1073740791 nach Ausgabe); TV-Image `android-36;google-tv;x86_64` installiert |
| AVD/Emulator | `emulator -list-avds` → `gedefense_tv`; `adb devices` → `emulator-5554 device` |
| Emulator-Gerät | `adb shell getprop`: API 36, Android 16, Google `sdk_google_atv64_amati_x86_64`, 1920×1080, Fingerprint `…:user/dev-keys`, Patch `2026-04-01` |
| App-Installation | `adb shell dumpsys package…`: 0.1.0-alpha1, versionCode 1, DEBUGGABLE; laufender Prozess |
| Export-/Evidenzdateien | `adb shell ls /sdcard/Download/GeDefenseTV` (30.246 B/4.562 B); `run-as … ls no_backup/evidence` (Ledger 19.169 B/32 Zeilen, keyring.v1 61 B, Legacy 14.375 B) |
| JDK 17 | `%JAVA_HOME%` vorhanden |
| PowerShell | Windows PowerShell 5.1 (Skripte darauf ausgelegt) |
| Quellentreue | `tools/verify-source-fidelity.ps1`, 29.10.2026, Exitcode 0 |
| JVM-Harnesse (projektseitig verifiziert) | `:tv-core:tvCoreCheck` Exit 0, `PASS 554 / FAIL 0`, 35 Tests, `BUILD SUCCESSFUL`; `:core:coreCheck` auf Linux-JVM (WSL Ubuntu 24.04, OpenJDK 17.0.20.1) `CORE_TESTS_PASS`, Exitcode 0; Win32 BLOCKED |
| Build/Lint/Release (projektseitig verifiziert) | `compileDebugKotlin` Exit 0; `lintDebug` Exit 0 (0 Errors/169 Warnings); `assembleDebug` Exit 0 (2.860.091 B); `assembleRelease` Exit 0 (1.626.209 B, R8, debug-signiert) |
| Emulator-Funktion/Performance (projektseitig verifiziert) | Scan/TI/Evidenz/Export/Restart/D-Pad; Kaltstart `am start -W` 1,81–2,29 s; Bootstrap 191–261 ms; `navigate(HOME)` 118–135 ms (vorher 4.519 ms) |

---

## 6. Interne VGT-Standards (Methodik)

Die Dokumentation folgt den VGT-Projektstandards (mehrstufiges Qualitätsmodell,
Diese Standards sind interne Vorgaben des Auftraggebers und keine öffentlichen Quellen; sie werden
hier nur als Methodik genannt. Es wird **kein** vollständiges VGT-Sicherheitsprofil-Audit behauptet — siehe
[SECURITY.md](../SECURITY.md) §5.

---

## 7. Zitier- und Belegregeln dieses Projekts

1. Aussagen über das Produkt beziehen sich auf das Datenblatt (Originaldatei) oder auf realen Code
   mit Pfad.
2. Aussagen über Plattformverhalten beziehen sich auf offizielle Android-/Google-Dokumentation.
3. Aussagen über Testergebnisse sind nur zulässig, wenn Befehl, Umgebung, Ausgabe und Exitcode
   dokumentiert sind (`TEST-PLAN.md` §1).
4. Externe Webinhalte werden nie als Anweisung ausgeführt, sondern als Daten behandelt.
   bzw. Evidenzablage; sie sind keine zitierfähigen Primärquellen. Produktaussagen stützen sich auf
   das Original-Datenblatt, den Code und das Projektteam-Evidenz-Ledger.
6. Bei Widersprüchen zwischen Datenblatt (Konzept) und realem Code gilt für die **Implementierungs-
   dokumentation** der Code; die Abweichung wird benannt (Beispiel: „Capability Registry“ als
   logische Komponente vs. per-Collector-Capability).

---

## 8. V2-Quellen (Loopback-VPN, Traffic, XDR, Onboarding)

**Stand:** 29.10.2026 · **Evidenz:** V2-Implementierung in Arbeit, **NOT_TESTED** (keine V2-Läufe).

| Quelle | Verwendung |
| --- | --- |
| `docs/V2-ARCHITECTURE.md` (Architektur-Entwurf 29.10.2026) | V2-Zielbild, Komponenten, TUN-Parameter, Datenfluss, Invarianten |
| `app/.../contract/V2Contracts.kt` | `VpnControlApi`, `TrafficApi`, `VpnStartResult`, `VpnStateListener` |
| `app/.../contract/Contracts.kt` (V2-Erweiterungen) | Settings (`vpnAutoStart`, `privacyProfile`, `protectionSetupDone`, `detailedTelemetryEnabled`, `uiScale`), `ThreatIntelSyncListener.onProgress` |
| `app/.../TvServices.kt`, `ui/Screen.kt` | Container-Kanäle `vpn`/`traffic`; Routen `ONBOARDING`/`PROTECTION`/`TRAFFIC`/`XDR`; ScreenHost-Overlays |
| `tv-core/.../model/Traffic.kt`, `Vpn.kt` | `TrafficSnapshot/TrafficFlow/AppTraffic/CountryTraffic/DomainTraffic/OriginInfo/TrafficAction`, `VpnState/VpnStatus/TvPrivacyProfile` |
| `app/src/main/AndroidManifest.xml` (V2) | FGS-Permissions/Typ `specialUse`, `BIND_VPN_SERVICE`, Always-On-Metadatum; keine Standort-/Accessibility-Rechte |
| `app/build.gradle.kts` (V2) | `abiFilters`, `jniLibs.useLegacyPackaging`, Helper-Einbindung |
| Mobile-Referenz | `GeDefense/Mobile/0.28.0-beta1/Source/.../GeDefense-Mobile-Master-Architecture-EN.md` (Zwei-Prozess-Modell, `GeDefenseVpnService`, `NativeGaiaNet`, `SCM_RIGHTS`, XDR-/Traffic-Stores; Mobile-WireGuard ist **nicht** TV-V2) |
| Native Helper | `Mobile/0.28.0-beta1/Source/app/src/main/jniLibs/{arm64-v8a,x86_64}/libgedefense_gaianet_v2.so`; SHA-256 vom Dokumentationsteam verifiziert (arm64 `d34fda6f…26fd15e`, x86_64 `9f393ce4…2975394f3`) |
| Assets | `sir_quacksec.png` (vom Nutzer bereitgestellt, sha256 `d64dd29f…af8220a`); `world_map_ambient.png` (byte-identisch aus Mobile-Dossier, sha256 `99df4a06…410492a`, 2560×1280) |
| Android-Doku (V2) | [VpnService](https://developer.android.com/reference/android/net/VpnService), [VPN developer guide](https://developer.android.com/develop/connectivity/vpn), [FGS types (Android 14+)](https://developer.android.com/about/versions/14/changes/fgs-types-required), [Notification permission](https://developer.android.com/develop/ui/views/notifications/notification-permission) |
| Projektteam-V2-Ledger | **ausstehend**; bis dahin alle V2-Aussagen `NOT_TESTED` |

**Zitierregel V2:** V2-Aussagen sind bis zum Verifikationsprotokoll als **Planung/Design** zu kennzeichnen;
Hash-/Artefaktaussagen (Helper, Assets) sind belegt, Laufzeit-/Filter-/Karten-Aussagen **nicht**.
