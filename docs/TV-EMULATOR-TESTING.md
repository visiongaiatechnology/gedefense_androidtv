# GeDefense TV — Android-TV-Emulator: Einrichtung und verifizierter Test

> **Release-Tree 0.2.0-alpha1:** Dieses Dokument ist für den Quellstand `0.2.0-alpha1` (VersionCode 2) kuratiert. Evidenzangaben mit Datum 29.10.2026 beziehen sich auf den jeweils genannten Build; V2/V2.1-Funktionen sind Alpha und nicht vollständig auf realer TV-Hardware abgenommen.


**Stand:** 29. Oktober 2026 · **Produktversion:** 0.2.0-alpha1 ·
**Status:** Anleitung **plus realer Emulator-Lauf** (Verifikationsprotokoll, read-only durch das Dokumentationsteam
gegengeprüft). Reale TV-Hardware bleibt **NOT_TESTED**.

Diese Anleitung beschreibt, wie ein Android-TV-/Google-TV-Emulator eingerichtet, die APK installiert
und die App mit einer Fernbedienung (D-Pad) geprüft wird. Grundlage ist die offizielle
Android-Dokumentation:

- **[Create and run a TV app — Run on a virtual device](https://developer.android.com/training/tv/get-started/create#run-on-a-virtual-device)**
  (Android Developers, abgerufen am 29.10.2026)
- Ergänzend: [Run apps on the Android Emulator](https://developer.android.com/studio/run/emulator)
  und [Create and manage virtual devices](https://developer.android.com/studio/run/managing-avds)

Die Kommandozeilenbefehle sind eine reproduzierbare Alternative zur Android-Studio-GUI (die
offizielle Anleitung beschreibt den Weg über **Tools → Device Manager → Create Device → Kategorie
„TV“**). Der in diesem Projekt tatsächlich verwendete Emulator ist unten dokumentiert; Befehle,
die nur Anleitung sind, sind entsprechend eingeordnet.

---

## 1. Verifizierter Emulator-Stand (29.10.2026)

| Prüfung | Ergebnis |
| --- | --- |
| SDK | `%ANDROID_HOME%` |
| Plattformen | `android-35`, `android-36`, `android-36.1` |
| Build-Tools | `34.0.0`, `35.0.0`, `36.0.0` |
| TV-System-Image | **`system-images;android-36;google-tv;x86_64` installiert** |
| AVD | **`gedefense_tv`** (in `%USERPROFILE%\.android\avd`) |
| Emulatorgerät | `emulator-5554 device` (Software-GPU) |
| Gerät | Google `sdk_google_atv64_amati_x86_64`, Android **16**, **API 36**, 1920×1080 (Density 320) |
| Fingerprint | `google/sdk_google_atv64_amati_x86_64/emu64xa:16/BT2A.260319.001/15058170:user/dev-keys` |
| Security-Patch | `2026-04-01` (App bewertet ihn als „veraltet“, ohne Verwundbarkeitsclaim) |
| App-Installation | `de.visiongaia.gedefense.tv`, `versionName=0.1.0-alpha1`, versionCode 1, DEBUGGABLE |
| cmdline-tools | `23.0.0` (alt); `sdkmanager --list` erzeugte die Paketliste, endete danach abnorm mit `-1073740791` |

Eigene read-only Gegenprüfung (Dokumentationsteam) per `adb`/`run-as`: App-Paket installiert und laufend
(PID vorhanden), Exportdateien im Download-Ordner, Ledger/Keyring im privaten
`no_backup/evidence` (siehe §9).

---

## 2. Voraussetzungen

1. **Android SDK** mit `cmdline-tools`, `platform-tools`, `emulator`.
   - Die installierten cmdline-tools 23.0.0 sind alt; für neue Images/AVD-Funktionen aktualisieren
     (Schritt 3). Das TV-Image ist in dieser Umgebung bereits installiert.
2. **JDK 17**, z. B. `%JAVA_HOME%`.
3. **Hardware-Virtualisierung** (WHPX/HAXM) oder ausreichend schneller ARM-Host.
4. **APK** aus dem Projekt (`:app:assembleDebug` bzw. Release).
5. Netzwerk für den einmaligen Image-Download (mehrere GB) und Feed-Tests.

---

## 3. Schritt 1 — SDK-Werkzeuge (bei Bedarf) aktualisieren

```powershell
$env:JAVA_HOME = '%JAVA_HOME%'
$sdk = '%ANDROID_HOME%'
$env:ANDROID_HOME = $sdk

# Aktuelle cmdline-tools installieren (neues Verzeichnis "<sdk>\cmdline-tools\latest")
& "$sdk\cmdline-tools\23.0.0\bin\sdkmanager.bat" --install "cmdline-tools;latest"

# Lizenzen bestätigen (einmalig)
& "$sdk\cmdline-tools\latest\bin\sdkmanager.bat" --licenses
```

> Warum: `sdkmanager` 23.0.0 endete in dieser Umgebung nach der Listenausgabe mit abnormem Exitcode.
> Kein App-Problem, sondern Tooling-Risiko.

---

## 4. Schritt 2 — TV-System-Image installieren (in dieser Umgebung bereits vorhanden)

```powershell
& "$sdk\cmdline-tools\latest\bin\sdkmanager.bat" --install `
  "platform-tools" "emulator" "platforms;android-36" `
  "system-images;android-36;google-tv;x86_64"
```

Prüfen:

```powershell
& "$sdk\cmdline-tools\latest\bin\sdkmanager.bat" --list_installed |
  Select-String "system-images|emulator|platform-tools"
```

Verfügbare TV-Images (Auszug aus `sdkmanager --list`): `android-36 google-tv x86_64` und
`arm64-v8a`, `android-36 android-tv x86_64`, `android-34 google-tv x86`, `android-33 google-tv x86`,
`android-30 google-tv x86`. Empfehlung für dieses Projekt: **API 36, google-tv, x86_64**.

---

## 5. Schritt 3 — AVD anlegen

### Variante A — Android Studio (Weg der offiziellen Dokumentation)

1. Android Studio → **Tools → Device Manager**.
2. **Create Device** → Kategorie **TV** → Gerätedefinition (z. B. Television 1080p) → **Next**.
3. System-Image (API 36, `google-tv`) → **Next** → Namen vergeben → **Finish**.
4. AVD markieren → **Play**.

### Variante B — Kommandozeile (`avdmanager`)

```powershell
$avdmanager = "$sdk\cmdline-tools\latest\bin\avdmanager.bat"

# TV-Gerätedefinitionen prüfen
& $avdmanager list device | Select-String -Pattern "tv_1080p|tv_720p" -Context 1,1

# AVD anlegen (im Projekt heisst der AVD "gedefense_tv")
'no' | & $avdmanager create avd `
  --name gedefense_tv `
  --package "system-images;android-36;google-tv;x86_64" `
  --device tv_1080p

# AVDs auflisten
& "$sdk\emulator\emulator.exe" -list-avds
```

Hinweis: Die Helper-Standardbezeichnung ist `GeDefenseTV_API36`; für den projektierten AVD
`-AvdName gedefense_tv` verwenden.

---

## 6. Schritt 4 — Emulator starten und Boot verifizieren

```powershell
# Start mit Fenster (Software-GPU bewährt für Screenshots)
& "$sdk\emulator\emulator.exe" -avd gedefense_tv -no-snapshot -gpu swiftshader_indirect

# Headless (z. B. automatisierte Läufe)
& "$sdk\emulator\emulator.exe" -avd gedefense_tv -no-window -no-snapshot -gpu swiftshader_indirect
```

Boot prüfen:

```powershell
& "$sdk\platform-tools\adb.exe" devices
# erwartet: "emulator-5554   device"

& "$sdk\platform-tools\adb.exe" wait-for-device
& "$sdk\platform-tools\adb.exe" shell getprop sys.boot_completed
# erwartet: "1"
```

Belegt: Emulator bootete, Gerät `emulator-5554` mit API 36/Android 16 war im Status `device`;
`am start -W` startete die App in **1,81–2,29 s** (Kaltstart, Debug, Software-GPU).

---

## 7. Schritt 5 — APK installieren und starten

```powershell
# Debug-APK bauen (siehe BUILD-RUNBOOK.md)
.\gradlew.bat :app:assembleDebug --console=plain

$adb = "$sdk\platform-tools\adb.exe"

# Installieren (bei mehreren Geräten: -s emulator-5554)
& $adb install -r app\build\outputs\apk\debug\app-debug.apk

# Starten
& $adb shell am start -n de.visiongaia.gedefense.tv/.TvMainActivity

# Logs beobachten
& $adb logcat -s GeDefenseTv:* AndroidRuntime:E
```

Belegt: `app-debug.apk` (2.860.091 B) installiert und gestartet; Release-APK (1.626.209 B,
debug-signiert) wurde ebenfalls installiert und als Smoke-Test gestartet, stammt aber aus der Zeit
**vor** dem letzten Redesign → finaler RC-Rebuild offen.

> Ein Debug-APK belegt nur Debug-Verhalten (`debuggable`, kein R8). Release-Aussagen nur mit dem
> finalen signierten RC-Artefakt treffen.

---

## 8. Schritt 6 — Bedienung mit der Fernbedienung (D-Pad)

Der TV-Emulator verarbeitet Tastatur-Eingaben als D-Pad; in der Android-Studio-GUI gibt es die
Remote-Control-Overlay (**Extended Controls → Remote**). Per `adb`:

```powershell
$adb = "$sdk\platform-tools\adb.exe"

& $adb shell input keyevent KEYCODE_DPAD_UP
& $adb shell input keyevent KEYCODE_DPAD_DOWN
& $adb shell input keyevent KEYCODE_DPAD_LEFT
& $adb shell input keyevent KEYCODE_DPAD_RIGHT
& $adb shell input keyevent KEYCODE_DPAD_CENTER    # OK / Auswahl
& $adb shell input keyevent KEYCODE_BACK          # Zurück
& $adb shell input keyevent KEYCODE_HOME
```

Wichtig für GeDefense TV (T-11/T-12):

- Jedes Rail-Ziel muss mit D-Pad erreichbar sein; der 4-dp-Gold-Fokusring muss sichtbar bleiben.
- `BACK` schließt zuerst screen-lokalen Zustand, dann Back-Stack, zuletzt nach `HOME`.
- `LEFT` führt zur Rail; Action-Band ist mit erster/letzter Listenzeile verknüpft (kein Focus-Trap).
- Kein Element darf ausschließlich per Touch/Hover erreichbar sein.

Belegt: alle Screens per D-Pad erreichbar, Listen fokussierbar/scrollbar, Delete zweistufig,
LEFT/BACK korrekt, keine Touch-Abhängigkeit (Screenshots).

---

## 9. Schritt 7 — Screenshot und Beweissicherung

```powershell
$adb = "$sdk\platform-tools\adb.exe"

# Auf dem Gerät speichern und abziehen (robust unter Windows PowerShell 5.1)
& $adb shell screencap -p /sdcard/gedefense-tv-01.png
& $adb shell rm /sdcard/gedefense-tv-01.png
```

> Unter Windows PowerShell 5.1 kann `>` Binärdaten beschädigen; daher `screencap` + `adb pull`
> verwenden. Für Abläufe: `adb shell screenrecord /sdcard/demo.mp4` (max. ~180 s) + `adb pull`.

1920×1080, Dateien **10–105**: Home, Rail, Check (ready/running/result), Findings (inkl. Scroll/
Fokus), Apps, Hardening, ThreatIntel, Evidence, Settings, Export-Dialog/Fallback, Restart-Summary,
RC-Stand 80–96.

**Export-/Evidenz-Nachweis (read-only geprüft):**

```powershell
& $adb shell ls -l /sdcard/Download/GeDefenseTV
# 30.246 B .txt + 4.562 B .json (valides JSON), 29.10.2026 10:32

& $adb shell run-as de.visiongaia.gedefense.tv ls -l no_backup/evidence
# events.v3.log (19.169 B, 32 Zeilen), keyring.v1 (61 B), legacy/ (14.375 B)
```

Auf TV-Images ohne DocumentsUI nutzt die App den dokumentierten MediaStore-Fallback
(`Downloads/GeDefenseTV`) ohne Storage-Permission.

---

## 10. Zuordnung zum Test-Plan

| Testfall ([TEST-PLAN.md](../TEST-PLAN.md)) | Status Emulator (29.10.2026) |
| --- | --- |
| T-01 Frische Installation | **PASS (PARTIAL)** – App-Start ohne Crash |
| T-02 Patch-Level | **PASS** – API 36, Patch 2026-04-01 → „veraltet“ |
| T-03/T-04 App-Inventar/Visibility | **PASS (PARTIAL)** – 66 sichtbare Apps, „Teilweise Sicht“ |
| T-05 Usage Access | **PASS** – keine Anforderung, keine Regression |
| T-06 TI stale | **NOT_TESTED** – nur Online-Fall (9/9) belegt |
| T-07 IOC-Match | **NOT_TESTED** – kein synthetischer Testfall |
| T-08 Doze/Neustart | **PARTIAL** – Force-Stop/Neustart-Summary belegt, Doze/Reboot offen |
| T-10 Export/Löschen | **PARTIAL** – Fallback-Export belegt, Clear-Reflexion offen |
| T-11/T-12 D-Pad/kein Touch | **PASS** |
| T-13 Scan-Grenzen | **PARTIAL** – JVM-Harness deckt Timeout/Cancel, Emulator-Adversarialtest offen |
| T-14 Evidenz-Fail-closed | **NOT_TESTED** – gesundes Ledger belegt, Tamper-Test fehlt |
| T-15 Performance | **PASS** – Kaltstart 1,81–2,29 s (Emulator, Software-GPU) |

**Wichtig:** Der Emulator belegt **kein** reales TV-/OEM-Verhalten. Für Release-Gates sind
mindestens zwei reale Geräte mit unterschiedlichem OEM erforderlich (Datenblatt §11).

---

## 11. Fehlerbehebung

| Problem | Ursache | Lösung |
| --- | --- | --- |
| `sdkmanager` endet abnorm (`-1073740791`) | alte cmdline-tools 23.0.0 | `sdkmanager --install "cmdline-tools;latest"`; neuen Pfad verwenden |
| `Package ... is not available` | Image nicht installiert / Tippfehler | exakt `system-images;android-36;google-tv;x86_64` verwenden |
| `avdmanager: Device 'tv_1080p' not found` | alte cmdline-tools | cmdline-tools aktualisieren; Geräteliste prüfen |
| Emulator startet langsam/gar nicht | Virtualisierung fehlt | BIOS-Virtualisierung + Windows-Hypervisor-Plattform prüfen; `emulator-check.exe accel` |
| `INSTALL_FAILED_...` | APK/ABI passt nicht | `x86_64`-Image verwenden; APK mit `apkanalyzer` prüfen |
| `adb devices` leer | Emulator noch nicht gebootet/adb-Server alt | `adb kill-server`, `adb start-server`, Boot abwarten |
| Screenshot schwarz | GPU-Modus | `-gpu swiftshader_indirect` verwenden |
| Export-Dialog erscheint nicht | TV-Image ohne DocumentsUI/Framework-Stub | Erwartetes Verhalten; dokumentierter MediaStore-Fallback greift |
| Launcher-Banner nicht sichtbar | unprovisionierter Emulator | Kein App-Fehler; Intent + Banner-Ressource statisch belegt |

---

## 12. Evidenzstatus dieser Anleitung

| Aussage | Belegt? |
| --- | --- |
| SDK-/Image-/AVD-Inventur | **ja**, real geprüft (29.10.2026) |
| `sdkmanager --list`-Ausgabe / TV-Image-Verfügbarkeit | **ja**; abnormer Exitcode dokumentiert |
| Image installiert | **ja** (`android-36;google-tv;x86_64`) |
| AVD-Erstellung `gedefense_tv` | **ja** |
| Emulatorstart / Boot | **ja** (`emulator-5554 device`, API 36/Android 16) |
| APK-Installation / App-Start | **ja** (Debug; Release-Smoke vor Redesign) |
| Screenshots / D-Pad-Testläufe | **ja** (Screenshots, 1920×1080) |
| Reale TV-Hardware | **nein (NOT_TESTED)** |
| Offizielle Doku-URL zitiert | **ja** (siehe Kopf) |

Die Anleitung bleibt reproduzierbar; die Evidenz stammt aus dem Verifikationsprotokoll und einer eigenen
read-only `adb`-Gegenprüfung.

---

## 13. V2-Tests (Loopback-VPN, Traffic, Onboarding) — geplant, NOT_TESTED

Für V2 gelten zusätzlich die Fälle aus [TEST-PLAN.md](../TEST-PLAN.md) §8. nützliche Befehle
(alle noch **nicht ausgeführt**; Ausgabe/Exitcodes sind zu protokollieren):

```powershell
$adb = "$sdk\platform-tools\adb.exe"

# App-Zustand / VPN-Service
& $adb shell dumpsys activity services de.visiongaia.gedefense.tv | Select-String "VpnService|vpn"
& $adb shell ip addr show tun0
& $adb shell dumpsys connectivity | Select-String "VPN|tun"

# Always-On (Systemeinstellung; nur Testgerät)
& $adb shell settings get secure always_on_vpn_app
& $adb shell settings get secure always_on_vpn_lockdown

# Benachrichtigung/FGS (Status, keine sensiblen Inhalte)
& $adb shell dumpsys notification --noredact | Select-String "de.visiongaia.gedefense.tv"

# Logs (auf DNS-/Traffic-Leaks prüfen – es dürfen keine DNS-Namen/Domains im Klartext erscheinen)
& $adb logcat -s GeDefenseTv:* VpnService:* AndroidRuntime:E

# Kaltstart/Performance
& $adb shell am start -W -n de.visiongaia.gedefense.tv/.TvMainActivity
& $adb shell dumpsys gfxinfo de.visiongaia.gedefense.tv

# Neustart-/Recovery-Test (Testgerät)
& $adb reboot
```

**Wichtig:** V2-Erwartungen (Consent, Fail-Closed, Blocking, Karte, Onboarding, Sir Quacksec,
TI-Modal) sind in TEST-PLAN §8 dokumentiert. Es werden **keine** V2-Ergebnisse behauptet, bis der
Projektteam den V2-Ledger liefert.
