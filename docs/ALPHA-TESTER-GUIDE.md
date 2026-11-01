# GeDefense TV (v0.3.0-alpha1) — Alpha-Tester Guide & Hardware Testmatrix

Willkommen beim Alpha-Test von **GeDefense TV mit Titan Engine (v0.3.0-alpha1 / VersionCode 4)**!  
Dieses Dokument führt dich durch die Installation, die beiden Testpfade (Standard Non-Root vs. Root-Sovereign) und das strukturierte Melden von Befunden.

---

## 1. Release-Paket & Integrität

Die APK-Dateien liegen im Repository unter `dist/`:

| Datei | Größe | SHA-256 Prüfsumme | Signatur |
| :--- | :--- | :--- | :--- |
| **`VGT_GeDefense_TV_0.3.0-alpha1_VC4_release-signed.apk`** | 6.522.110 B | `DA4110EB18ED9376B2C16AD70065C9F39A1F7592865B612A469E969B0F3F2934` | CN=VisionGaiaTechnology GeDefense TV Alpha (VGT Alpha-Cert) |
| `VGT_GeDefense_TV_0.3.0-alpha1_VC4_debug.apk` | 8.811.121 B | `2FB107BB473BFF4C6BCDBE8ED97605D057BD7E18B404BF80561331A25087B2D4` | Android Debug Key |

> [!IMPORTANT]
> Für reale Nutzertests bitte **stets die signierte Release-APK** verwenden. Sie enthält alle Härtungen (`FLAG_SECURE`, Policy-Caps, Release-Signaturprüfung).

---

## 2. Installation auf Android TV / Google TV / TV-Box

### Methode A: Drahtlos via ADB (Empfohlen für Entwickler & Power-User)
1. Auf dem TV: **Einstellungen → Geräte-Einstellungen → Über → 7x auf Build-Nummer klicken** (Entwickleroptionen freischalten).
2. **Entwickleroptionen → USB-Debugging** und **Netzwerk-Debugging** aktivieren.
3. Vom PC im gleichen WLAN:
   ```bash
   adb connect <TV-IP-ADRESSE>:5555
   adb install -r VGT_GeDefense_TV_0.3.0-alpha1_VC4_release-signed.apk
   ```

### Methode B: USB-Stick (Einfachste Methode für TV-Boxen)
1. APK auf einen FAT32/exFAT formatierten USB-Stick kopieren.
2. Am Smart TV oder an der TV-Box einstecken.
3. Mit einem Dateimanager (z. B. *File Commander*, *AnExplorer* oder bordeigenem Explorer) öffnen und installieren.
4. Ggf. „Installation aus unbekannten Quellen“ für den Dateimanager zulassen.

### Methode C: Downloader-App (AFTVnews)
1. Im Play Store / Fire TV Appstore die App **Downloader** installieren.
2. Den direkten Download-Link zur Release-APK eingeben und direkt auf dem TV installieren.

---

## 3. Test-Pfade

### Testpfad 1: Level 1 – Standard Non-Root (Jeder Smart TV / Google TV)
Ziel: Verifikation der 10-Fuß-Bedienbarkeit, des lokalen VPN-Schutzes und der ehrlichen Zustandserkennung.

- [ ] **Ersteinrichtung (Onboarding):**
  - Führt der 6-Stufen-Wizard sauber per Fernbedienung (D-Pad `HOCH/RUNTER/LINKS/RECHTS`, `OK`, `ZURÜCK`) durch die Schritte?
  - Wird der lokale VPN-Loopback-Tunnel fehlerfrei initialisiert?
- [ ] **10-Fuß-Ergonomie & Fernbedienung:**
  - Ist der D-Pad-Fokus auf allen 11 Menüeinträgen (Linke Navigationsleiste) jederzeit eindeutig sichtbar (Goldener Glanz/Rand)?
  - Sir Quacksec Begrüßungsmaskottchen: Lässt es sich mit jedem Tastendruck sofort überspringen?
- [ ] **Lokaler Schutz (Protection Dashboard):**
  - Schaltet der VPN-Schutz fehlerfrei zwischen *Balanced*, *Strict* und *Off* um?
  - Werden ACR-Tracker (Smart-TV Telemetrie von Samsung, LG, Sony, Xiaomi etc.) laut Zähler geblockt?
- [ ] **Streaming-Kompatibilität:**
  - Laufen Streaming-Dienste (Netflix, Prime Video, YouTube, Disney+, Joyn, RTL+, VLC) bei **aktiver Schutzschleife** ruckelfrei und ohne Geo-Blockaden? (GeDefense leitet keinen Traffic über externe Server um).
- [ ] **TITAN LIVE (im Non-Root-Modus):**
  - Zeigt der Bildschirm ehrlich `Level 1 · Standard` an?
  - Stehen alle 7 erweiterten Schilde auf `Unavailable` (Zero Snake Oil)?
  - Es darf **kein** aggressiver Root-Prompt oder gefälschter Schutzstatus erscheinen.

---

### Testpfad 2: Level 3 – Titan Sovereign (Gerootete TV-Boxen & Sticks)
Ziel: Tiefenverifikation der Endpoint-Integrität auf modifizierten Systemen (Nvidia Shield rooted, Mecool, Amlogic S905/S922 Boxen, Fire TV mit Magisk/KernelSU/APatch).

- [ ] **Passiver Root-Check:**
  - Nach dem Start: Erkennt GeDefense TV das Vorhandensein des Root-Managers (`su`, Magisk, KernelSU) rein passiv, ohne dass das System ungefragt Root anfordert?
  - Erscheint der Button `Activate Titan` in der Titan-Live-Ansicht?
- [ ] **Zweistufiger Sicherheitsdialog:**
  - Beim Klick auf `Activate Titan`: Öffnet sich der Glass-2100-Bestätigungsdialog?
  - Liegt der initiale Fokus sicherheitskonform auf **Abbrechen**?
- [ ] **Superuser-Prompt auf TV-UI:**
  - Beim Bestätigen: Wie reagiert dein Root-Manager (Magisk / KernelSU / SuperSU)?
  - Erscheint der Prompt im TV-Vollbild oder im Hintergrund?
- [ ] **Socket Provenance Radar:**
  - Liest Titan nach Freigabe `/proc/net/tcp` und `/proc/net/tcp6` aus?
  - Werden offene Verbindungen transparent den installierten Apps (UIDs/Paketnamen) zugeordnet?
  - Werden offene ADB-Ports (Port 5555) oder unzugeordnete Sockets als Risiko markiert?
- [ ] **FIM (File Integrity Monitoring):**
  - Wird ein Baseline-Hash von Systemverzeichnissen (`/system/bin`, `/system/xbin` etc.) angelegt?
  - Werden manipulierte oder neu abgelegte Binaries erkannt?
- [ ] **Containment (Freeze / Network Isolate):**
  - Test auf einer unkritischen Dummy-App: Lässt sich die App über den Dialog einfrieren (`pm disable` / `kill`) bzw. wieder freigeben?

---

## 4. Issue-Vorlage für Tester (Bug / Feedback Report)

Bitte kopiere diese Vorlage in ein neues GitHub-Issue:

```markdown
### Geräte- & Systeminformationen
- **Gerätemodell / Box:** (z. B. Nvidia Shield Pro 2019, Mecool KM2 Plus, Fire TV Stick 4K Max, Xiaomi TV Box S)
- **SoC / Chipsatz:** (z. B. Amlogic S905X4, Tegra X1+, MediaTek MT9611)
- **Android-Version:** (z. B. Android TV 11, Google TV 12, Android 14)
- **Root-Lösung (falls vorhanden):** (z. B. Kein Root / Magisk v27.0 TV / KernelSU / APatch)
- **Auflösung / Framebuffer:** (z. B. 1080p @ 60Hz, 4K @ 60Hz)
- **Fernbedienung:** (Original Bluetooth Fernbedienung / AirMouse / Tastatur)

### Getesteter Pfad
- [ ] Testpfad 1 (Standard Non-Root)
- [ ] Testpfad 2 (Titan Sovereign Root)

### Beobachtetes Verhalten
(Genaue Beschreibung: Was hast du gemacht, was ist passiert und was hast du erwartet?)

### Screenshots / Fotos vom TV
(Optional: Foto vom TV-Bildschirm anhängen)

### Logcat-Auszug (falls ADB verfügbar)
```bash
adb logcat -d -s GeDefenseTv Titan AndroidRuntime
```
(Hier Logs einfügen)
```

---

## 5. Bekannte Alpha-Grenzen (Known Limits)

Folgende Funktionen sind in der Alpha 0.3.0 bewusst noch nicht aktiv und müssen nicht als Fehler gemeldet werden:
1. **Shizuku-Ausführung:** Nur passive Erkennung von Shizuku; noch keine direkte Befehlsausführung über Shizuku-IPC (folgt in 0.4.0).
2. **Mobile-Witness-Pairing:** Checkpoints werden lokal kryptografisch signiert (Ed25519/HMAC); der automatische Push an die GeDefense Mobile App ist ein Alpha-Gap.
3. **Quarantäne-Vault UI:** Der Vault ist im UI vorerst *read-only* (kein manueller Restore-Knopf im Dashboard).
