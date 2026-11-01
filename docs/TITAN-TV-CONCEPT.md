# GeDefense Titan TV — Masterkonzept
## Sovereign TV Endpoint Integrity, Socket Provenance & Active Defense Engine

| Attribut | Wert |
| :--- | :--- |
| **Produkt** | GeDefense TV — Modul: **Titan Engine** |
| **Kürzel / Namespace** | `titan-tv` / `de.visiongaia.gedefense.tv.titan` |
| **Referenzdokumente** | `GeDefenseTitan_Masterkonzept.txt`, `ARCHITECTURE.md`, `THREAT-MODEL.md` |
| **Design-DNA** | VGT GLASS 2100 (Obsidian, Metallic-Gold `#E6B95C`, Electric-Blue `#258CF4`) |
| **Modul-Architektur** | `:tv-core` (Pure JVM Domain & Rules), `:app` (Android Platform & Root Adapters) |
| **Status** | Architektur- und Implementierungskonzept für Agenten-Handoff |

---

## 1. Executive Summary & Vision

GeDefense TV in Version `0.1.0-alpha1` hat das Fundament als **ehrlicher, nicht-privilegierter Sentinel** gelegt (Zero Snake Oil, transparente `PARTIAL`-Sichtbarkeit, 10-Fuß-D-Pad-Bedienung). 

Auf Smart TVs und TV-Boxen existiert jedoch eine wachsende Gruppe von **Bastlern, Power-Usern und Betroffenen vorkonfigurierter Hardware** (China-TV-Boxen, Sideloading-Nutzer, Kodi/IPTV-Communities, Custom-ROMs), deren Geräte entweder:
1. **vom Nutzer bewusst gerootet** wurden (Magisk, KernelSU, APatch),
2. **mit ADB / Shizuku** für tiefere Konfigurationen freigeschaltet sind, oder
3. **ab Werk mit gefährlicher Pre-Rooted-Malware / Dirty-Roots** (z. B. *Badbox*, *Vo1d*, *Peachpit*) infiziert sind und im Standby heimlich als Residential Proxies oder DDoS-Bots agieren.

**GeDefense Titan TV** hebt GeDefense TV auf die nächste Evolutionsstufe: Es verwandelt die App bei Vorhandensein erweiterter Rechte dynamisch vom passiven Beobachter zum **autonomen, manipulationssicheren Endpoint-Guardian**. 

```
                               ┌────────────────────────────────────────────────────────┐
                               │                 GeDefense TV Shell                     │
                               │        (VGT GLASS 2100, 10-Fuß TV-UI, D-Pad)           │
                               └──────────────────────────┬─────────────────────────────┘
                                                          │
                                         Dynamische Privileg-Erkennung
                                                          │
                 ┌────────────────────────────────────────┼────────────────────────────────────────┐
                 ▼                                        ▼                                        ▼
    [LEVEL 1: Sentinel Standard]              [LEVEL 2: Titan Shizuku]                 [LEVEL 3: Titan Root]
    • Unprivilegierter Modus                 • Erhöhte System-Rechte                  • Volle Kernel- & Dateisystemtiefe
    • 100 % Google-Play-konform              • Kein Root / Kein DRM-Verlust           • FIM Anti-Planting (/system, /data)
    • Sichtbarkeit: PARTIAL                  • App-Deaktivierung & Freeze             • Socket-zu-PID C2-Erkennung
    • Beobachtend & Beratend                 • Permission-Hardening                   • Active Network Quarantine (iptables)
    • Evidenz: Lokaler HMAC-Ledger           • Sichtbarkeit: ENHANCED                 • Sichtbarkeit: FULL (Sandbox durchbrochen)
```

---

## 2. Das 3-Stufen-Privilegmodell (Zero Snake Oil Garantie)

GeDefense TV bleibt **eine einheitliche App**. Es gibt keinen separaten APK-Fork. Das System passt seine Fähigkeiten zur Laufzeit transparent und belegbar an:

| Merkmal | Level 1: Standard Sentinel | Level 2: Titan Shizuku (ADB) | Level 3: Titan Sovereign Root |
| :--- | :--- | :--- | :--- |
| **Voraussetzung** | Jedes Standard-TV (API 26+) | Shizuku-App / Wireless ADB aktiv | `su`-Binary (Magisk, KernelSU, etc.) |
| **DRM / Widevine L1** | Bleibt vollständig erhalten | Bleibt vollständig erhalten | Kann je nach Gerät beeinträchtigt sein |
| **Sichtbarkeit (`DataVisibility`)** | `PARTIAL` (Package-Visibility-Limits) | `ENHANCED` (Alle Pakete & Rechte) | **`FULL`** (Kernel, Sockets, alle Pfade) |
| **Netzwerk-Sicht** | Nur eigener App-Status | App-Netzwerk-Berechtigungen | **Live-Sockets (`/proc/net/*`) & PIDs** |
| **Reaktionsfähigkeit** | Manuelle Handlungsempfehlung | `pm disable`, `pm revoke` | **Quarantine Vault, `iptables`-Drop, Kill** |
| **Anti-Planting / FIM** | Keine Dateisystem-Sicht | Begrenzte Pfade via Content-Provider | **Vollständiges FIM (`/system`, `/data`)** |

---

## 3. Die 6 Kernmodule von Titan TV

### Modul 1: `TitanPrivilegeGate` & Dirty-Root Audit
Verantwortlich für die sichere, unaufdringliche Prüfung und Klassifikation des Privileg-Status.

* **Fähigkeiten:**
  1. **Root-Erkennung:** Sichere Erkennung von `su`-Binaries in Standard- und Nicht-Standard-Pfaden (`/system/bin`, `/system/xbin`, `/sbin`, `/data/local/xbin`).
  2. **Root-Manager Audit:** Unterscheidung zwischen autorisiertem Superuser (Magisk Socket, KernelSU API, APatch) und unsicherem **Dirty Root** (freie `su` ohne Prompt, worauf jede Malware zugreifen kann – typisch für Billig-TV-Boxen).
  3. **SELinux State:** Auslesen von `getenforce`. Alarm bei `Permissive` (hohes Einfallstor für Rootkits).
  4. **Shizuku Provider Bridge:** Prüfung des `moe.shizuku.server`-Binders über AIDL.

---

### Modul 2: `TitanSocketProvenanceCollector` (C2- & Botnet-Jäger)
Ermöglicht erstmals auf Smart TVs die forensische Verknüpfung von Netzwerkverbindungen mit realen App-Prozessen.

```
┌──────────────────────────┐     ┌──────────────────────────┐     ┌──────────────────────────┐
│   /proc/net/tcp & udp    │ ──► │  /proc/[pid]/fd Socket   │ ──► │     Package Manager      │
│  (Remote IP & Port)      │     │  (Inode-zu-PID Mapping)  │     │   (App-Paket & Name)     │
└──────────────────────────┘     └──────────────────────────┘     └─────────────┬────────────┘
                                                                                │
                                                                  Abgleich mit 9 Threat-Feeds
                                                                                │
                                                                                ▼
                                                                  [Ereignis: C2-Verbindung!]
                                                                  App: "HD-Stream-Player"
                                                                  Ziel: 185.220.101.5:4444
                                                                  Aktion: Sofortiges Containment
```

* **Funktionsweise:**
  1. Liest periodisch (oder im Scan-Lauf) `/proc/net/tcp`, `/proc/net/tcp6` und `/proc/net/udp`.
  2. Löst die Inode-Nummern des Sockets über die File-Deskriptoren in `/proc/<pid>/fd/` zur konkreten **Prozess-ID (PID)** auf.
  3. Mappt die PID über `/proc/<pid>/status` (UID) auf das installierte Android-Paket (`InstalledApp`).
  4. Gleicht die Remote-IP in $O(1)$ mit dem GeDefense `ThreatIndex` (9 Feeds: Botnets, C2, Tor-Exit, Malicious Proxies) ab.
  5. Erzeugt ein `TvEvent` der Klasse `TITAN_C2_SOCKET_DETECTED`.

---

### Modul 3: `TitanDeepInventory & FIM Collector` (Anti-Planting Engine)
Verhindert und erkennt das heimliche Ablegen schädlicher Binaries in persistenten TV-Verzeichnissen.

* **Schutzbereiche (FIM Targets):**
  * `/data/local/tmp` (Häufigster Ablageort für Root-Exploits und Miner).
  * `/system/bin`, `/system/xbin` und `/vendor/bin` (Systemintegrität).
  * `/system/etc/init` und `init.*.rc` (Boot-Persistenz).
  * Magisk-Modulverzeichnis (`/data/adb/modules`).
* **Erkennungslogik:**
  * SHA-256 Hash-Vergleich gegen den Baseline-Snapshot des Erstscans.
  * Alarmierung bei neuen, unautorisierten Binaries oder geänderten Datei-Hashes (Anti-Planting-Garantie).

---

### Modul 4: `TitanResponseEngine` & Quarantine Vault (Active Containment)
Schluss mit bloßen Warnhinweisen: Titan kann Bedrohungen direkt am TV isolieren.

* **Containment-Stufen (per D-Pad aktivierbar):**
  1. **App Freeze (Weiche Isolation):**
     * Befehl: `pm disable-user --user 0 <package>` oder `pm suspend <package>` gefolgt von `am force-stop <package>`.
     * Wirkung: Die App verschwindet aus dem Launcher, kann nicht mehr gestartet werden, behält aber ihre Daten für forensische Analysen.
  2. **Netzwerk-Quarantäne (Per-App Firewall):**
     * Befehl: `iptables -I OUTPUT 1 -m owner --uid-owner <UID> -j DROP`.
     * Wirkung: Der kompromittierten App wird augenblicklich jeglicher Internetverkehr verboten. Der restliche TV (Netflix, YouTube) läuft normal weiter.
  3. **ADB Lockdown:**
     * Befehl: `setprop service.adb.tcp.port -1` & `stop adbd`.
     * Wirkung: Schließt den berüchtigten Netzwerk-Port 5555 gegen Würmer im LAN.
  4. **Quarantine Vault:**
     * Verschiebt verdächtige APKs/Binaries in einen geschützten Ordner (`/data/local/gedefense_vault/`), entzieht ihnen Ausführungsrechte (`chmod 000`) und verschlüsselt die Metadaten.

---

### Modul 5: `TitanWitnessProtocol` (Second-Device Trust)
Ein Fernseher läuft oft unbeaufsichtigt im Standby. Bricht ein Angriff aus, sieht der Nutzer den TV-Bildschirm nicht.

* **Architektur:**
  * GeDefense TV fungiert als **Witness Agent**.
  * **Pairing:** Der Nutzer koppelt GeDefense TV einmalig mit seinem Smartphone (**GeDefense Mobile**) per QR-Code (enthält Ed25519 Public Key des Handys + lokale IP).
  * **Heartbeat & Checkpoints:** Alle 15–30 Minuten sendet GeDefense TV einen signierten Checkpoint des `EvidenceLedgers` über das lokale LAN (Pinned TLS / mDNS).
  * **Sofort-Eskalation:** Erkennt Titan einen C2-Traffic oder schlägt das Ledger-Heartbeat fehl, sendet der TV einen verschlüsselten Push-Alarm an das Smartphone des Besitzers:
    > *„[GeDefense Titan Alert] TV im Wohnzimmer hat verdächtigen Datenverkehr von 'IPTV-Pro' blockiert (Ziel: Bekanntes Botnet C2).“*

---

### Modul 6: Titan UI/UX (VGT GLASS 2100 Erweiterungen)

Die TV-Oberfläche erweitert sich bei aktivem Titan-Modus elegant und organisch:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ [GeDefense Logo]  GeDefense TV  |  [TITAN SHIELD: ROOT ACTIVE]  | 29. Okt 2026 14:30   │
├───────────────┬────────────────────────────────────────────────────────────────────────┤
│ • LAGE        │  TITAN STATUS: AKTIV                                   [Erneut prüfen] │
│ • PRÜFUNG     │ ┌────────────────────────────────────────────────────────────────────┐ │
│ • BEFUNDE     │ │ [Gold Ring: 94]  SOVEREIGN INTEGRITY: GESCHÜTZT                    │ │
│ • APPS        │ │                  Vollständige Sicht (FULL) • Sockets überwacht     │ │
│ • HÄRTUNG     │ └────────────────────────────────────────────────────────────────────┘ │
│ • TITAN LIVE  │                                                                        │
│ • THREAT INTEL│ ┌─ Aktive Socket-Verbindungen ──────┐ ┌─ Titan Schutzschilde ────────┐ │
│ • EVIDENZ     │ │ 12 Verbindungen aktiv             │ │ [x] C2-Socket Guard: AKTIV   │ │
│ • EINSTELLUNG │ │ 0 verdächtige Endpunkte           │ │ [x] FIM Anti-Planting: AKTIV │ │
│               │ │ 1 geblockter Port (ADB 5555)      │ │ [x] Quarantine Vault: BEREIT │ │
│               │ └───────────────────────────────────┘ └──────────────────────────────┘ │
└───────────────┴────────────────────────────────────────────────────────────────────────┘
```

* **Neuer Menüreiter `TITAN LIVE`:**
  * **Socket-Radar:** Liste aller aktiven ausgehenden IP-Verbindungen mit App-Zuweisung.
  * **Quarantäne-Manager:** Übersicht aller isolierten und eingefrorenen Apps inkl. 1-Klick-Reaktivierung („Wiederherstellen“ / „Endgültig entfernen“).
  * **Systemintegrität:** FIM-Status von `/system` und `/data/local/tmp`.

---

## 4. Datenmodell & Schnittstellen (`:tv-core`)

Die Logik wird strikt modular gehalten. Alle neuen Modelle liegen in `:tv-core` (reine JVM, zero Android-Abhängigkeit):

```kotlin
// tv-core/src/main/java/de/visiongaia/gedefense/tv/core/model/TitanModels.kt

enum class TitanPrivilegeLevel {
    STANDARD_UNPRIVILEGED, // Level 1
    SHIZUKU_ADB,           // Level 2
    SOVEREIGN_ROOT         // Level 3
}

data class SocketObservation(
    val protocol: String,          // TCP, TCP6, UDP
    val localAddress: String,
    val localPort: Int,
    val remoteAddress: String,
    val remotePort: Int,
    val inode: Long,
    val pid: Int?,
    val uid: Int,
    val packageName: String?,
    val threatMatch: ThreatMatch?  // Falls in Threat-Feed vorhanden
)

data class FimObservation(
    val path: String,
    val sha256: String,
    val modifiedAtMillis: Long,
    val permissions: String,
    val status: FimStatus          // NEW_FILE, MODIFIED, MATCHES_BASELINE, UNREADABLE
)

enum class TitanContainmentAction {
    FREEZE_APP,
    ISOLATE_NETWORK_UID,
    KILL_PROCESS,
    CLOSE_ADB_PORT,
    RESTORE_APP
}
```

---

## 5. Arbeits- und Paketplan für Entwicklungsagenten (Work Packages)

| Work Package | Modul | Verantwortung & Aufgaben |
| :--- | :--- | :--- |
| **WP-T1: Privilege & Shizuku Bridge** | `:app/platform/titan` | Implementierung von `TitanPrivilegeGate.kt` (Erkennung `su`, Magisk-Manager, SELinux, Shizuku-AIDL-Client). Rückgabe von `TitanPrivilegeLevel`. |
| **WP-T2: Socket Provenance Collector** | `:app/platform/titan` | Implementierung von `SocketProvenanceCollector.kt`. Liest `/proc/net/tcp*`, mappt Inode zu PID/UID, matcht mit `ThreatIndex`. |
| **WP-T3: FIM & Anti-Planting Engine** | `:app/platform/titan` | Hash-Prüfung von `/data/local/tmp` und Binärverzeichnissen. Delta-Erkennung gegen `TvInventoryBaseline`. |
| **WP-T4: Active Response & Quarantine Vault** | `:app/platform/titan` | Ausführung von Root-/Shizuku-Befehlen (`pm disable`, `iptables UID drop`). Verwaltung des verschlüsselten Quarantäne-Verzeichnisses. |
| **WP-T5: Titan Live UI & D-Pad Integration** | `:app/ui/screens` | Screen `TitanScreen.kt`, Integration des Titan-Status in `HomeScreen.kt`, D-Pad Fokus für Containment-Buttons. |
| **WP-T6: Evidenz-Erweiterung & Witness Pairing** | `:tv-core` & `:app` | Neue Event-Typen für den `EvidenceLedger v3`. Lokaler UDP/HTTP-Broadcast für Zweitgeräte-Checkpoints (Mobile Companion). |

---

## 6. Sicherheitsrichtlinien für die Umsetzung

1. **Kein Root-Exploit:** GeDefense TV hackt sich niemals selbst ins System. Root-Rechte werden ausschließlich passiv abgefragt und genutzt, wenn der Nutzer sie via Magisk/SuperSU/KernelSU explizit bewilligt.
2. **Fail-Safe & No-Brick-Garantie:**
   * Es werden niemals Systempartitionen unüberlegt gelöscht.
   * `App Freeze` nutzt immer reversible Befehle (`pm disable-user` / `suspend`), sodass versehentlich deaktivierte Streaming-Apps jederzeit mit der Fernbedienung reaktiviert werden können.
3. **Dual-Mode-Sauberkeit:** Ist kein Root/Shizuku vorhanden, bleibt die App zu 100 % der saubere, auditierte Sentinel aus Alpha 1. Kein einziger Fehler, keine Abstürze wegen fehlender Rechte.
4. **VGT Coder Qualitäts-Gate:** Alle neuen Klassen in `:tv-core` benötigen 100 % JVM-Unit-Test-Coverage. Die Quellentreue des vendorten `:core` bleibt unangetastet.
