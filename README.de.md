<p align="center">
  <img src="docs/assets/sir_quacksec.png" alt="Sir Quacksec — GeDefense TV" width="200">
</p>

<h1 align="center">GeDefense TV</h1>

<p align="center"><b>Sicherheitskonsole direkt auf dem Gerät für Android TV OS und Google TV.</b><br>
Lokale Loopback-VPN-Filterung, Traffic-Map mit Geo-Zuordnung, XDR-Light und ein ehrliches Statusmodell.<br>
Kein externer VPN-Server. Keine Cloud. Keine Telemetrie.</p>

<p align="center">
  <a href="https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha2/VGT_GeDefense_TV_0.2.0-alpha2_VC3_release-signed.apk"><img src="https://img.shields.io/badge/release-0.2.0--alpha1-E8C46A?style=flat-square" alt="Release 0.2.0-alpha2"></a>
  <img src="https://img.shields.io/badge/status-early%20alpha-E86A5A?style=flat-square" alt="Frühe Alpha">
  <img src="https://img.shields.io/badge/platform-Android_TV%20%7C%20Google_TV-5FBFA8?style=flat-square" alt="Android TV / Google TV">
  <img src="https://img.shields.io/badge/Kotlin-1.9.24-7F52FF?style=flat-square&logo=kotlin&logoColor=white" alt="Kotlin 1.9.24">
  <img src="https://img.shields.io/badge/minSdk-26-3DDC84?style=flat-square&logo=android&logoColor=white" alt="minSdk 26">
  <img src="https://img.shields.io/badge/license-AGPL--3.0-1F8FFF?style=flat-square" alt="AGPL-3.0">
</p>

[English](README.md) · **Deutsch** · [Русский](README.ru.md) · [Français](README.fr.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md)

---

> ## ⚠️ FRÜHE ALPHA (early alpha) — jeder Nutzer ist Alpha-Tester
>
> GeDefense TV **0.2.0-alpha2** ist ein früher Alpha-Build. Es ist kein fertiges Verbraucherprodukt
> und kein auditiertes Sicherheitsprodukt; die veröffentlichte APK ist mit einem **Test-Signaturschlüssel**
> signiert. Verhalten, Oberfläche und Filterrichtlinie ändern sich zwischen Alpha-Builds. Bevor du
> dich darauf verlässt: lies den [Umfang und die Grenzen](#umfang-und-grenzen), die
> [Release-Notes](RELEASE-NOTES.md) und behandle jedes Ergebnis als Hinweis, nicht als Garantie.

## 🌐 Das GeDefense-Universum

GeDefense ist eine lokal-first Security-Fabric – für Linux, Windows, Android und WordPress. Alle Schwesterprojekte teilen dieselbe Philosophie: lokale Kontrolle, ehrliche Sichtbarkeit, keine stille Telemetrie.

| Projekt | Schwerpunkt |
| --- | --- |
| [![Android TV](https://img.shields.io/badge/Android_TV-3DDC84?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense_androidtv) **GeDefense TV** *(dieses Repository)* | Sicherheitskonsole für Android TV / Google TV: Loopback-VPN, Traffic-Map, XDR-Light und reversibles Kinetic-Lite-Containment. |
| [![Linux](https://img.shields.io/badge/Linux-D4AF37?style=flat-square&logo=linux&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense) **GeDefense Linux** | Kernel-nahe Netzwerkverteidigung: eBPF/XDP-Durchsetzung, L7-WAF, Host-XDR mit signierter Evidenz und reversible Härtung (Rust/Go, vollständig lokal). |
| [![Windows](https://img.shields.io/badge/Windows-8B5CF6?style=flat-square&logo=windows&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewin) **GeDefense Windows** | Lokale, souveräne Windows-11-Sicherheitskonsole: Defender/ASR/WFP/App Control, Härtung, MHX EDR/XDR, lokale Threat Intelligence und HMAC-verkettete Evidenz. |
| [![Android](https://img.shields.io/badge/Android-22D3EE?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefenseandroid) **GeDefense Android** | Native Android-Sicherheitsplattform: lokale VPN-Durchsetzung, Endpoint-Telemetrie, XDR/EDR-Korrelation, Threat Intelligence, App-Risikoanalyse und verschlüsselte Evidenz. |
| [![WordPress](https://img.shields.io/badge/WordPress-1F8FFF?style=flat-square&logo=wordpress&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewp) **GeDefense WordPress** | AGPL-3.0-Open-Core-Suite für WordPress: ZEUS-WAF, AEGIS-Deep-Packet-Inspection, TRINITY-XDR, ThroneGuard-Lockdown und HADES-Admin-Cloaking. |

## Download

[![Die neueste Alpha-APK herunterladen](https://img.shields.io/badge/Download-latest%20APK-E8C46A?style=for-the-badge&logo=android&logoColor=black)](https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha2/VGT_GeDefense_TV_0.2.0-alpha2_VC3_release-signed.apk)

Verwende immer die [Seite des neuesten Releases](https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha2/VGT_GeDefense_TV_0.2.0-alpha2_VC3_release-signed.apk):
Dort liegen das genaue APK-Artefakt, seine Prüfsummen und die Build-Hinweise. Die Alpha-APK ist
test-signiert — Android kann beim Sideloading warnen. Prüfe die SHA-256-Prüfsumme gegen
[SHA256SUMS.txt](SHA256SUMS.txt) bzw. gegen die Prüfsummen am Release, bevor du installierst.

## Screenshots

Echte Renderings der englischen Oberfläche, aufgenommen aus einem laufenden Android-TV-Emulator-Build
(1920×1080, Android 16 Google TV / API 36).

| Home — Sicherheitslage | Protection — lokales Loopback-VPN |
| --- | --- |
| ![Home-Screen](docs/screenshots/home.png) | ![Schutz-Dashboard](docs/screenshots/protection.png) |

| Network — Traffic-Map und Ziele | Umkehrbares Containment-Popup (Kinetic-Lite) |
| --- | --- |
| ![Netzwerk und Traffic-Map](docs/screenshots/network.png) | ![Temporäres Containment-Popup](docs/screenshots/containment.png) |

| Erststart-Onboarding mit Sir Quacksec | XDR-Light — korrelierte Vorfälle | Threat-Intelligence-Sync-Overlay |
| --- | --- | --- |
| ![Onboarding Schritt 1](docs/screenshots/onboarding.png) | ![XDR-Light-Vorfälle](docs/screenshots/xdr.png) | ![Threat-Intelligence-Sync-Overlay](docs/screenshots/ti-sync.png) |

### Sechs UI-Sprachen

Die Oberfläche folgt der Systemsprache des Fernsehers. Englisch ist Standard; Deutsch, Französisch,
Russisch, vereinfachtes Chinesisch und Japanisch sind vollständig übersetzt.

| English (Standard) | Deutsch | Français |
| --- | --- | --- |
| ![Englische Startansicht](docs/screenshots/home.png) | ![Deutsche Startansicht](docs/screenshots/languages/home-de.png) | ![Französische Startansicht](docs/screenshots/languages/home-fr.png) |

| Русский | 简体中文 | 日本語 |
| --- | --- | --- |
| ![Russische Startansicht](docs/screenshots/languages/home-ru.png) | ![Chinesische Startansicht](docs/screenshots/languages/home-zh-CN.png) | ![Japanische Startansicht](docs/screenshots/languages/home-ja.png) |

## Was ist GeDefense TV?

GeDefense TV ist eine auf D-Pad-Bedienung optimierte Sicherheits-App für Android TV OS und Google TV.
Sie verbindet eine lokale Filterungsschicht mit einer lokalen Beobachtungskonsole: Sie zeigt, was der
Fernseher im Netzwerk tut, was blockiert wurde, welche Apps mit welchen Ländern kommunizieren und
welche Befunde auf dem Gerät tatsächlich überprüfbar sind.

Leitregel: **Nur melden, was auf genau diesem Gerät beobachtbar ist.** Fehlende Berechtigungen,
nicht unterstützte APIs oder eingeschränkte Sichtbarkeit werden als eingeschränkte Sichtbarkeit
ausgewiesen — niemals als Beweis, dass der Fernseher sauber ist. Ein Schutzstatus wird nur behauptet,
wenn wirklich ein Tunnel aktiv ist.

Die App ist eine **eigenständige TV-App**. Sie ist kein Router, kein Firewall-Gateway und kein
Netzwerksensor und integriert sich nicht in Router-Firmware.

### Warum ein rein lokales Loopback-VPN?

GeDefense TV filtert direkt auf dem Gerät. Die App erstellt ein lokales TUN-Interface, leitet den
eigenen Datenverkehr hindurch und lässt einen vendorten, auditierten Datenplan-Helper DNS- und
Verbindungsmetadaten auswerten. Der gefilterte Verkehr verlässt das Gerät anschließend direkt zu
seinem Ziel.

Dieses Design hat bewusste Konsequenzen:

- **Kein externer Server, kein Konto, kein Abo.** Der Datenverkehr wird nicht über einen
  VGT-Server oder einen Drittanbieter-VPN-Endpunkt geleitet — es gibt keine Mitte, der man vertrauen muss.
- **Keine Payload-Inspektion.** Ausgewertet werden nur DNS- und Verbindungsmetadaten. TLS-/QUIC-Inhalte
  bleiben verschlüsselt und unangetastet — das ist kein MITM-Proxy und kann nicht in HTTPS hineinsehen.
- **Lokale Evidenz.** Befunde, Zähler und Evidenz bleiben auf dem Fernseher. Nichts wird hochgeladen.
- **Ehrliches Scheitern.** Fehlt die Einwilligung, scheitert der Helper oder lässt sich die Richtlinie
  nicht auswerten, meldet die App einen eingeschränkten/fehlerhaften Zustand, statt den Verkehr still
  ungefiltert durchzulassen.

## Funktionen

### Lokaler Schutz (Loopback-VPN)

- TUN-Dienst auf dem Gerät (`VpnService`, Foreground-Service, Always-On-Unterstützung) mit vendortem
  nativen Helper für `arm64-v8a` und `x86_64`.
- Start/Stopp mit der einmaligen Android-VPN-Einwilligung; optionaler Auto-Start nach App-Start.
- Filterprofile: **Off**, **Conservative**, **Balanced**, **Strict** — jedes Profil ändert, wie
  aggressiv bekannte Telemetrie-, ACR-, Werbe-, Tracker- und C2-Ziele behandelt werden.
- Explizites Zustandsmodell: Off, Preparing, Active, Limited, Failed, Not supported. „Active“ wird
  nur angezeigt, solange der lokale Tunnel wirklich läuft.
- Live-Zähler: blockierte Flows, beobachtete Apps, aktive Flows und übertragenes Volumen seit dem Start.

### Filterung: DNS, Tracker, ACR, Werbung und C2

- Lokale Auswertung von DNS-Anfragen und Verbindungszielen gegen den vendorten Threat-Index, einen
  kuratierten Tracker-/Telemetrie-Katalog und das gewählte Datenschutzprofil.
- Aktionen sind erklärbar: erlauben, annotieren, korrelieren oder blockieren — mit einer Begründung
  aus der lokalen Richtlinie, nie aus einem Remote-Urteil.
- Begrenzter Threat-Intelligence-Cache aus öffentlichen IOC-Listen; veraltete Feeds werden
  gekennzeichnet, nicht versteckt.
- Ehrliche Grenze: Nutzt eine App DNS-over-TLS/HTTPS, sind ihre Domainnamen nicht sichtbar; die App
  sagt das, statt zu raten.

### Traffic-Map mit lokaler Geo-Zuordnung

- Aggregation pro App, Land und Domain über den beobachteten Verkehr: Bytes, aktive Flows, blockierte
  Flows, korrelierte Flows.
- Weltkarte mit Ländermarkern und einem Herkunftsmarker aus TV-Region/Netzwerk — **kein GPS, keine
  Standortberechtigung**.
- Die Zuordnung IP→Land nutzt einen offline heruntergeladenen Datensatz mit SHA-256-Prüfsummen;
  die Länderzuordnung ist eine Schätzung (CDNs, Anycast und Shared Hosting können falsch zugeordnet werden).
- Begrenzte, datenschutzfreundliche Daten: keine Payloads, keine Bildschirminhalte, kein Audio/Video,
  keine Per-Paket-Logs.

### XDR-Light

Korreliert das lokal Beobachtbare zu erklärbaren Vorfällen: wiederholte blockierte Flows pro App,
blockierte Telemetrie-/ACR-Ziele, erstmals beobachteter App-Verkehr, C2-Feed-Treffer und
Hochrisiko-Länderkorridore (nur informativ). Jeder Vorfall trägt Regel, Konfidenz, Sichtbarkeit und
Empfehlung. Dedupliziert, begrenzt und ausdrücklich **kein** privilegiertes EDR: keine systemweiten
Flows, keine Prozessüberwachung, keine Firmware-Integritätsbehauptungen.

### V2.1 Outbound Kinetic-Lite

Deterministische, begrenzte Heuristiken über gleitende Zeitfenster auf dem beobachteten ausgehenden
Verkehr: DNS-Bursts, Ziel-Fan-out, Beacon-Muster, Volumenspitzen, wiederholte Blockierungen,
Tracker-Kategorien, C2-Treffer und Hochrisiko-Korridore. Jede Anomalie ist ein Score mit benannten
Signalen — niemals ein „Malware“-Urteil.

**Standardmäßig nur beobachten.** Temporäres Containment ist ein ausdrückliches Opt-in und nur im
Profil „Strict“ verfügbar. Wenn aktiviert, werden ausschließlich Ziel-Präfixe gesperrt (niemals Apps),
mit strengen Leitplanken: mindestens zwei unabhängige Signale, ein Mindestscore, ein bekanntes
Zielland, eine kurze TTL (1–30 Minuten, Standard 10), maximal vier aktive Containments und Allowlists
für Plattform-, Google- und CDN-Bereiche. Jedes Containment ist umkehrbar: Ein TV-Popup erscheint,
der Nutzer kann **Rückgängig** drücken, und die Sperre endet automatisch mit Ablauf der TTL.

### Erststart-Onboarding mit Sir Quacksec

Ein sechsstufiger, ausschließlich per D-Pad bedienbarer Assistent: Begrüßung, Funktionsweise des
lokalen Schutzes, VPN-Einwilligung, Threat-Intelligence-Sync (überspringbar), erste Prüfung und eine
Zusammenfassung, die den vollen Schutz aktiviert. Nichts wird vorgetäuscht: Wird die Einwilligung
abgelehnt oder scheitert ein Schritt, sagt der Assistent das.

### Threat-Intelligence-Sync-Overlay

Ein D-Pad-sicheres Overlay zeigt den Fortschritt der Feed-Synchronisierung, während öffentliche
IOC-Feeds aktualisiert werden. Veraltete oder fehlgeschlagene Synchronisierung wird ehrlich gemeldet
und kann später wiederholt werden.

### Evidenz, Berichte und Export

- Lokales Evidenz-Ledger mit HMAC-verifizierter Hash-Kette und verschlüsselten Payloads; fail-closed
  bei Schlüsselverlust, statt still eine neue Kette zu beginnen.
- Lokaler Sicherheitsbericht als Text und JSON.
- Export über die System-Dateiauswahl (SAF); auf TV-Images ohne Dokumentauswahl nutzt die App einen
  berechtigungsfreien `Downloads/GeDefenseTV`-Fallback und teilt dem Nutzer mit, wo die Dateien liegen.

### Sechs Sprachen, vollständig lokalisiert

Englisch (Standard), Deutsch, Französisch, Russisch, vereinfachtes Chinesisch und Japanisch —
vollständige Ressourcensätze für jeden UI-String, geprüft durch den Übersetzungs-Checker des Repositories.

### Geräte-Audit und Befunde

Neben der Filterung behält GeDefense TV die lesende Audit-Oberfläche, mit der das Produkt begonnen hat:

- **Geräte-Posture:** Android-Version/API-Level, Build-Fingerprint, ABI und Patch-Alter-Klassifikation —
  ausdrücklich Metadaten, keine Verwundbarkeitsgarantie.
- **Sichtbare Apps:** Version, Installer, Signatur-Digests und NEU/GEÄNDERT gegenüber einer Baseline,
  mit offen ausgewiesenen Grenzen der Android-Package-Visibility.
- **Härtungsprüfungen:** ADB/Debugging, Entwickleroptionen, test-keys/userdebug-Builds, Device-Admin-Pakete,
  Accessibility-Dienste und Nicht-Store-Installer — tri-state, wobei nicht lesbare Werte unlesbar bleiben
  und nie als „sicher“ gelten.
- **Befunde und Threat Intelligence:** erklärbare Befunde mit Schwere, Konfidenz und Sichtbarkeit sowie
  lokaler Feed-Aktualität und Indikator-Treffern.

### Ehrliches Statusmodell

Das Statusmodell ist das Produkt: Fähigkeit und Sichtbarkeit sind zentrale Daten. Statt eines grünen
„sicher“-Abzeichens gibt es einen Sicherheitswert nur bei ausreichender Abdeckung, explizite
Teilsichtbarkeits-Kennzeichnungen und eine klare Aussage darüber, was nicht beobachtet werden konnte.

## Funktionsweise

```text
Android TV / Google TV (nicht gerootet)
┌──────────────────────────────────────────────────────────────────────────┐
│ :app  (normale App-Sandbox, kein AndroidX, keine Drittanbieter-Laufzeit)  │
│   UI (Views, D-Pad)   Protection   Network   XDR   Onboarding   Settings │
│   Contracts / Services                                                    │
│        │                                                                  │
│   TvVpnService (Foreground-Service, lokales TUN)                          │
│        │  begrenzte Steuerung + Telemetrie                                │
│        ▼                                                                  │
│   GaiaNet-Helper (vendorte native .so, Kindprozess, kein Root)            │
│        DNS-/Flow-Richtlinie  →  direkter Egress zum Ziel                  │
└──────────────────────────────────────────────────────────────────────────┘
     :tv-core — reine JVM-Domäne: Scan, Scoring, Traffic, XDR, Anomalien,
                 Containment-Richtlinie, Geo-Helfer, Berichte, Events
     :core    — vendorter, byte-identischer GeDefense-Mobile-Core
```

## Umfang und Grenzen

GeDefense TV ist bewusst **nicht**:

- ein externer VPN- oder Geo-Unblocking-Dienst — es gibt keinen Server und nichts wird vom Gerät weg getunnelt;
- ein Virenscanner oder Malware-Entferner — es beobachtet Netzwerkverhalten und berichtet, es bereinigt keine Apps;
- ein privilegiertes EDR — kein Kernel-Zugriff, kein Root, keine systemweite Prozess- oder Flow-Überwachung;
- ein Ersatz für Router/Gateway/Firewall — es läuft nur auf dem Fernseher;
- ein vollständiges App-Inventar — Androids Package Visibility begrenzt, was eine App sehen kann;
- eine Schutzgarantie — die Filterung erfasst nur Verkehr, der tatsächlich durch den lokalen Datenpfad
  läuft, und nur die Richtlinien, die sie kennt.

Weitere bekannte Einschränkungen:

- **Alpha-Qualität:** echte TV-Hardware (OEM-Geräte) ist noch nicht verifiziert; Emulator-Verhalten ist
  die aktuelle Evidenzbasis.
- **DNS-Sichtbarkeit:** DoT/DoH-Verkehr verbirgt Domains vor der lokalen Beobachtung.
- **Geo-Zuordnung ist Näherung:** CDNs, Anycast und Shared Hosting können dem falschen Land zugeordnet werden.
- **Containment ist bewusst temporär:** kurze TTL, maximal vier aktive Sperren, leicht rückgängig zu
  machen — keine dauerhafte Firewall-Regel.
- **Test-signierte Alpha-APK:** kein produktionssignierter Build; Sideloading erfordert das Erlauben
  unbekannter Quellen.

## Sicherheit und Datenschutz

- **Keine Telemetrie, keine Analytics, keine Werbung, keine Crash-SDKs.** Die App enthält kein
  Drittanbieter-Laufzeit-SDK.
- **Keine Inhaltserfassung:** keine Bildschirm-, Audio-, Video- oder Payload-Erfassung; keine
  TLS-Interception.
- **Lokale Verarbeitung als Standard:** Traffic-Metadaten, Befunde und Evidenz bleiben auf dem Gerät.
- **Minimale Berechtigungen:** `INTERNET`, `ACCESS_NETWORK_STATE`, `FOREGROUND_SERVICE`,
  `FOREGROUND_SERVICE_SPECIAL_USE`, `POST_NOTIFICATIONS` plus die Service-Permission
  `BIND_VPN_SERVICE`. Kein Standort, keine Accessibility, kein Overlay, keine Kamera, kein Mikrofon,
  kein `QUERY_ALL_PACKAGES`.
- **Nur öffentliche Daten verlassen das Gerät:** Threat-Intelligence-Feeds und ein IP-zu-Land-Datensatz
  werden per HTTPS geladen; keine Gerätedaten werden hochgeladen.
- **Sicherheitsmeldungen:** siehe [SECURITY.md](SECURITY.md). Bitte keine ausnutzbaren Details in
  öffentlichen Issues veröffentlichen.

Vollständige Datenübersicht: [PRIVACY.md](PRIVACY.md) · [DATA-SAFETY.md](DATA-SAFETY.md).
Sicherheitsdesign und Bedrohungsmodell: [SECURITY.md](SECURITY.md) · [THREAT-MODEL.md](THREAT-MODEL.md).

## Voraussetzungen

| Komponente | Anforderung |
| --- | --- |
| Gerät | Android TV OS / Google TV, `minSdk 26` (Android 8.0) oder neuer, `arm64-v8a` oder `x86_64` |
| TV-UI | Leanback-kompatibler Launcher, D-Pad-Fernbedienung (kein Touch nötig) |
| Build | JDK 17, Android-SDK-Plattform 36, Build-Tools 36.0.0, Gradle 8.7 (Wrapper enthalten) |
| Laufzeitabhängigkeiten | keine — kein AndroidX, keine Drittanbieter-Bibliotheken |

## Installation (Sideload)

1. Erlaube auf dem Fernseher die Installation aus unbekannten Quellen für die App, mit der du APKs
   installierst (Sideload-/Dateimanager-App oder ADB).
2. Installiere die APK aus dem [neuesten Release](https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha2/VGT_GeDefense_TV_0.2.0-alpha2_VC3_release-signed.apk).
3. Starte **GeDefense TV**, folge dem Onboarding und bestätige den einmaligen Android-VPN-Dialog.
4. Optional per ADB:

```bash
adb connect <tv-ip>:5555
adb install -r VGT_GeDefense_TV_0.2.0-alpha2_VC3_release-debugsigned.apk
adb shell am start -n de.visiongaia.gedefense.tv/.TvMainActivity
```

Die Alpha-APK ist **test-signiert**. Ein Produktions-Signaturschlüssel ist nicht Teil dieser Alpha.

## Aus dem Quellcode bauen

```bash
git clone https://github.com/visiongaiatechnology/gedefense_androidtv.git
cd gedefense_androidtv

export JAVA_HOME=/path/to/jdk-17
export ANDROID_HOME=/path/to/android-sdk

./gradlew :app:assembleDebug           # Debug-APK
./gradlew :app:assembleRelease         # R8-minifizierte Release-APK
```

Die Release-Signierung liest `GEDEFENSE_RELEASE_STORE_FILE`, `GEDEFENSE_RELEASE_STORE_PASSWORD`,
`GEDEFENSE_RELEASE_KEY_ALIAS` und `GEDEFENSE_RELEASE_KEY_PASSWORD` aus der Umgebung. Ohne diese
Variablen fällt der Build auf die Debug-Signatur zurück — in Ordnung für Alpha-Tests, nicht für die
Verteilung. Mehr dazu: [BUILD-RUNBOOK.md](BUILD-RUNBOOK.md).

## Tests

```bash
./gradlew :tv-core:tvCoreCheck     # Domänen-Harness Core
./gradlew :tv-core:tvV2Check       # Traffic-/Privacy-/XDR-Domänen-Harness
./gradlew :tv-core:tvKineticCheck  # V2.1-Anomalie- und Containment-Harness
./gradlew :app:lintDebug           # Android Lint
```

Der Harness des vendorten Cores (`:core:coreCheck`) benötigt eine Linux-/macOS-JVM: Sein
Durable-File-Code nutzt Verzeichnis-`fsync`, das unter Windows nicht unterstützt wird. Die
Emulator-Anleitung inklusive AVD-Erstellung und Screenshot-Aufnahme steht in
[docs/TV-EMULATOR-TESTING.md](docs/TV-EMULATOR-TESTING.md). Die Abnahmematrix ist
[TEST-PLAN.md](TEST-PLAN.md).

## Projektstruktur

```text
.
├── app/                    Android-TV-App-Modul (Views, kein AndroidX)
│   └── src/main/            java/ · res/ (6 Sprachen) · assets/ · jniLibs/ · AndroidManifest.xml
├── core/                   vendorter, byte-identischer GeDefense-Mobile-Core (reine JVM)
├── tv-core/                reine JVM-Domäne: Scan, Scoring, Traffic, XDR, Anomalien, Berichte
├── docs/                   Architektur, Traffic-Map, Onboarding, Design-DNA, Emulator-Guide,
│                           screenshots/ und assets/
├── tools/                  Build-/Test-/Emulator-/Remote-/Verifikationsskripte
├── gradle/ + gradlew*      Gradle-8.7-Wrapper (Distribution-SHA-256 gepinnt)
├── build.gradle.kts        AGP 8.5.2 · Kotlin 1.9.24 · Java 17
└── settings.gradle.kts     Module :core, :tv-core, :app
```

## Dokumentation

| Dokument | Inhalt |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Modulgraph, Datenfluss, Collectors, Evidenz, Performance-Budgets |
| [docs/V2-ARCHITECTURE.md](docs/V2-ARCHITECTURE.md) | Loopback-VPN, Telemetrie, Traffic-Aggregation, Supply-Chain des nativen Helpers |
| [docs/TRAFFIC-MAP.md](docs/TRAFFIC-MAP.md) | Datenquellen der Traffic-Map, Grenzen, Farben und Datenschutz |
| [docs/ONBOARDING.md](docs/ONBOARDING.md) | Erststart-Assistent, Einwilligungs- und Berechtigungserklärungen |
| [docs/DESIGN-DNA.md](docs/DESIGN-DNA.md) | TV-Designsystem, Fokus-/Interaktionsregeln, verbotene Muster |
| [SECURITY.md](SECURITY.md) | Sicherheitsdesign, Schlüsselverwahrung, Berechtigungen, Meldeweg |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Assets, Vertrauensgrenzen, STRIDE-Analyse, TV-spezifische Risiken |
| [PRIVACY.md](PRIVACY.md) | Dateninventar, Aufbewahrung, Export, Begründung der Berechtigungen |
| [TEST-PLAN.md](TEST-PLAN.md) | Abnahmematrix und Evidenzanforderungen |
| [BUILD-RUNBOOK.md](BUILD-RUNBOOK.md) | Build, Signierung, Logs und Fehlerbehebung |
| [docs/TV-EMULATOR-TESTING.md](docs/TV-EMULATOR-TESTING.md) | Schritt-für-Schritt-Anleitung Android-TV-Emulator |
| [docs/SOURCES.md](docs/SOURCES.md) | Quellen und Referenzen |
| [RELEASE-NOTES.md](RELEASE-NOTES.md) | Änderungen dieser Alpha und ihr Verifikationsstatus |

## Lizenz und Drittanbieter-Hinweise

GeDefense TV ist freie Software unter der **GNU Affero General Public License v3.0 (AGPL-3.0)**.
Du darfst sie gemäß den Bedingungen der AGPL-3.0 nutzen, untersuchen, verändern und weitergeben.
Wenn du eine veränderte Version als Netzwerkdienst betreibst, verlangt die AGPL, dass du den
entsprechenden Quellcode den Nutzern anbietest. Den vollständigen Lizenztext findest du in
[LICENSE](LICENSE). Die Software wird ohne Gewährleistung bereitgestellt, wie in der Lizenz beschrieben.

Drittanbieter-Komponenten, vendorte Binärdateien, Assets und Laufzeit-Datenquellen (öffentliche
Threat-Intelligence-Feeds, der öffentliche IP-zu-Land-Datensatz, die Go-Standardbibliothek im nativen
Helper) sind in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) dokumentiert.

## Alpha-Feedback

Feedback ist willkommen über [GitHub Issues](https://github.com/visiongaiatechnology/gedefense_androidtv/issues).
Bitte gib Gerätemodell, Android-TV-OS-Version und die in den Einstellungen angezeigte App-Version an.
Veröffentliche keine Geheimnisse, personenbezogenen Daten oder ausnutzbaren Sicherheitsdetails in
öffentlichen Issues — siehe [SECURITY.md](SECURITY.md).

---

<p align="center"><i>GeDefense TV ist ein Projekt von VisionGaiaTechnology.<br>
„The humor is load-bearing. The code is not a joke.“</i></p>
