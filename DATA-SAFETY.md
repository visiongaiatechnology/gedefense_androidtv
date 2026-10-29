# GeDefense TV — Data-Safety-Entwurf (Google Play)

> **Release-Tree 0.2.0-alpha1:** Dieses Dokument ist für den Quellstand `0.2.0-alpha1` (VersionCode 2) kuratiert. Evidenzangaben mit Datum 29.10.2026 beziehen sich auf den jeweils genannten Build; V2/V2.1-Funktionen sind Alpha und nicht vollständig auf realer TV-Hardware abgenommen.


**Status:** ENTWURF · **Stand:** 29. Oktober 2026 · **NICHT bei Google Play eingereicht**
(`Play-Console-Status: NOT_SUBMITTED`). Dieses Dokument ist eine interne Vorbereitung, keine
Rechtsberatung und keine offizielle Erklärung gegenüber Google.

Grundlage: Die App verarbeitet Daten ausschließlich lokal. Es gibt keine Telemetrie, kein
Backend, keine Analytics- oder Crash-SDKs. Netzwerkzugriffe sind rein abrufend (öffentliche
Threat-Intelligence-Feeds über HTTPS). Damit sind die folgenden Antworten für das
Data-Safety-Formular vorbereitet — sie müssen vor einer Veröffentlichung gegen die dann gültige
Play-Definition und den finalen Code geprüft werden.

---

## 1. Vorbereitete Formularantworten

| Frage (Data-Safety-Formular) | Entwurfsantwort | Begründung |
| --- | --- | --- |
| Erhebt oder teilt die App Nutzerdaten? | **Nein** (keine Übertragung vom Gerät zu Servern des Entwicklers oder Dritter) | Kein Backend, keine Analytics/Crash-SDKs; einzige ausgehende Verbindung sind HTTPS-Abrufe öffentlicher Feeds (kein Upload von Gerätedaten). |
| Werden Daten verschlüsselt übertragen? | **Ja**, soweit überhaupt übertragen wird | Ausschließlich HTTPS (`usesCleartextTraffic="false"`); keine Klartext-Übertragung. |
| Kann der Nutzer die Löschung der Daten verlangen? | **Lokale Löschung durch Nutzer/System** | `EvidenceApi.clear()` und Android-App-Datenlöschung/Deinstallation; kein serverseitiger Datenbestand. Automatische Retention/Rotation ist **V2** und in V1 nicht aktiv. |
| Werden Daten an Dritte geteilt? | **Nein** | Keine Weitergabe; Export nur auf ausdrückliche Nutzeraktion (SAF-Ziel oder – wenn das TV-Image keinen Picker hat – MediaStore-Ordner `Downloads/GeDefenseTV`). |
| Ist die App für Kinder geeignet? | **Nein, nicht ausgerichtet** | Sicherheitswerkzeug für TV-Geräte; keine kinderspezifischen Inhalte. |
| Werden Standortdaten erhoben? | **Nein** | Keine Standortberechtigung, keine Standort-APIs. |
| Werden Gesundheits-/Fitnessdaten erhoben? | **Nein** | Nicht relevant. |
| Werden Nachrichten/Kontakte/Kalender erhoben? | **Nein** | Keine entsprechenden Berechtigungen/APIs. |
| Werden Fotos/Videos/Audio erhoben? | **Nein** | Keine Kamera/Mikrofon/Bildschirmaufnahme; keine Medieninhalte. |
| Werden App-Aktivitäten (Nutzung) erhoben? | **Nein** | Kein `PACKAGE_USAGE_STATS`; keine Foreground-/Nutzungsanalyse in V1. |
| Werden Geräte- oder andere IDs erhoben/geteilt? | **Lokal, nicht geteilt** | Pseudonyme `tv_…`-ID wird lokal erzeugt und gespeichert; sie wird **nicht** an Server übertragen. |
| Werden Absturzprotokolle/Diagnosedaten erhoben? | **Nein** | Kein Crash-Reporting-SDK. |

**Play-Definitionshinweis:** Google unterscheidet „erhoben“ (Übertragung vom Gerät) von rein
lokaler Verarbeitung. Da keine Übertragung an den Entwickler oder Dritte stattfindet, lautet die
Entwurfsantwort „keine Erhebung/kein Teilen“. Der nutzerinitiierte Datei-Export verlässt das Gerät
auf Wunsch des Nutzers; das ist keine Erhebung durch die App, sollte aber im Datenschutztext
erklärt werden.

---

## 2. Datenarten und lokale Verarbeitung

| Datenart | Entsteht lokal? | Verlässt Gerät? | Zweck | Aufbewahrung |
| --- | --- | --- | --- | --- |
| Pseudonyme Geräte-ID (`tv_` + 32 Hex) | ja (SecureRandom) | nein (außer im nutzerinitiierten Report/Export) | lokale Befundkorrelation | bis App-Datenlöschung |
| Geräte-/Plattformmetadaten (Android-Version, OEM, Modell, Build, Patch) | ja (Build-APIs) | nein (außer Export) | Security-Posture | Scan/Evidenz-Retention |
| Sichtbares App-Inventar (nur sichtbare Pakete) | ja (PackageManager) | nein | App-Hygiene | Scan-Lebensdauer; nicht zentral |
| Hardening-Beobachtungen | ja | nein | Empfehlungen | Evidenz-Retention |
| Befunde/Evidenz | ja | nein | Nachvollziehbarkeit | bis zur manuellen Löschung; automatische Retention ist V2 und in V1 nicht aktiv |
| TI-Feed-Cache | ja (Download) | nein | Offline-IOC-Prüfung | Feed-Stale-Budget |
| Einstellungen | ja | nein | Nutzerkontrolle | bis App-Datenlöschung |

---

## 3. Sicherheitspraktiken (Entwurf)

- **Datenverschlüsselung im Ruhezustand:** Evidenz-Ledger per AES-256-GCM geschützt, HMAC-Kette;
  Schlüsselhohheit über Keystore-gewrappten 256-bit-Root (`TvKeyCustody`, Keyring
  `no_backup/evidence/keyring.v1`). Emulator-Beleg: Ledger „gesund“, 40 Einträge; Tamper-Test
  **NOT_TESTED**.
- **Datenverschlüsselung bei Übertragung:** ausschließlich HTTPS; keine Klartextpfade.
- **Unabhängige Sicherheitsprüfung:** Für 0.1.0-alpha1 **nicht** erfolgt/nachgewiesen. Keine
  MVS-/Pen-Test-Behauptung.
- **Datenminimierung:** minimale Manifest-Berechtigungen; keine Laufzeitberechtigungen; kein
  `QUERY_ALL_PACKAGES`.
- **Löschung:** lokale Datenlöschung über App-Funktion und Android-System; kein Serverbestand.
  Automatische Retention/Rotation ist **V2** und in V1 nicht aktiv (keine Fake-Löschautomatik).
- **Alpha-Artefakt:** Ein 0.1.0-alpha1-Build ist ausdrücklich ein debug-signiertes
  Testartefakt, kein produktionsfähiges Release.

---

## 4. Berechtigungsdeklaration (Play-Kontext)

| Berechtigung | Play-Relevanz |
| --- | --- |
| `INTERNET` | normal, für Feed-Abruf |
| `ACCESS_NETWORK_STATE` | normal, für Netzwerkstatus |
| `uses-feature android.software.leanback` (required) | TV-Geräte-Filter |
| `<queries>` (Intent-basiert) | Package Visibility ohne `QUERY_ALL_PACKAGES` |

**Keine** sensiblen/dangerous Permissions. Damit entfallen die typischen Play-Declaration-Formulare
(Standort, SMS, Anrufe, All-Files-Access, Accessibility, VPN). Ein späterer On-Device-VPN wäre
**nicht** Teil von V1 und würde eine gesonderte Play-Deklaration erfordern.

---

## 5. Vor Einreichung zu klären

1. Finalen Code gegen diese Antworten prüfen (insbesondere: keine später hinzugefügten SDKs,
   keine neuen Netzwerkziele, keine Upload-Pfade).
2. **Retention (V2):** automatische Rotation/Retention ist V2 und in V1 nicht aktiv; in der
   Datenschutzerklärung präzise als „Aufbewahrung bis manuelle Löschung“ beschreiben.
3. Datenschutzerklärung mit Verantwortlichem/Kontakt veröffentlichen (siehe [PRIVACY.md](PRIVACY.md)).
4. Exportverhalten im Datenschutztext erklären: SAF primär, bei fehlendem TV-Picker
   MediaStore-Fallback nach `Downloads/GeDefenseTV`; Dateien bleiben bis zur manuellen Löschung
   und sind nicht Teil der App-Datenlöschung.
5. Google-Play-TV-Anforderungen (z. B. Target-API-Mindeststand, Banner/Launcher-Kategorie) prüfen;
   das Datenblatt nennt Target API 34+ als Mindestanforderung für neue TV-Apps ab 31.08.2026 —
   die App baut mit `targetSdk 36`.
6. Keine „unabhängig geprüft“-Aussage verwenden, solange kein Auditbeleg existiert.

---

## 6. V2-Ergänzung: Loopback-VPN und Traffic-Metadaten

**Status:** Entwurf 29.10.2026 · **Evidenz: NOT_TESTED** (V2-Implementierung in Arbeit).
Grundlage: [docs/V2-ARCHITECTURE.md](docs/V2-ARCHITECTURE.md), [PRIVACY.md](PRIVACY.md) §10.

| Frage (Data-Safety-Formular) | Entwurfsantwort V2 | Begründung |
| --- | --- | --- |
| Erhebt/teilt die App Nutzerdaten? | **Nein** | Traffic-Metadaten (App, Ziel-IP/Land, Domain, Bytes, Zeiten) bleiben **lokal**; kein Upload, keine Cloud-Analyse. |
| Werden Daten verschlüsselt übertragen? | **Ja**, soweit übertragen wird | TI-Feeds HTTPS; der VPN-Datenpfad endet lokal, kein externer VPN-Server. |
| Werden Traffic-Inhalte erfasst? | **Nein** | Keine Payloads, kein TLS-MITM, keine Entschlüsselung; nur Verbindungs-/DNS-Metadaten. |
| Werden Standortdaten erhoben? | **Nein** | Herkunftsland aus Locale/Netzwerk, keine Standortberechtigung, kein GPS. |
| Werden Benachrichtigungen gesendet? | **Ja, nur FGS-Status** | Android verlangt für den VPN-Vordergrunddienst eine dauerhafte Benachrichtigung; `POST_NOTIFICATIONS` dient nur diesem Zweck. |
| Warum VPN-Berechtigung/Consent? | **Lokale Filterung** | `VpnService` erlaubt den lokalen TUN-Datenpfad; System-Dialog `VpnService.prepare`; kein externer Anbieter. |
| Löschung? | **Lokal/manuell** | `TrafficApi.clearSession()` für Session-Zähler; App-Daten/Deinstallation löschen lokale Stores; automatische Retention ist **V2/V2.x** und in V1 nicht aktiv. |
| Teilen mit Dritten? | **Nein** | Keine Weitergabe von Traffic-/App-Metadaten; Export nur Nutzeraktion mit minimierten Feldern. |

**Zusätzliche Play-Deklarationen (offen):** FGS-Typ `specialUse` mit Begründung, VPN-
Dienstdeklaration/-erklärung, Benachrichtigungsnutzung; Datenschutztext für Traffic-Metadaten.
**Status:** V2-Datenflüsse sind implementierungs- und testabhängig (**NOT_TESTED**); dieser
Abschnitt darf erst nach Code-/Laufzeitprüfung als offizielle Erklärung verwendet werden.
