# GeDefense TV — Datenschutz / Privacy

> **Release-Tree 0.2.0-alpha1:** Dieses Dokument ist für den Quellstand `0.2.0-alpha1` (VersionCode 2) kuratiert. Evidenzangaben mit Datum 29.10.2026 beziehen sich auf den jeweils genannten Build; V2/V2.1-Funktionen sind Alpha und nicht vollständig auf realer TV-Hardware abgenommen.


**Version:** 0.2.0-alpha1 · **Stand:** 29. Oktober 2026 · **Status:** Design- und
Dokumentationsstand; keine Datenschutzerklärung im Rechtssinn veröffentlicht, keine
Aufsichts-/Anwaltsprüfung erfolgt.

Dieses Dokument beschreibt, welche Daten GeDefense TV verarbeitet, wo sie bleiben, wie lange sie
bleiben und was der Nutzer kontrollieren kann. Es ist bewusst nüchtern und enthält keine
Marketingaussagen. Wo die Implementierung hinter der Beschreibung zurückbleibt, steht das
ausdrücklich dabei.

---

## 1. Grundsatz: lokale Verarbeitung als Standard

1. **Alle Sicherheitsdaten bleiben auf dem Gerät.** V1 besitzt **keine Telemetrie**, keine
   Analytics-, Crash-Reporting- oder Werbe-SDKs und keinen stillen Upload.
2. **Kein Konto, keine Cloud, kein Backend.** Die App funktioniert ohne Registrierung; es gibt
   keine VGT-Dienstkommunikation in V1.
3. **Netzwerkzugriffe sind rein abrufend:** Die App lädt öffentliche Threat-Intelligence-Feeds
   per HTTPS herunter (9 Quellen, siehe [ARCHITECTURE.md](ARCHITECTURE.md) §8). Dabei werden
   **keine** Gerätedaten, App-Listen, Befunde oder Nutzungsspuren an die Feed-Anbieter
   übermittelt. Technisch unvermeidbar sieht der Anbieter die öffentliche IP-Adresse des
   Geräts (wie bei jedem direkten HTTPS-Abruf).
4. **Keine Erfassung von Inhalten:** keine Audio-, Video-, Bildschirm-, Kamera- oder
   Streaming-Inhalte; keine Standortdaten; keine Kontakte, SMS, Kalender, Dateien oder
   Zwischenablage; keine Tastatureingaben.
5. **Keine Nutzungsprofile:** Die App erstellt kein Verhaltens- oder Interessenprofil. Es gibt
   keinen Usage-Access-Zugriff in V1 (`PACKAGE_USAGE_STATS` wird nicht angefordert).

---

## 2. Dateninventar

| Kategorie | Beispiele | Zweck | Speicherort | Aufbewahrung (Design) | Verlässt Gerät? |
| --- | --- | --- | --- | --- | --- |
| Pseudonyme Geräte-ID | `tv_` + 32 Hex-Zeichen (SecureRandom) | Korrelation lokaler Befunde ohne Klarnamen | `SharedPreferences "gedefense_tv"` | persistiert bis App-Datenlöschung | **nein** |
| Plattform-/Build-Metadaten | Android-Release, API-Level, Hersteller, Modell, Gerät, Fingerprint, Patch-Datum, ABIs | Security-Posture, Report | in-memory; ggf. Evidenz | Scan-Lebensdauer / Evidenz-Retention | **nein** |
| Sichtbares App-Inventar | Paketname, Label, Version, Signatur-Digest (SHA-256), Installer-Kennung, Install-/Update-Zeit | App-Hygiene, Änderungserkennung | in-memory; nicht zentral übertragen; **keine** rohen Paketlisten im JSON-Export | Scan-Lebensdauer | **nein** |
| Hardening-Beobachtungen | Debugging-/Entwickleroptionen, Build-Tags/-Typ, Device-Admin-Pakete, Accessibility-Dienste, sichtbare Nicht-Store-Installer | Hardening-Hinweise | in-memory/Evidenz | Evidenz-Retention | **nein** |
| Befunde/Findings | Regel-ID, Schwere, Konfidenz, Komponente, Evidenzreferenz | Nachvollziehbarkeit | Evidenz-Ledger | Retention-Einstellung | **nein** |
| Evidenz-Ledger | Events, Befund-/Aktionsverlauf | tamper-evidentes lokales Protokoll | `noBackupFilesDir/evidence/events.v3.log` (HMAC + AES-256-GCM) | bis zur **manuellen Löschung**; automatische Retention ist V2 und in V1 nicht aktiv | **nein** |
| TI-Feed-Cache | Indikator-Präfixe, Quelle, Abrufzeit, Ablaufstatus | Offline-IOC-Prüfung | `filesDir/threat-intel/` | Feed-spezifisches Stale-Budget (Core) | **nein** |
| Einstellungen | TI-Autosync, Retention, `lastScanAt`, Onboarding | Nutzerkontrolle | `SharedPreferences "gedefense_tv"` | bis App-Datenlöschung | **nein** |
| Bericht (Export) | Score, Findings, Sichtbarkeit, Evidenz-Gesundheit, TI-Status, Device-ID | Nutzer-Export | primär nutzergewählter SAF-Zielort; Fallback `Downloads/GeDefenseTV` (MediaStore, API 29+) bzw. app-spezifisches Dokumentverzeichnis (API 26–28) | außerhalb des App-Einflusses | **nur auf ausdrückliche Nutzeraktion** |

**Nicht verarbeitet:** Klarname, E-Mail, Telefonnummer, Adresse, Geburtsdatum, Konten,
Standort, biometrische Daten, Gesundheitsdaten, Zahlungsdaten, Werbe-ID, IMEI/Seriennummer
(sofern nicht Teil der öffentlichen Build-Metadaten), Inhalte von Streaming-Diensten.

---

## 3. Rechtsgrundlage und Verantwortlichkeit (offen)

- Verantwortlich im Sinne der DSGVO ist die VisionGaiaTechnology (VGT) als Produktorganisation.
  Eine **veröffentlichte Datenschutzerklärung mit ladungsfähiger Anschrift/Impressum** liegt im
  Projekt noch **nicht** vor; das ist ein offener Punkt vor einer Veröffentlichung.
- Soweit überhaupt personenbezogene Daten anfallen (pseudonyme Geräte-ID, technische
  Geräte-Metadaten), erfolgt die Verarbeitung **ausschließlich lokal auf dem Gerät** und dient
  der Sicherheitsdiagnostik. Es findet keine Übermittlung an VGT oder Dritte statt.
- Es gibt **kein** Tracking, keine Profilbildung und keine automatisierte Entscheidungsfindung
  mit Rechtswirkung.
- Für eine Google-Play-Veröffentlichung ist zusätzlich eine Data-Safety-Erklärung erforderlich;
  Entwurf: [DATA-SAFETY.md](DATA-SAFETY.md) (nicht eingereicht).

---

## 4. Aufbewahrung und Löschung

| Datenart | Design | Ist-Stand 29.10.2026 |
| --- | --- | --- |
| Evidenz-Ledger | Aufbewahrung **bis zur manuellen Löschung**; automatische Rotation/Retention ist **V2** und in V1 **nicht aktiv** | `retentionDays` wird **nicht** als wirksame Löschautomatik dargestellt (kein Fake-Control). Manuell: `EvidenceApi.clear()` löscht die Ledger-Datei. |
| TI-Cache | Generationen begrenzt (max. 2 je Feed), alte Generationen werden bereinigt | geplant/implementiert in Core-Pfad – **NOT_TESTED** |
| Settings/Device-ID | bleiben, bis App-Daten gelöscht werden | kein automatisches Löschen |
| Exporte | liegen außerhalb der App (SAF-Ziel oder `Downloads/GeDefenseTV`-Fallback) | Nutzer muss sie selbst löschen; die App kann fremde/öffentliche Speicherorte nicht kontrollieren. Fallback-Dateien bleiben auch nach `clear()`/Deinstallation bestehen. |

**Deinstallationsverhalten:** Mit dem Deinstallieren der App entfernt Android die privaten
App-Daten (SharedPreferences, `filesDir`, `noBackupFilesDir`). `allowBackup="false"` verhindert
eine Wiederherstellung aus Cloud-Backups.

**Wichtige Ehrlichkeit:** Automatische Retention ist **V2**. In V1 bleiben Befunde bis zur
manuellen Löschung erhalten; weder Dokumentation noch UI dürfen eine automatische Löschung nach
30 Tagen suggerieren. Die Einstellung `retentionDays` ist vorhanden, aber in V1 **nicht wirksam**
und wird nicht als wirksam dargestellt (tv-ui soll keinen scheinbar wirksamen Selektor zeigen).

---

## 5. Exportinhalte

Der Report (Text/JSON) wird **nur** auf ausdrückliche Nutzeraktion geschrieben – primär über den
System-Dateidialog (SAF, `ACTION_CREATE_DOCUMENT`). **TV-Realität:** Viele Android-TV-/Google-TV-
Images besitzen keinen nutzbaren SAF-Picker (Framework-Stub). Dann schreibt die App die beiden
Dateien selbst ohne Storage-Permission:

- API 29+: MediaStore `Downloads/GeDefenseTV` (öffentlicher Download-Ordner),
- API 26–28: app-spezifisches externes Dokumentverzeichnis.

Dateinamen: `GeDefense-TV-Report-<yyyyMMdd-HHmmss>.txt`/`.json` (UTC). Belegt im Emulator:
**30.246 B** Text und **4.562 B** JSON (valides JSON). Da der Fallback in einen öffentlichen
Ordner schreibt, muss der Nutzer diese Dateien selbst löschen; sie sind nicht Teil der
App-Datenlöschung.

Der Report enthält:

- Scan-Zusammenfassung, Posture-Score/Band inkl. Sichtbarkeitsstatus (`FULL`/`PARTIAL`/`STALE`/
  `NONE`) und Kappungsgrund,
- Findings mit Regel-ID, Schwere, Konfidenz, Komponente, Evidenzreferenz,
- Evidenz-Gesundheit (Ledger-Status, Record-Anzahl, ggf. Fehlergrund),
- TI-Status (Feeds, Alter, fresh/stale, Sync-Zustand),
- pseudonyme Geräte-ID und Bewertungszeitpunkt,
- Scope/Limitations-Hinweise.

Er enthält **nicht**: Keystore-Schlüssel, Tokens, Secrets, rohe Logauszüge, vollständige
Paketlisten (JSON bewusst ohne rohe App-Liste), Audio/Video/Screen-Inhalte, personenbezogene
Daten des Nutzers.

Hinweis: Ein geteilter Report kann den Gerätezustand offenlegen. Der Nutzer entscheidet über
Zielort und Weitergabe; die App kennzeichnet den Bericht als sicherheitsrelevant.

---

## 6. Berechtigungen und ihre Begründung

| Berechtigung / Feature | Begründung | Missbrauchspotenzial |
| --- | --- | --- |
| `INTERNET` | HTTPS-Abruf der öffentlichen TI-Feeds | Nur ausgehend, nur feste Katalog-URLs |
| `ACCESS_NETWORK_STATE` | Netzwerkstatus/-wechsel der eigenen App | keine Standort-/Netzwerkinhalte |
| `<queries>` LEANBACK_LAUNCHER / LAUNCHER | Sichtbarkeit von TV-Apps für das Inventar | nur sichtbare Launcher-Pakete |
| `<queries>` https-VIEW | Sichtbarkeit von Apps, die HTTPS-URLs öffnen (begrenzter Review-Kontext) | keine Inhaltsdaten |
| `uses-feature leanback required` | TV-Gerät erforderlich | keine Daten |
| **nicht** angefordert: `QUERY_ALL_PACKAGES`, `PACKAGE_USAGE_STATS`, BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW, Kamera, Mikrofon, Standort, Speicher, Kontakte, SMS | bewusst weggelassen | — |

Die App fordert **keine** Laufzeitberechtigungen an und hat keine Berechtigungs-Dialoge. Damit
gibt es auch keine „Berechtigung verweigert“-Pfade für Kernfunktionen – die Einschränkungen
entstehen durch Plattform-APIs (Package Visibility, OEM-Verhalten) und werden als
`PARTIAL`/`UNKNOWN` ausgewiesen.

---

## 7. Nutzerkontrolle

| Kontrolle | Umsetzung |
| --- | --- |
| Scan starten/abbrechen | `ScanControllerApi.start/cancel` |
| TI-Autosync an/aus | `SettingsApi.tiAutoSyncEnabled` |
| TI manuell synchronisieren | `ThreatIntelApi.syncNow` |
| Evidenz einsehen | `EvidenceApi.rows(limit)` |
| Evidenz löschen | `EvidenceApi.clear()` |
| Report exportieren | `ReportApi.export` (SAF, bei fehlendem Picker MediaStore-Fallback) |
| Retention einstellen | automatische Retention ist **V2**; in V1 keine wirksame Automatik, keine Fake-Anzeige |
| App-Daten vollständig löschen | Android-Systemeinstellungen (App-Daten löschen/deinstallieren) |

---

## 8. Kinder, Werbung, Drittanbieter

- Keine Werbung, keine In-App-Käufe, keine personalisierte Werbe-ID.
- Keine Ausrichtung auf Kinder; die App ist ein Sicherheitswerkzeug für TV-Geräte.
- Keine Drittanbieter-SDKs zur Laufzeit; damit auch keine SDK-Datenflüsse.
- Die einzigen externen Kontakte sind die im Core-Katalog fest definierten Feed-URLs.

---

## 9. Offene Punkte (vor Veröffentlichung)

1. **Datenschutzerklärung/Impressum** veröffentlichen (Verantwortlicher, Kontakt, Rechte) –
   **offener Punkt**, derzeit offen.
2. **Retention/Rotation (V2):** in V1 bewusst nicht aktiv; bis dahin klar kommunizieren, dass
   Daten bis zur manuellen Löschung bleiben.
3. **Data-Safety-Erklärung** für Google Play erstellen und einreichen (Entwurf vorhanden).
4. **Feed-Anbieter-Transparenz** im UI/Report klar benennen (URLs/Attribution).
5. **Löschkonzept für Exporte** beschreiben (App kann fremde Speicherorte nicht löschen).
6. **Rechtsprüfung** (DSGVO, TV-Plattformrichtlinien, Google-Play-Policy) durchführen.

---

## 10. V2: Loopback-VPN und Traffic-Metadaten

**Status:** Planungsstand 29.10.2026 · **Evidenz: NOT_TESTED** (V2-Implementierung in Arbeit).
Architektur: [docs/V2-ARCHITECTURE.md](docs/V2-ARCHITECTURE.md).

Mit V2 verarbeitet die App zusätzlich **lokale Verkehrs-Metadaten**, um Telemetrie/Tracker/C2 zu
filtern und die Traffic-Map zu füllen. Es werden weiterhin **keine Inhalte** erfasst oder
entschlüsselt.

### 10.1 Zusätzliches Dateninventar (V2)

| Kategorie | Felder (Beispiele) | Zweck | Verbleib | Verlässt Gerät? |
| --- | --- | --- | --- | --- |
| Traffic-Snapshot | Zustand, Start-/Update-Zeit, tx/rx-Bytes, aktive/blockierte/korrelierte Flows, Transportfehler | Schutz-/Traffic-Anzeige | lokal, in-memory/Snapshot | **nein** |
| App-Traffic | Paketname/Label (soweit sichtbar), tx/rx, Flow-Zähler, Top-Länder/-Domains (≤ 12) | App-bezogene Auswertung | lokal, begrenzt | **nein** |
| Flow-Historie | App-Owner, Ziel-IP, Land (optional), Domain (nur lokal beobachtet), Aktion, Protokoll, Bytes, Zeiten | Nachvollziehbarkeit/Traffic-Map | lokal, begrenzte Tail-Historie (`flows(limit=200)`) | **nein** |
| Länder-Aggregat | ISO-Ländercode, Bytes, Flows, blockierte Flows | Karten-/Länderansicht | lokal, ≤ 64 Länder | **nein** |
| Domain-Aggregat | beobachtete Domain, Queries, blockierte Queries | Tracker-/Domain-Ansicht | lokal, ≤ 200 Domains | **nein** |
| Herkunftsland | Land/GeoPunkt, Label | Karten-Projektion | lokal; aus Locale/Netz, **kein GPS** | **nein** |
| XDR-Ereignisse | Regel, Schwere, Konfidenz, Komponente, Evidenz | Korrelation/Evidenz | lokale HMAC-Evidenz | **nein** |

**Nicht verarbeitet:** Payloads, TLS-/QUIC-Klartexte, Bildschirminhalte, Audio/Video, Standort
(GPS), Kontakte, Nachrichten, Werbe-ID.

### 10.2 Keine Inhaltserfassung, kein MITM

- Das Loopback-VPN filtert anhand von Verbindungs-/DNS-Metadaten; TLS-Inhalte werden **nicht**
  entschlüsselt, keine Zertifikate installiert, kein Proxy eingerichtet.
- Bei verschlüsseltem DNS (DoT/DoH) ist der Domainname für die App **nicht sichtbar**; sichtbar
  bleiben Ziel-IP/Land und Metadaten. Die UI muss das als Einschränkung benennen
  ([TRAFFIC-MAP.md](docs/TRAFFIC-MAP.md)).
- Es gibt **keinen externen VPN-Server**: Der Datenpfad endet lokal; Zielserver sehen nur den
  üblichen Geräte-Verkehr.

### 10.3 Herkunftsland ohne Standortberechtigung

Das geschätzte Herkunftsland stammt aus System-Locale/Netzwerk-Metadaten (z. B. Zeitzone/Locale),
nicht aus GPS oder Standort-APIs. Die App fordert **keine** Standortberechtigung an. Die Angabe ist
eine Schätzung und kann falsch sein; sie wird optional manuell korrigierbar (V2.1+).

### 10.4 Retention und Löschung (V2)

| Datenart | Festlegung | Status |
| --- | --- | --- |
| Live-Snapshot | nur Laufzeit; Zähler über `TrafficApi.clearSession()` löschbar | Implementierung **NOT_TESTED** |
| Flow-Historie | begrenzte Tail-Historie (Standard `flows(limit=200)`), keine unbegrenzte Speicherung | Modell-Cap vorhanden; Persistenz/Retention **NOT_TESTED** |
| Aggregate | Caps: Apps ≤ 200, Länder ≤ 64, Domains ≤ 200, Top-Listen ≤ 12 | Modell erzwungen |
| XDR/Evidenz | bestehende HMAC-Evidenz, Retention wie V1 (manuell; Automatik V2) | von V1 unverändert |
| Traffic-Persistenz über Neustart | geplant/implementierungsabhängig; **nicht** als dauerhaft garantiert darstellen | **NOT_TESTED** |

**Ehrlichkeit:** Solange die V2-Retention nicht implementiert und getestet ist, darf weder Doku
noch UI eine automatische Löschung oder eine bestimmte Aufbewahrungsdauer für Traffic-Metadaten
versprechen.

### 10.5 Nutzerkontrolle (V2)

| Kontrolle | Wirkung |
| --- | --- |
| Schutz aus / VPN stoppen | beendet Datenpfad; keine „geschützt“-Anzeige |
| Profil Off/Konservativ/Ausgewogen/Streng | Filterintensität; Fehlblockungsrisiko steigt mit Strenge |
| Auto-Start an/aus | Start nach Geräte-/App-Neustart nur mit vorhandenem Consent |
| Detaillierte Telemetrie an/aus | mehr/weniger lokale Traffic-Details; **kein** Upload |
| Session-Zähler löschen | setzt Traffic-Snapshot zurück (stoppt VPN nicht) |
| Evidenz/Bericht löschen/exportieren | wie V1; Export nur Nutzeraktion |

### 10.6 Export- und Daten-Safety-Implikationen

- Ein Report kann V2-Aggregate (z. B. Top-Länder/-Domains oder Blockzähler) enthalten; **keine
  rohen Flow-Dumps** und keine Payloads. Die exakte Report-Erweiterung ist **NOT_TESTED**.
- Geteilte Reports können Nutzungsverhalten offenlegen → minimierte Felder, Warnhinweis.
- Data-Safety-Entwurf: Traffic-Metadaten bleiben lokal, werden nicht „erhoben/geteilt“ im
  Play-Sinne; VPN-Consent und FGS-Benachrichtigung sind gesondert zu erklären
  ([DATA-SAFETY.md](DATA-SAFETY.md)).

### 10.7 Offene Punkte (V2, vor Veröffentlichung)

1. V2-Datenschutztext (Traffic-Metadaten, VPN-Consent, Benachrichtigung, Retention) verfassen.
2. Retention/Persistenz der Traffic-Historie implementieren und belegen.
3. Export-Inhalte der V2-Reports prüfen (keine Roh-Flows/keine DNS-Dumps).
4. Play-Data-Safety und FGS-/VPN-Deklaration aktualisieren.
5. Nachweis „keine Uploads“ (Code-Review + Netzwerk-/Proxy-Test) führen.
6. Löschkonzept für Traffic-Metadaten (Session, App-Daten, Deinstallation) dokumentieren.
