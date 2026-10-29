# GeDefense TV — Threat Model

> **Release-Tree 0.2.0-alpha1:** Dieses Dokument ist für den Quellstand `0.2.0-alpha1` (VersionCode 2) kuratiert. Evidenzangaben mit Datum 29.10.2026 beziehen sich auf den jeweils genannten Build; V2/V2.1-Funktionen sind Alpha und nicht vollständig auf realer TV-Hardware abgenommen.


**Version:** 0.2.0-alpha1 · **Stand:** 29. Oktober 2026 · **Methode:** STRIDE-orientierte
Analyse der tatsächlich vorgesehenen Architektur · **Status:** Dokumentation belegt; Build/Lint/
JVM-Harnesse und zentrale Emulator-Pfade verifiziert, reale TV-Hardware und adversariale Tests
**NOT_TESTED** (PARTIAL_VERIFIED)

Dieses Threat Model beschreibt, wovor GeDefense TV schützt, welche Daten und Grenzen es besitzt,
welche Eingaben als feindlich zu behandeln sind und welche Risiken bewusst akzeptiert oder
ausgeschlossen werden. Es ist kein Penetration-Test-Bericht. Jede Gegenmaßnahme ist mit ihrem
Umsetzungs-/Prüfstatus versehen.

---

## 1. Systemkontext und Schutzziele

GeDefense TV ist eine **nicht privilegierte Consumer-App** auf Android TV OS / Google TV. Sie
liest öffentliche Plattformdaten, lädt öffentliche Threat-Intelligence-Feeds, bewertet lokal und
exportiert auf Wunsch einen Bericht. Sie besitzt keinen Root-Zugriff, keine System-App-Rechte,
keine Device-Owner-Rolle, keinen VPN-Datenpfad und keine systemweite Netzwerksicht.

Schutzziele (in Prioritätsreihenfolge):

1. **Integrität und Vertraulichkeit der lokalen Evidenz** (Manipulation erkennbar, Daten nicht
   lesbar ohne Schlüssel, kein stiller Verlust).
2. **Wahrhaftigkeit der Aussagen** (keine „sauber“-Behauptung bei eingeschränkter Sichtbarkeit).
3. **Verfügbarkeit der Kernfunktion** (auch bei fehlenden Permissions, offline, nach Doze/Neustart).
4. **Datenminimierung und lokale Verarbeitung** (keine Telemetrie, kein stiller Upload).
5. **Vertraulichkeit der Exporte** (keine Secrets, keine unnötigen Identifikatoren).
6. **Resilienz gegen feindliche Eingaben** (TI-Feeds, Paketmetadaten, Geräte-Build-Werte).
7. **Supply-Chain-Integrität** (vendored Core unverändert, keine Drittanbieter-Runtime).

Ausdrücklich **nicht** geschützt: kompromittierte Kernel/Firmware, Root-Geräte, ein Angreifer mit
ADB-/Systemrechten, physischer Zugriff mit Unlock, ein bereits eingeschleuster systemweiter
Schadprozess. Gegen diese Klassen kann eine gewöhnliche App keine belastbare Aussage treffen.

---

## 2. Assets

| ID | Asset | Sensitivität | Speicherort / Lebensdauer |
| --- | --- | --- | --- |
| A-01 | Evidenz-Ledger (Befunde, Events, Aktionsverlauf) | hoch (Sicherheitshistorie) | `noBackupFilesDir/evidence/events.v3.log`, HMAC-verschlüsselt (Emulator: 40 Einträge) |
| A-02 | Keyring-Root (256 bit) | kritisch | gewrappt in `noBackupFilesDir/evidence/keyring.v1`; Entschlüsselung nur über AndroidKeyStore-KEK `vgt.gedefense.tv.evidence.kek.v1` |
| A-03 | Domain-Subkeys (HMAC/AES/TI) | kritisch | nur im Prozessspeicher (SHA-256(root‖label)); nie persistiert |
| A-04 | Pseudonyme Geräte-ID (`tv_…`) | mittel (pseudonym, aber persistent) | Settings (`SharedPreferences "gedefense_tv"`) |
| A-05 | Geräte-/Plattformmetadaten (Modell, OEM, Build, Patch) | mittel | in-memory, Report, ggf. Evidenz |
| A-06 | Sichtbares App-Inventar (Pakete, Versionen, Signatur-Digests) | mittel-hoch | in-memory; nicht zentral übertragen |
| A-07 | TI-Feed-Cache | niedrig-mittel (öffentliche Feeds) | `filesDir/threat-intel/`, HMAC-authentifizierte Generationen |
| A-08 | Sicherheitsberichte (Text/JSON) | hoch (können Gerätezustand offenlegen) | SAF-Zielort bzw. Fallback `Downloads/GeDefenseTV` |
| A-09 | Einstellungen (Retention, TI-Autosync, lastScanAt) | niedrig | SharedPreferences |
| A-10 | App-Integrität / vertrauenswürdiger Code | kritisch | APK, vendored Core |
| A-11 | Nutzervertrauen in die Aussagen der App | kritisch (Produktkern) | UI/Report |

---

## 3. Trust Boundaries

```text
                        ┌──────────────────────────────────────────┐
   untrusted TI-Feeds   │              INTERNET (HTTPS)            │
   (payload = fremd)    └───────────────┬──────────────────────────┘
                                        │ TLS, Größen-/Zeit-/Redirect-Limits
                        ┌───────────────▼──────────────────────────┐
                        │   :app  (Sandbox, keine Sonderrechte)    │
                        │  Collector · Scan · Evidence · Report    │
                        └───┬───────────────┬──────────────────┬───┘
                            │               │                  │
        Android Platform APIs│      SAF/User │                  │ statische API
        (OEM-abhängig,  ┌───▼───────┐  ┌────▼─────┐   ┌────────▼─────────┐
        teils fremd)    │ Platform  │  │  Nutzer  │   │  vendored :core   │
                        │ (Package, │  │ (Export, │   │  (byte-identisch, │
                        │  Build)   │  │  Sharing)│   │  Fidelity-Gate)   │
                        └───────────┘  └──────────┘   └───────────────────┘
                            │
                ┌───────────▼──────────────────────────────┐
                │ andere Apps: Labels, Installer-Angaben,  │
                │ Signatur-Digests (nur sichtbarer Teil)   │
                └──────────────────────────────────────────┘
```

| Grenze | Was sie trennt | Vertrauensannahme |
| --- | --- | --- |
| B-01 App ↔ Internet | TI-Feed-Abrufe | Netzwerk und Feed-Inhalt sind **untrusted**; TLS schützt Transport, nicht Inhalt |
| B-02 App ↔ Android-APIs | Build, PackageManager, Connectivity, Keystore | Plattform-API ist vertrauenswürdig im Sinne von „liefert Werte“, aber OEM-modifiziert und teils unvollständig; Werte sind **keine** Integritätsbescheinigungen |
| B-03 App ↔ andere Apps | sichtbare Paketmetadaten | Metadaten sind durch die fremde App beeinflussbar (Labels, Installer-Angaben) – untrusted |
| B-04 App ↔ Nutzer/SAF | Report-Export, Löschen, Einstellungen | Nutzer wählt Zielort; Fallback schreibt in öffentliches `Downloads/GeDefenseTV`; ein geteilter/gefundener Report verlässt den Schutzbereich |
| B-05 App ↔ vendored Core | gemeinsame Logik | Core gilt als auditiert, aber nur solange byte-identisch (Manifest-Prüfung) |
| B-06 Build ↔ Runtime | Gradle, Repositories, Wrapper | Supply-Chain; keine Runtime-Drittdeps reduziert die Angriffsfläche |
| B-07 App ↔ Keystore | Schlüsselhohheit | Hardware-Backing darf nicht angenommen werden; Keystore kann fehlen/blockieren |

---

## 4. Untrusted Inputs

| ID | Eingabe | Angreifer-/Fehlerquelle | Erwartete Gegenmaßnahme | Status |
| --- | --- | --- | --- | --- |
| I-01 | TI-Feed-Payload (Plain/JSONL/IPsum) | Feed-Betreiber, MITM ausgeschlossen durch TLS, aber Feed-Inhalt frei | Größen-/Zeilenlimits, Formatvalidierung, Verwerfen statt Raten (`ThreatIntelParser`), begrenzte Einträge, Stale-Budget | Core-Parser + `TvFeedDownloader` vorhanden; Laufzeit **NOT_TESTED** |
| I-02 | HTTP-Antwort-Metadaten (Redirects, Content-Length, Content-Type, HTML) | feindlicher/fehlerhafter Server | HTTPS-only, max. 2 Redirects same-host, Streaming-Größenlimit, HTML-Refusal, Timeouts | implementiert; Laufzeit **NOT_TESTED** |
| I-03 | Paketmetadaten sichtbarer Apps (Label, Version, Installer, Signatur-Digest) | fremde Apps | Signatur-Digests als Hash; Installer-Angaben nur als Review-Heuristik; kein Vertrauen aus Label/Name | Emulator-belegt (sichtbares Inventar, `PARTIAL`) – adversarial **NOT_TESTED** |
| I-04 | Build-/Gerätewerte (`Build.*`, Security-Patch-String) | OEM-Firmware | tri-state (`Observed`), Plausibilitätsprüfung, `UNKNOWN` statt Default; Patch-Alter ≠ Verwundbarkeit | Emulator-belegt (Patch 2026-04-01 → „veraltet“ ohne Verwundbarkeitsclaim) |
| I-05 | Soft-Keyboard-/Key-Events | Nutzer, ggf. fehlerhafte Remote | Screen-Vertrag: `onKeyEvent`/`handleBack` konsumieren definiert; keine Touch-Abhängigkeit | Emulator-belegt (D-Pad-Traversal); reale TV-Remote **NOT_TESTED** |
| I-06 | SAF-Ziel-URI / Export-Fallback | Nutzer/fehlerhafter Provider bzw. fehlender TV-Picker | SAF nur über gelieferten URI; Fallback erkennt Stub und schreibt permission-frei nach MediaStore/App-Dokumente; Fehler → ehrlicher `ExportResult(ok=false)` | Emulator-belegt (30.246 B/4.562 B); Retest nach Redesign offen |
| I-07 | Exported Report (geteilt/gefunden) | Empfänger | Inhalt minimiert (keine Secrets/Tokens, keine rohen Paketlisten im JSON); Fallback-Dateien im öffentlichen Downloads-Ordner | stichprobenartig geprüft; **PARTIAL** |
| I-08 | JobService-Start (System) | System-Scheduler | `exported=true` nur mit `BIND_JOB_SERVICE`-Permission; keine Nutzdaten aus Intents | Manifest statisch geprüft – **PASS (statisch)** |
| I-09 | Evidenzdatei-Manipulation (anderer Prozess/Backup/Root) | lokaler Angreifer | HMAC-Kette + AES-GCM; `verify()` erkennt Manipulation; fail-closed; Alt-Ledger wird archiviert | Emulator: Ledger gesund (40 Einträge); Tamper-Test **NOT_TESTED** |
| I-10 | Zeit/Clock-Skew | Nutzer/Firmware | Patch-Zukunft > 7 Tage → `UNKNOWN`; TI-Clock-Skew 10 min | Core-Regeln vorhanden; **NOT_TESTED** |

---

## 5. STRIDE-Analyse

Bewertung: **H** = hoch, **M** = mittel, **L** = niedrig (relativ zur nicht privilegierten
TV-App). „Mitigation“ bezieht sich auf den vorgesehenen Mechanismus; Status sagt, ob er real
verifiziert ist.

| ID | STRIDE | Szenario | Wirkung | Mitigation | Status |
| --- | --- | --- | --- | --- | --- |
| T-01 | Spoofing | Gefälschte/kompromittierte Feed-Quelle liefert falsche IOCs | falsche Findings/Reputation | TLS-Only, Redirect-Limit, keine Signatur→Restrisiko; Quelle/Alter sichtbar, keine Auto-Blockierung | **NOT_TESTED**; Feed-Signatur fehlt (Gap) |
| T-02 | Spoofing | Fremde App gibt sich als Store-Installation aus (Installer-Angabe) | falsches „vertrauenswürdig“ | Installer nur Review-Heuristik; Signatur-Digest + sichtbare Quelle; keine Vertrauensaussage | Design; **NOT_TESTED** |
| T-03 | Tampering | Evidenz-Ledger wird lokal verändert/gelöscht | Vertrauensverlust in Historie | HMAC-Kette + AES-GCM + `verify()`; Löschung durch Nutzer ist legitim und sichtbar; Alt-Ledger wird archiviert statt still verworfen | Emulator: gesundes Ledger (40 Einträge); Tamper-Test **NOT_TESTED** |
| T-04 | Tampering | Vendored Core wird in-place gepatcht | manipulierte Logik unter „auditiertem“ Anschein | Byte-Fidelity-Manifest + Script als Release-Gate | **PASS** (29.10.2026, 26/26 Dateien, Exitcode 0) |
| T-05 | Tampering | Release-APK mit falschem/fehlendem Schlüssel gebaut | Update-/Vertrauensbruch | vorgesehene Release-Signatur über Env-Variablen; **Fallback auf Debug-Keystore ist ein offener offener Punkt für die Produktion** | **FAIL für Produktion** – Release-APK existiert, ist aber debug-signiert (F-01) |
| T-06 | Repudiation | Nutzer/Support kann Befundherkunft nicht nachvollziehen | Vertrauensverlust | `EvidenceRef` (Quelle, Zeit, Digest), `ruleId`, Report mit Scope | Design; **NOT_TESTED** |
| T-07 | Information Disclosure | Report/Backup/Logs leaken Gerätezustand oder Secrets | Datenschutzverletzung | `allowBackup=false`, keine Debug-Logs mit Secrets, Report ohne Tokens/rohe Paketlisten | Statisch: `allowBackup=false` **PASS**; Runtime **NOT_TESTED** |
| T-08 | Information Disclosure | Export landet an unerwartetem Ort/Cloud-Sync | Verbreitung des Reports | SAF-Nutzerentscheidung, minimierter Inhalt, Report als „sicherheitsrelevant“ gekennzeichnet; bei TV-ohne-Picker permission-freier Fallback in `Downloads/GeDefenseTV` | Emulator-Beleg; Restrisiko dokumentiert (Datei bleibt außerhalb App-Verwaltung) |
| T-09 | Denial of Service | Feindlicher/riesiger Feed blockiert App oder füllt Speicher | App unbrauchbar | Größen-/Eintragslimits, Streaming, Timeouts, max. 3 Parallel-Downloads, Cache-Generationen max. 2 | Core/Plan; **NOT_TESTED** |
| T-10 | Denial of Service | Keystore-Provider blockiert/hängt | Prozess hängt, UI friert ein | `BoundedSecretKeyCrypto` (Admission-Lock, Timeout, Circuit), `UnavailableEvidenceStore` fail-closed | Core + `AndroidKeystoreGate` vorhanden; Laufzeit **NOT_TESTED** |
| T-11 | Denial of Service | Doze/Background-Stopp bricht Scan/Sync | unvollständige Daten | kein Dauerbetrieb; nutzerinitiierter Scan, Job-basierter TI-Sync; ehrlicher Zustand | Force-Stop/Neustart-Summary **belegt**; Doze/Reboot **NOT_TESTED** |
| T-12 | Elevation of Privilege | Fehlerhafte exported Components erlauben fremden Aufruf | unautorisierte Aktionen | nur Launcher-Activity exported, Service mit `BIND_JOB_SERVICE`, keine Provider/Receiver | Statisch **PASS**; künftige Änderungen prüfen |
| T-13 | Elevation of Privilege | Symlink/Path-Traversal beim Schreiben von Cache/Evidenz | Überschreiben fremder Dateien | `SecureFiles`/`DurableAtomicFiles`-Muster, keine externen Pfade, private Verzeichnisse | Core-Helfer vorhanden; App-Nutzung **NOT_TESTED** |
| T-14 | Elevation of Privilege | Malformed Feed-Inhalt triggert Parser-Schwachstelle | Code-Ausführung/Absturz | bounded Parser, keine Deserialisierung beliebiger Objekte, JSONL-Zeilenlimit | **NOT_TESTED** (kein Fuzz-Test) |
| T-15 | Spoofing/Integrität | OEM meldet falsches/altes Patch-Datum | falsche Aktualitätsbewertung | `UNKNOWN` bei unplausibel; Patch-Alter nur als „alt“, nicht „verwundbar“ | Emulator-belegt (Patch 2026-04-01 → „veraltet“, keine Verwundbarkeitsaussage); reale OEM-Werte **NOT_TESTED** |
| T-16 | Repudiation | Evidenz-Record ohne Kontext (welcher Collector, welche Sichtbarkeit) | nicht interpretierbar | Event-Schema mit `collector_id`, `data_quality`, `visibility` | Modell vorhanden; Event-Persistenz z. T. offen |
| T-17 | Information Disclosure | TI-Downloads offenbaren Geräte-IP an Feed-Anbieter | Metadatenleck | direkte HTTPS-Abrufe ohne Proxy; kein Upload von Gerätedaten; IP sieht der Anbieter technisch immer | Design; accepted residual risk |
| T-18 | Tampering | Manipulierte Settings (Retention/Autosync) | Daten bleiben länger / mehr Sync | Settings lokal; keine Sicherheitsdurchsetzung davon abhängig | akzeptiert (niedrig) |

### Kettenrisiken (Kurzform)

| Chain | Kette | Wirkung | Breakpoint |
| --- | --- | --- | --- |
| C-01 | kompromittierter Feed (T-01) → falsches Finding → Nutzer verlässt sich darauf → Fehlentscheidung | Vertrauensschaden | Quelle/Alter/Confidence sichtbar; keine Auto-Blockierung; Scoring-Regeln gegen Einzelsignal-Kritikalität |
| C-02 | Keystore blockiert (T-10) → Evidenz nicht schreibbar → App behauptet trotzdem „gesund“ | Integritätslüge | `UnavailableEvidenceStore` fail-closed, `EvidenceHealth(healthy=false, reason=…)` |
| C-03 | Package-Visibility eingeschränkt → Inventar unvollständig → „keine unbekannten Apps“ suggeriert Sauberkeit | falsches Sicherheitsgefühl | `PARTIAL`/`coverage.total=null`, UI-/Report-Pflicht zur Kennzeichnung, Scoring-Kappung |
| C-04 | Evidenzdatei manipuliert (T-03) → Report übernimmt manipulierte Findings | Vertrauensverlust | HMAC-Verify vor Nutzung; bei Fehler „Evidenz kompromittiert/nicht verfügbar“ statt stiller Fortsetzung |

---

## 6. TV-spezifische Risiken

| ID | Risiko | Beschreibung | Gegenmaßnahme | Restrisiko |
| --- | --- | --- | --- | --- |
| TV-01 | **OEM-Fragmentierung** | Gleiche Android-Hauptversion kann je Hersteller andere APIs, Berechtigungen, Hintergrundregeln und Patch-Politik haben. | Capability-first (`CapabilityState`, tri-state `Observed`) statt Versionsnummer allein; reale Geräte als Release-Gate; `UNKNOWN` erlaubt. | Nicht messbar ohne Gerätematrix; Aussagen gelten nur für geprüfte Profile. |
| TV-02 | **Package Visibility** | Ab API 30 sieht die App nur über `<queries>` erreichbare Pakete (plus sich selbst/Aufrufer). Kein vollständiges Inventar. | Gezielte `<queries>` (LEANBACK_LAUNCHER, LAUNCHER, https-VIEW); `packageVisibilityRestricted`; `observed` ohne `total`; UI-Kennzeichnung. | Vollständigkeit bleibt unmöglich; „unbekannte App“ kann unentdeckt bleiben. |
| TV-03 | **Sideloading / unbekannte Installer** | TV-Geräte erlauben oft Installation aus unbekannten Quellen; Installer-Angaben sind fälschbar. | Sichtbare Nicht-Store-Installer als Review-Signal, Signatur-Digests, keine automatische Malware-Klassifikation. | Falsch-positive/-negative Bewertung möglich; Nutzerentscheidung nötig. |
| TV-04 | **ADB-/Debugging aktiv** | Entwickleroptionen/ADB-Zugriff erweitern Angriffsfläche erheblich. | Hardening-Collector erkennt, was über öffentliche APIs lesbar ist; nicht Lesbares bleibt `Observed.unreadable`; Empfehlung an Nutzer, keine Automatik. | ADB-Zustand ist als normaler App nicht zuverlässig abfragbar → `PARTIAL`/`UNKNOWN`. |
| TV-05 | **Kein privilegierter Sensor** | Keine systemweiten Flows, Ports, Socket-/Prozesszuordnung, PPS-/SYN-/UDP-Raten, keine Flood-Erkennung. | Produkt- und UI-Sprache behauptet diese Fähigkeiten nicht; Datenblatt §7 als verbindliche Grenze. | Ein echter Inbound-Flood/systemweite Kompromittierung bleibt unsichtbar. |
| TV-06 | **10-Fuß-UX / Remote-only** | Kleine Schrift, versteckter Fokus, Hover-/Touch-Abhängigkeit oder Fallen im Back-Stack machen die App unbedienbar. | D-Pad-Verträge, sichtbarer 4-dp-Gold-Fokusring, 10-Fuß-Typo (15–92 sp), Overscan 48 dp, `handleBack`-Hierarchie, keine Hover-Pfade. | Emulator: D-Pad-vollständig, keine Touch-Abhängigkeit (Screenshots); reale TV-/OEM-Remote **NOT_TESTED**. |
| TV-07 | **Streaming-/DRM-Sensibilität** | Kein Eingriff in Wiedergabe/Netzwerk; keine VPN-/TUN-Nutzung in V1. | Kein VPN, kein MITM, keine Netzwerkmanipulation; nur lesende Metadaten. | Keine (bewusst außerhalb des Designs). |
| TV-08 | **Doze/Background-Limits** | Hintergrundjobs können verzögert/gestoppt werden. | Keine Dauerüberwachung versprechen; nutzerinitiierter Scan, Job-basierter TI-Sync, sichtbarer letzter Lauf/Stale-Status. | Kein „kontinuierlich überwacht“-Versprechen möglich. |
| TV-09 | **Gemeinsame Gerätenutzung** | Mehrere Haushaltsmitglieder, keine Nutzertrennung. | Lokale Datenminimierung, keine personenbezogenen Profile, pseudonyme Geräte-ID. | Report/Export kann Gerätezustand offenlegen, wenn geteilt. |
| TV-10 | **Firmware-/Hersteller-Fernzugriff** | Hersteller-/OEM-Dienste können Geräteverhalten beeinflussen. | Keine Gegenmaßnahme möglich ohne Privilegien; ehrlich als nicht prüfbar ausweisen. | Akzeptiert; außerhalb des Produktanspruchs. |

---

## 7. Nicht-Ziele und Missbrauchsgrenzen

GeDefense TV ist **kein**:

- Ersatz für ein EDR/XDR mit privilegiertem Sensor, kein Antivirus mit Cloud-Analyse,
- Netzwerk-Firewall, Router-Härtung oder Network-Sentinel,
- Flood-/DDoS-Schutz, IDS/IPS oder Paketinspektor,
- Parental-Control-/Kindersicherungs- oder Nutzungscontrolling-Produkt,
- Attestierungs- oder Firmware-Integritätsnachweis,
- Überwachungs-/Spionagewerkzeug (keine Audio-/Video-/Bildschirmaufzeichnung, keine
  Standort-/Kontakt-/Nachrichtenzugriffe, keine versteckten Kanäle).

Missbrauch, der bewusst nicht unterstützt wird: stilles Deaktivieren von Sicherheitsfunktionen
des Geräts, Auslesen fremder App-Daten, Umgehen von Berechtigungen, „Reparatur“ ohne
Nutzerbestätigung, zentrale Sammlung von Geräte-/Nutzungsdaten.

Bewusste Grenze gegen Selbstüberschätzung: Eine gewöhnliche TV-App kann die Abwesenheit von
Schadsoftware **nicht** beweisen. Jede „grün“-Darstellung setzt `DataVisibility.FULL` und
`supported`-Collectoren voraus; die UI muss Einschränkungen sichtbar machen.

---

## 8. Restrisiken (akzeptiert oder offen)

| Risiko | Einstufung | Begründung / offener Punkt |
| --- | --- | --- |
| Öffentliche Feeds ohne Signatur (T-01) | mittel | TLS + Sichtbarkeit von Quelle/Alter/Confidence; kryptografische Feed-Signaturen fehlen (Gap, VGT-Sicherheitsprofil). |
| Release-Signatur-Fallback auf Debug-Keystore (T-05) | **hoch (offener Punkt für die Produktion)** | Release-APK ist debug-signiert; erst mit `GEDEFENSE_RELEASE_*` korrekt. |
| Retention nicht automatisch (Daten bleiben bis `clear()`) | niedrig-mittel | **V2**; nicht als wirksame Löschautomatik darstellen. |
| Keine Fuzz-/Negativtests der Parser | mittel | Bounded Parser vorhanden, nicht adversarial getestet (**NOT_TESTED**). |
| Keine reale Geräte-/OEM-Verifikation | hoch für Produktion | Capability-Modell ehrlich, aber reale TV-Aussagen fehlen. |
| Kein unabhängiges Security-Review | hoch für Produktion | Lint/Build/Emulator ersetzen kein Security-Audit. |
| Export-Fallback in öffentlichem Downloads-Ordner | niedrig-mittel | Nutzer-initiert, minimierter Inhalt; Datei bleibt außerhalb App-Verwaltung. |
| Keystore-Hardware-Backing unbestimmt | mittel | Keyring ist Keystore-gewrappt; StrongBox nur versucht, Hardware-Backing wird nicht behauptet. |
| Kein Schutz gegen Root/Firmware-Kompromittierung | inhärent | Außerhalb des Produktanspruchs; wird nicht als Fähigkeit verkauft. |

---

# V2-Erweiterung (On-Device-Loopback-VPN, Traffic-Map, XDR-Light)

**Status dieses Abschnitts:** Planungsstand 29.10.2026 · **Evidenz: NOT_TESTED** (V2-
Implementierung in Arbeit; keine V2-Läufe/Screenshots). Quelle: [docs/V2-ARCHITECTURE.md](docs/V2-ARCHITECTURE.md),
`V2Contracts.kt`, `model/{Traffic,Vpn}.kt`, Mobile-Referenzdossier.

Mit V2 erhält die App erstmals einen **eigenen lokalen Netzwerk-Datenpfad** (TUN + GaiaNet-Helper).
Damit entstehen neue Assets, Grenzen und Angriffsflächen, die ohne aktive V2-Implementierung
ehrlich als Risiko dokumentiert und **nicht** als geschützt behauptet werden.

## 9. V2-Assets (zusätzlich zu A-01…A-11)

| ID | Asset | Sensitivität | Speicherort / Lebensdauer |
| --- | --- | --- | --- |
| A-12 | TUN-Schnittstelle / lokaler Datenpfad | hoch (Verfügbarkeit, Vertraulichkeit) | Laufzeit, FGS; Fail-Closed-Anker |
| A-13 | GaiaNet-Helper-Binary (`libgedefense_gaianet_v2.so`) | kritisch (Code-Ausführung) | `nativeLibraryDir`, byte-identisch aus Mobile 0.28.0-beta1 |
| A-14 | Policy-/Regelbestand (Privacy/Threat-Indizes, Kategorien) | hoch (Filterwirkung) | App-Assets/Cache; Integrität derzeit nicht signiert |
| A-15 | Traffic-Metadaten (App, Ziel-IP, Land, Domain, Bytes, Zeiten, Aktion) | hoch (Nutzungsverhalten) | lokal (Snapshot/Historie, begrenzt); kein Upload |
| A-16 | Verkehrs-Telemetrie-Pipe (Helper→App) | hoch (Integrität/Verfügbarkeit) | Laufzeit; begrenzte Frames 2…1024 B |
| A-17 | Geo-Zuordnung/Herkunftsland | mittel | lokales Offline-Asset; keine GPS-/Standortdaten |

## 10. V2-Trust-Boundaries

| Grenze | Verlauf | Vertrauensannahme / Risiko |
| --- | --- | --- |
| V2-B-01 App ↔ TUN | eigene TUN-Schnittstelle, Full-Flow-Direktmodus | Nur ein VPN-Owner; bei Ausfall kein stiller Bypass (Fail-Closed-Anker) |
| V2-B-02 App ↔ Helper-Prozess | Kindprozess, privater Control-Socket + Token + `SCM_RIGHTS` | Helper kompromittiert = Datenpfad kompromittiert; Exec nur aus `nativeLibraryDir` |
| V2-B-03 Helper ↔ Telemetrie-Pipe | begrenzte Frames | Fehlerhafte/feindliche Frames dürfen App nicht crashen oder Speicher füllen |
| V2-B-04 App ↔ Netzwerk | direkter Egress, **kein** externer VPN-Server | Keine VGT-/Drittanbieter-Zentrale; TLS-Inhalte bleiben unlesbar |
| V2-B-05 Policy ↔ Datenpfad | lokale Regeln/Indizes | Policy-Fehler → konservative Aktion (Block/Correlate), kein stiller Allow |
| V2-B-06 Traffic-Metadaten ↔ UI/Export | lokale Aggregation | Kein Upload; Export nur Nutzeraktion, begrenzte Felder |
| V2-B-07 Native-Binary ↔ Build | vendorte `.so` aus Mobile-Dossier | Nur byte-identische, gehashte Binaries; Abweichung = offener Punkt |

## 11. V2-Untrusted-Inputs

| ID | Eingabe | Quelle | Gegenmaßnahme | Status |
| --- | --- | --- | --- | --- |
| I-11 | TUN-Pakete (IPv4/IPv6, fragmentiert/malformed) | beliebige Apps auf dem Gerät | Parser im Helper (Go, bounded), Fragment-/Größenlimits, Fuzzing geplant | **NOT_TESTED** |
| I-12 | Control-Socket-Nachrichten | lokaler Angreifer/fehlerhafter Helper | privater Socket, Token-Handshake, striktes Framing, keine Shell-Kommandos | **NOT_TESTED** |
| I-13 | Telemetrie-Frames | Helper/Fehlerzustand | Frame-Längen 2…1024 B, Validierung, Unbekanntes verwerfen, Caps | **NOT_TESTED** |
| I-14 | Policy-/Geo-Assets | Build/Cache | Integritätsprüfung geplant; derzeit keine Signatur dokumentiert | **GAP** |
| I-15 | VPN-Consent-/System-Intents | System/Nutzer | nur `BIND_VPN_SERVICE`-geschützter Service, kein fremder Export außer Systembindung | statisch vorbereitet |
| I-16 | DNS-Antworten/Klassifizierung | Netzwerk | nur Metadaten; keine Payload-Auswertung, keine DNS-Manipulation im Klartext | **NOT_TESTED** |

## 12. V2-STRIDE-Ergänzungen

| ID | STRIDE | Szenario | Wirkung | Mitigation | Status |
| --- | --- | --- | --- | --- | --- |
| T-19 | Spoofing | Fremde App/Prozess bindet an VPN-Service oder gibt sich als Helper aus | Übernahme des Datenpfads | Service-Permission `BIND_VPN_SERVICE`; Helper nur aus `nativeLibraryDir`; Token-Handshake | **NOT_TESTED** |
| T-20 | Tampering | Helper-Binary/`.so` im Build oder auf Platte manipuliert | Code-Ausführung, Filterumgehung | Byte-Identität + SHA-256 zum Mobile-Original (verifiziert), Legacy-Packaging, Release-Gate | **teilweise belegt (Hash)**, Laufzeit-Self-Check **NOT_TESTED** |
| T-21 | Tampering | Policy-/Geo-Dateien manipuliert | falsche Blocks/Allow | Integritätsprüfung geplant; derzeit **keine Signatur** | **GAP** |
| T-22 | Tampering | Telemetrie-Frames manipuliert (lokal) | falsche Traffic-/XDR-Anzeige | begrenzte Frames, Plausibilitätsprüfung, HMAC-Evidenz für Findings geplant | **NOT_TESTED** |
| T-23 | Information Disclosure | DNS-Namen/Traffic-Metadaten landen in Logs/Crash-Reports | Nutzungsprofil-Leak | keine Payload-/DNS-Logs, Redaktion; Logcat-Prüfung im Testplan | **NOT_TESTED** |
| T-24 | Information Disclosure | Traffic-Metadaten werden exportiert/hochgeladen | Verlust der Privatsphäre | kein Upload; Export nur Nutzeraktion, begrenzte Felder; Data-Safety-Aussage | Design |
| T-25 | Denial of Service | Helper-Crash/Endlosschleife/Telemetrie-Flut | TV ohne Netzwerk/UI blockiert | Fail-Closed-Anker, Bounded Frames, Watchdog/Recovery, FGS | **NOT_TESTED** |
| T-26 | Denial of Service | VPN blockiert Streaming/Updates/DRM | Nutzer erlebt „Internet kaputt“ | Profile/Allowlists, Aus/Notfall-Aus, ehrliche Degraded-Anzeige | **NOT_TESTED** |
| T-27 | Elevation of Privilege | Helper/Socket erlaubt Befehlsausführung | Root-/Systemnähe | kein Root, kein Shell-Spawn, festes Protokoll, keine dynamischen Kommandos | **NOT_TESTED** |
| T-28 | Elevation of Privilege | Symlink/Path-Traversal beim Helper-Start/Asset-Laden | Fremddatei-Ausführung | Exec aus `nativeLibraryDir`, feste Pfade, kein Nutzerpfad | **NOT_TESTED** |
| T-29 | Spoofing/Integrität | Always-On/Lockdown umgangen, Verkehr ungefiltert | falsches Schutzgefühl | Always-On-Metadaten, Fail-Closed, ehrlicher Status | **NOT_TESTED** |
| T-30 | Repudiation | Block/Allow nicht nachvollziehbar | Vertrauensverlust | `TrafficFlow`-Aktion + Regel/Quelle/Zeit; Evidenz-Andockung geplant | **NOT_TESTED** |

**V2-Kettenrisiken:**

| Chain | Kette | Wirkung | Breakpoint |
| --- | --- | --- | --- |
| C-05 | Helper kompromittiert (T-20/T-27) → Datenpfad manipuliert → Traffic-Map/XDR zeigen Falsches → Nutzer vertraut falschem „geschützt“ | Vertrauensverlust | Hash-/Binary-Provenienz, Fail-Closed, ehrliche Degraded-Anzeige, kein „geschützt“ ohne ACTIVE |
| C-06 | Policy-Datei manipuliert (T-21) → Tracker/C2 nicht blockiert oder legitime Dienste blockiert | Fehlschutz/Fehlblock | Integritätsprüfung (offen), konservative Defaults, sichtbare Aktionen |
| C-07 | Telemetrie-Frame-Fehler (T-22/T-25) → UI zeigt falsche Länder/Apps → Fehlentscheidung | Fehlbewertung | Frame-Validierung, Caps, Evidenz, keine Einzelmerkmals-Kritikalität |
| C-08 | DNS-Metadaten im Log (T-23) → Nutzungsprofil entsteht | Datenschutzverletzung | Log-Redaktion, keine Roh-DNS-Ausgabe, Testplan-Prüfung |

## 13. V2-spezifische TV-Risiken

| ID | Risiko | Beschreibung | Gegenmaßnahme | Restrisiko |
| --- | --- | --- | --- | --- |
| TV-11 | **VPN-Konflikt** | Android erlaubt nur einen aktiven VPN-Dienst; eine andere VPN-App kann verdrängt werden bzw. V2 kann nicht starten. | Consent/Status ehrlich, `UNSUPPORTED`/`FAILED`, Erklärung im Onboarding | Kein paralleler Betrieb möglich; Nutzerentscheidung |
| TV-12 | **Streaming/DRM-Bruch** | Filter/Profile können Streaming, Updates oder DRM-Prüfungen blockieren. | Default `BALANCED`, Allowlists, Aus/Notfall-Aus, Fehlblock-Meldung | Fehlblockungen möglich; Tests auf realen Geräten **NOT_TESTED** |
| TV-13 | **Always-On/Recovery** | Nach Neustart/Absturz kann Verkehr ungefiltert sein, wenn Always-On/Recovery fehlschlägt. | `SUPPORTS_ALWAYS_ON`, Fail-Closed-Anker, Recovery, ehrlicher Zustand | OEM-Verhalten **NOT_TESTED** |
| TV-14 | **Batterie/Thermik** | Dauerhafter FGS + Paketverarbeitung können TV-SoC belasten. | Bounded Telemetrie, kein Polling, FGS nur bei aktivem Schutz | Messung **NOT_TESTED** |
| TV-15 | **Geo-/CDN-Fehlinterpretation** | Traffic-Map zeigt Länder, die wegen CDN/Anycast nicht den Dienststandort widerspiegeln. | UI erklärt Grenzen; keine Angriffsbehauptung aus Land | Fehlinterpretation durch Nutzer möglich |
| TV-16 | **Verschlüsseltes DNS** | DoT/DoH in Apps verhindert DNS-Sichtbarkeit; „keine Tracker“ wäre falsch. | Ehrliche Anzeige „Domain nicht sichtbar“, nur IP/Land | Keine vollständige DNS-Sicht möglich |

## 14. V2-Nicht-Ziele und Missbrauchsgrenzen

- Kein externer VPN-Server, kein WireGuard-Egress, keine FritzBox-/Router-Integration.
- Keine TLS-Interception, keine Inhalts-/Payload-Auswertung, keine Werbe-ID/Standortnutzung.
- Kein Kernel-/Prozess-EDR, keine Root-/System-App-Rechte.
- Keine „100 % Schutz“-Behauptung; ohne `ACTIVE`/`DEGRADED` kein „geschützt“.
- Kein stiller Bypass bei Helper-/Policy-Ausfall (Fail-Closed statt Fail-Open).

## 15. V2-Restrestrisiken

| Risiko | Einstufung | Begründung / offener Punkt |
| --- | --- | --- |
| V2-Implementierung ungetestet | **hoch** | Keine V2-Laufzeittests, keine Screenshots, keine Emulator-Evidenz (**NOT_TESTED**). |
| Helper-Binary-Provenienz | mittel | Byte-Identität + SHA-256 zum Mobile-Original verifiziert; Laufzeit-Self-Check/Verifikationsprotokoll offen. |
| Policy-Integrität unsigniert | mittel-hoch | Manipulierte Policy könnte Filterwirkung ändern; Signatur/Integritätsprüfung offen. |
| Fail-Closed/Recovery auf realen TVs | **hoch** | Nur Design; OEM-/Always-On-Verhalten unbekannt. |
| Streamings-/DRM-Kompatibilität | mittel-hoch | Fehlblockungen wahrscheinlich; reale Tests fehlen. |
| Traffic-Metadaten-Retention | mittel | Persistenzdauer/-löschung noch nicht final; Datenschutztext muss folgen. |
| Akku-/Thermik-Last | mittel | Keine Messung auf TV-Hardware. |
| Play-/FGS-Policy (`specialUse`) | mittel | Deklaration/Prüfung vor Veröffentlichung offen. |
