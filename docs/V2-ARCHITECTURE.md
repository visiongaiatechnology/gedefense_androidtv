# GeDefense TV V2 — Architektur: On-Device-Loopback-VPN, Traffic-Map, XDR-Light, Onboarding

> **Release-Tree 0.2.0-alpha1:** Dieses Dokument ist für den Quellstand `0.2.0-alpha1` (VersionCode 2) kuratiert. Evidenzangaben mit Datum 29.10.2026 beziehen sich auf den jeweils genannten Build; V2/V2.1-Funktionen sind Alpha und nicht vollständig auf realer TV-Hardware abgenommen.


**Version:** 2.0-plan · **Stand:** 29.10.2026 · **Dokumentstatus:** Architektur/Plan
(Architektur-Entwurf erweitert) · **Implementierungsstand:** Verträge/Modelle/Manifest/Build und ein
Großteil der Klassen (VPN/Traffic/XDR/V2-Screens) sind angelegt; **Compile-, Laufzeit- und
Emulator-Evidenz fehlen** · **Evidenzstatus: NOT_TESTED**

> **Ehrlichkeit:** Dieses Dokument beschreibt die geplante V2-Architektur auf Basis des
> Architektur-Entwurfs, der Verträge (`app/.../contract/V2Contracts.kt`), der Modelle
> (`tv-core/.../model/{Traffic,Vpn}.kt`), des geänderten Manifest-/Build-Setups und des
> Mobile-Referenzdossiers. Es werden **keine** V2-Testergebnisse, Screenshots oder Messwerte
> behauptet. Sobald der Projektteam den V2-Endledger liefert, werden Status und Evidenz nachgetragen.

---

## 1. Zielbild und Abgrenzung

GeDefense TV wandelt sich in V2 vom reinen Diagnose-Tool zum **aktiven, rein lokalen Schutz** auf
dem Fernseher:

- **Loopback-VPN ohne externen Server:** `VpnService` + TUN + vendortes GaiaNet-Datenplan-Modul
  filtern ausgehenden DNS-/Verbindungsverkehr lokal (Smart-TV-Telemetrie, ACR-/Werbenetzwerke,
  bekannte C2-Indikatoren). Kein Root, keine Cloud, kein externer Gateway.
- **Traffic-Map:** lokale Aggregation pro App/Land/Domain (Bytes, Flows, blockiert/korreliert) mit
  Visualisierung auf einer importierten statischen Weltkarte.
- **XDR-Light (TV-adaptiert):** Korrelation lokaler Ereignisse mit erklärbaren Scores; kein
  privilegiertes EDR.
- **Onboarding:** Erststart-Assistent mit Begrüßung durch Sir Quacksec, Erklärung, VPN-Consent,
  TI-Sync, erster Prüfung und Aktivierung.
- **Feedback:** Sir-Quacksec-Willkommensanimation (überspringbar) und TI-Sync-Popup mit
  Fortschritt.

### Im Scope (V2.0)

| Bereich | Umfang |
| --- | --- |
| Loopback-VPN | Start/Stop/Consent, Auto-Start, Always-On-Unterstützung, Fail-Closed, Recovery |
| Datenplan | TUN-Routing, DNS-/Flow-Evaluierung, Threat-/Privacy-Policy, Telemetrie-Pipe |
| Traffic | Flows/Apps/Länder/Domains, begrenzte Historie, Traffic-Map, Herkunftsland ohne GPS |
| XDR-Light | Korrelation, Dedupe, erklärbare Findings, Evidenz-Andockung |
| UI/UX | Schutz-Dashboard, Traffic-Ansicht, XDR-Ansicht, Onboarding, Sir Quacksec, TI-Modal |
| Plattform | FGS-Typ, Benachrichtigung, `VpnService`, `BIND_VPN_SERVICE`, Always-On |

### Ausdrücklich nicht im Scope (V2.0)

- Kein externer VPN-Server, kein WireGuard-Egress, keine FritzBox-/Router-/Network-Sentinel-
  Integration (bleibt separate Produktlinie).
- Keine TLS-Interception/kein MITM, keine Inhalts-/Payload-Auswertung, keine Entschlüsselung von
  QUIC/TLS 1.3.
- Kein Kernel-/Prozess-EDR, keine System-App-/Root-Rechte, kein vollständiger Flow-Beweis bei
  deaktiviertem VPN.
- Keine Cloud-Telemetrie, kein Upload von Traffic-Metadaten.
- Keine Zusage „100 % Schutz“ oder vollständige Abdeckung aller Apps/Protokolle.

---

## 2. Systemkontext und Trust Boundaries

```text
                          Android TV / Google TV (nicht gerootet)
 ┌───────────────────────────────────────────────────────────────────────────┐
 │ :app (Sandbox, normale Rechte)          ┌───────────────┐                │
 │  TvMainActivity / V2-UI                 │ App-Prozess   │                │
 │  TvVpnController ── Consent/Status      │ (Kotlin)      │                │
 │  TvVpnService (FGS, specialUse) ────────┤ TUN fd        │                │
 │        │  private Steuerung/Telemetrie  └──────┬────────┘                │
 │        │  (Unix-Socket/Token/Framing)          │ TUN                     │
 │  TvFlowTelemetryReader / TvTrafficStore         ▼                         │
 │  TvXdrEngine / Evidence                          ┌────────────────────┐  │
 │                                                   │ GaiaNet-Helper     │  │
 │                                                   │ (Go, Kindprozess,  │  │
 │                                                   │  nativeLibraryDir) │  │
 │                                                   │ DNS/Flow/Policy    │  │
 │                                                   └─────────┬──────────┘  │
 └─────────────────────────────────────────────────────────────┼─────────────┘
                                                               │ direct egress
                                                               ▼
                                                        Internet (Zielserver)
```

**Trust Boundaries (V2):**

| Grenze | Verlauf | Vertrauensannahme |
| --- | --- | --- |
| V2-B-01 App ↔ TUN | eigenes TUN-Interface, Full-Flow | Nur eigenes Gerät; kein zweiter VPN-Owner; Fail-Closed-Anker |
| V2-B-02 App ↔ Helper-Prozess | privater Control-Socket + Token + SCM_RIGHTS | Helper ist eigener Kindprozess; bei Ausfall kein stiller Bypass |
| V2-B-03 Helper ↔ Telemetrie-Pipe | begrenzte Frames an die App | Fremde/fehlerhafte Frames dürfen die App nicht zum Absturz bringen |
| V2-B-04 App ↔ Netzwerk | direkt (kein externer VPN-Server) | Kein VGT-/Drittanbieter-VPN-Endpunkt; ausgehender Verkehr bleibt lokal gefiltert |
| V2-B-05 Policy ↔ Kern | Privacy-/Threat-Indizes + Profil | Policy-Fehler → Block/CORRELATE statt stiller Freigabe (fail-closed) |
| V2-B-06 Traffic-Metadaten ↔ Export | lokale Aggregation, optionaler Report | Keine Roh-Payloads, keine App-Listen-Uploads; Exportinhalte begrenzt |
| V2-B-07 Native Bibliothek ↔ Build | `jniLibs`-`.so` aus Mobile-Dossier | Nur byte-identische, geprüfte Binärdateien; Hash-Nachweis vor Release |

---

## 3. Komponenten

| Komponente | Modul | Verantwortung | Status |
| --- | --- | --- | --- |
| `TvVpnService` | `:app` (`vpn/`) | `VpnService`, TUN-Establish, Full-Flow-Direktmodus, Fail-Closed-Anchor, FGS (specialUse), Always-On | Code vorhanden; **NOT_TESTED** |
| `NativeGaiaNet`/Helper-Bridge | `:app` (`vpn/`) | startet `libgedefense_gaianet_v2.so`, Token-Handshake, Control-Socket, Telemetrie-Pipe; ergänzende Klassen `BoundedAndroidCall`, `ConnectionOwnerResolver`, `PackageEgressGate`, `RuntimeFailureLog`, `TvVpnProcessState` | Code vorhanden; **NOT_TESTED** |
| `TvFlowTelemetryReader` | `:app` (`vpn/`) | liest begrenzte Telemetrie-Frames (2…1024 B/Frame), validiert, löst UID→Paket, Geo-Land, Aktion auf | Code vorhanden; **NOT_TESTED** |
| `TvTrafficStore` | `:app` (`traffic/`) | aggregiert Flows/Apps/Länder/Domains, persistiert Snapshot, implementiert `TrafficApi` | Code vorhanden; **NOT_TESTED** |
| `TvVpnController` | `:app` (`vpn/`) | Consent (`VpnService.prepare`), Start/Stop, Status, Auto-Start, Recovery | Code vorhanden; **NOT_TESTED** |
| `VpnControlApi`/`TrafficApi` | `:app` (`contract/`) | stabile UI-Verträge (`VpnStatus`, `VpnStartResult`, `TrafficSnapshot`, `TrafficFlow`, `OriginInfo`) | **Vorhanden** |
| Geo-Zuordnung | `:tv-core` (`geo/GeoLookup.kt`), `:app` (`TvTrafficStore`) | Offline-IP→Land, Herkunftsland aus Locale/Netz (kein GPS) | Code vorhanden (GeoLookup/OriginInfo); **NOT_TESTED** |
| `TvXdrEngine` | `:tv-core` (`xdr/`) | TV-Regeln (Telemetrie-Ziel, ACR-Muster, Tracker, C2, First-Seen), Score, Dedupe | Code vorhanden; **NOT_TESTED** |
| Privacy-Policy | `:app` (`vpn/TvPrivacyIntelligence`), `:tv-core` | Profile (Off/Conservativ/Balanced/Streng), Domains→Block/Annotate über Core-PrivacyIntelligence | Code vorhanden; **NOT_TESTED** |
| V2-UI | `:app::ui` | `OnboardingScreen`, `ProtectionScreen`, `TrafficScreen` (+ `TrafficWorldMapView`), `XdrScreen`, Sir Quacksec, TI-Sync-Modal | Screens/Views vorhanden; **NOT_TESTED** |
| Modelle | `:tv-core/.../model/` | `VpnStatus`/`VpnState`, `TvPrivacyProfile`, `TrafficSnapshot`, `TrafficFlow`, `AppTraffic`, `CountryTraffic`, `DomainTraffic`, `OriginInfo`, `TrafficAction` | **Vorhanden** |

Neue `TvRoute`-Ziele sind bereits definiert: `ONBOARDING`, `PROTECTION`, `TRAFFIC`, `XDR`
(neben V1-Zielen). `ScreenHost` wurde um `activity()`, `setRailVisible()`,
`showWelcomeOverlay()`, `showSyncOverlay()`/`updateSyncOverlay()`/`hideSyncOverlay()` erweitert.

---

## 4. VPN-Datenplan und Fail-Closed-Verhalten

- **TUN-Konfiguration (Architektur-Entwurf):** IPv4 `10.253.0.2/32`, IPv6 `fd7a:4744::2/128`;
  Full-Flow-Direktmodus (kein externer VPN-Server, kein WireGuard in V2.0).
- **Datenpfad:** App → TUN (`TvVpnService`) → Helper (DNS-Parser, Flow-Engine, Threat-/Privacy-
  Policy) → direkter Egress über geschützte Upstream-Sockets; Telemetrie zurück an die App.
- **Helper:** eigener Kindprozess, gestartet aus `nativeLibraryDir` (deshalb
  `jniLibs.useLegacyPackaging = true`), ohne Root, ohne externen Export.
- **Steuerung:** privater Unix-Socket + zufälliger Token-Handshake; File-Descriptors per
  `SCM_RIGHTS`, keine kopierten Paket-Payloads über die Pipe.
- **Telemetrie:** zeilen-/frame-basiert, 2…1024 Byte/Frame (Architektur-Entwurf), begrenzte Zähler und
  Listen; die App validiert jede Zeile und verwirft Unbekanntes statt zu raten.

**Zustandsmodell (`VpnState`):** `OFF`, `PREPARING`, `ACTIVE`, `DEGRADED`, `FAILED`,
`UNSUPPORTED`. `VpnStatus.isProtecting` ist **nur** bei `ACTIVE`/`DEGRADED` wahr; UI und Bericht
dürfen außerhalb dieser Zustände **niemals** „geschützt“ behaupten.

**Fail-Closed (geplant, NOT_TESTED):**

1. Consent fehlt/abgelehnt → `OFF` bzw. `UNSUPPORTED`, ehrlicher Hinweis, keine Schutzbehauptung.
2. Helper-Start/-Crash → TUN bleibt als Fail-Closed-Anchor bestehen; Zustand `DEGRADED`/`FAILED`
   mit Ursache; Recovery startet den Helper neu, ohne den Verkehr still ungefiltert freizugeben.
3. Policy-/Key-Custody-Fehler → konservative Aktion (block/correlate) statt Bypass; Zustand
   `DEGRADED`.
4. Always-On: Manifest-Metadaten `SUPPORTS_ALWAYS_ON=true`; ein TV-Neustart darf nicht still
   ungefilterten Verkehr hinterlassen. Verhalten auf echten Geräten: **NOT_TESTED**.

---

## 5. Telemetrie, Traffic-Aggregation und Grenzen

Die Modelle in `tv-core/.../model/Traffic.kt` setzen harte Obergrenzen (durch `require(...)`):

| Typ | Inhalt | Grenzen |
| --- | --- | --- |
| `TrafficFlow` | App-Owner, Ziel-IP, optional Land/Domain, Aktion, Protokoll, Bytes, Zeiten | Adresse ≤ 64 Zeichen, Protokoll 1–8, `lastSeen >= openedAt` |
| `TrafficSnapshot` | Zustand, Zähler, Apps/Länder/Domains, Transportfehler | Apps ≤ 200, Länder ≤ 64, Domains ≤ 200 |
| `AppTraffic` | tx/rx, aktive/geöffnete/blockierte/korrelierte/annotierte Flows | Top-Länder/Domains ≤ 12 |
| `CountryTraffic` | Ländercode (ISO-3166-2), Bytes, Flows, blockiert | `blockedFlows <= flows` |
| `DomainTraffic` | beobachtete Domain, Queries, blockiert | Domain ≤ 253 Zeichen |
| `OriginInfo` | Herkunftsland/-punkt, Label | Label ≤ 64, WGS84-Grenzen |

**Keine Inhalte:** Es werden keine Payloads, Bildschirminhalte, TLS-Klartexte oder
DNS-Antwortinhalte gespeichert; Domains nur, soweit sie lokal im DNS-Pfad beobachtet werden.
**Retention/Begrenzung:** Live-Snapshot + begrenzte Flow-Historie (`flows(limit=200)`); die
konkrete Persistenz-/Retention-Dauer ist Implementierungsdetail und **NOT_TESTED** (siehe
[PRIVACY.md](../PRIVACY.md) V2-Abschnitt).

---

## 6. Geo-Zuordnung und Herkunftsland

- **Ziel-Länder:** Offline-Zuordnung Ziel-IP → Land (Bibliothek/Asset im App-Build); keine
  Online-Geo-Abfragen, kein externer Dienst.
- **Herkunftsland des Geräts:** aus System-Locale/Netzwerk-Metadaten (kein GPS, keine
  Standortberechtigung); optional manuell korrigierbar (UI-Detail später).
- **Grenzen:** Länder-Granularität, CDN-/Shared-Hosting-Fehlerzuordnung, Anycast, fehlende oder
  veraltete Geo-Daten. Die Karte ist eine **Schätzung**, kein Beweis über den tatsächlichen
  Serverstandort. Details: [TRAFFIC-MAP.md](TRAFFIC-MAP.md).

---

## 7. Privacy-/Filter-Profile

`TvPrivacyProfile`: `OFF`, `CONSERVATIVE`, `BALANCED`, `STRICT` (Persistenz-Key in `Vpn.kt`).
Regeln stammen aus dem vendorten Core (`PrivacyIntelligence`, `ThreatIndex`); Aktionen:
`ALLOW`, `ANNOTATE`, `CORRELATE`, `BLOCK` (`TrafficAction`).

- **Kein MITM:** Es wird nur der Verbindungs-/DNS-Metadatenpfad ausgewertet; TLS-/QUIC-Inhalte
  bleiben verschlüsselt und unangetastet.
- **Verschlüsseltes DNS:** Nutzt eine App DoT/DoH, ist der Domainname für die TV-App **nicht
  sichtbar**; sichtbar bleiben Ziel-IP/Land und Metadaten. Das wird in der UI ehrlich benannt.
- **Profilwirkung:** Höhere Profile blockieren mehr Kategorien, erhöhen aber das Risiko von
  Fehlblockungen (Streaming, Updates, DRM). Default ist `BALANCED`; das Profil ist jederzeit
  änderbar.

---

## 8. XDR-Light (TV-adaptiert)

Geplante Regel-Familien (Implementierung/Details in Arbeit, **NOT_TESTED**):

1. **Telemetrie-Ziel:** bekannte Smart-TV-Telemetrie-/ACR-Ziele (Domain/IP) im lokalen
   Privacy-Katalog.
2. **Tracker-Kategorie:** Domain fällt in eine Tracker-/Analytics-Kategorie.
3. **C2-/Threat-Treffer:** lokale Threat-Indizes (Feeds) melden den Ziel-Präfix.
4. **First-Seen/Auffälligkeit:** neue Ziele/Domains je App im Beobachtungsfenster.
5. **Sensor-Gesundheit:** Telemetrie-/Policy-Ausfall wird als Coverage-Risiko gemeldet, nicht als
   Angriff.

Grundsätze: Jeder Befund trägt Quelle/Regel/Zeit/Konfidenz; dieselbe Quelle über mehrere
Feed-Spiegel zählt nicht als mehrere unabhängige Signale; Korrelation statt Einzelmerkmal-
Überinterpretation; keine „Malware“-Behauptung aus einem einzelnen Treffer. Evidenz wird lokal
(HMAC-gesichert) angedockt. Konkrete Schwellen/Scores werden **nicht erfunden**; sie werden nach
Implementierung aus dem Code dokumentiert.

---

## 9. UI/UX-Bausteine

| Baustein | Inhalt | Status |
| --- | --- | --- |
| Onboarding | Erststart-Assistent inkl. Sir Quacksec, Consent, TI-Sync, erste Prüfung | **in Arbeit** |
| Schutz-Dashboard (`PROTECTION`) | VPN-Zustand (OFF/PREPARING/ACTIVE/DEGRADED/FAILED), Blockzähler, Profil, Consent-/Recovery-Aktionen | **in Arbeit** |
| Traffic-Map (`TRAFFIC`) | Weltkarte, Ziel-Länder, App-/Domain-Toplisten, Aktionen | **in Arbeit** |
| XDR (`XDR`) | korrelierte Findings, Erklärungen, Evidenz | **in Arbeit** |
| Sir Quacksec | Willkommensanimation einmal pro App-Start, überspringbar, D-Pad-sicher | **in Arbeit** |
| TI-Sync-Modal | Fortschritt (completed/total), Logo, ehrlicher Fehler-/Stale-Zustand | **in Arbeit** |

Verbindlich: D-Pad-vollständig, sichtbarer Fokus, kein Touch/Hover-Zwang; Zustände ehrlich
(kein „geschützt“ ohne TUN); Animationen kurz und überspringbar (GLASS-2100/Design-DNA).

---

## 10. Berechtigungen und Plattformintegration

| Berechtigung/Element | Zweck | Bewertung |
| --- | --- | --- |
| `INTERNET` | TI-Feeds (V1) + eigener Datenpfad-Egress | unverändert notwendig |
| `ACCESS_NETWORK_STATE` | Netzwerkstatus/-wechsel | unverändert notwendig |
| `FOREGROUND_SERVICE` | VPN-Dienst läuft als FGS | **neu V2**, notwendig |
| `FOREGROUND_SERVICE_SPECIAL_USE` | targetSdk 36 verlangt deklarierten FGS-Typ; Subtyp: lokales Loopback-VPN | **neu V2**, notwendig; Play-Deklaration erforderlich |
| `POST_NOTIFICATIONS` | FGS-Hinweis/Benachrichtigung sichtbar machen | **neu V2**, nur für FGS-Status |
| Service-Permission `BIND_VPN_SERVICE` | Schutz vor fremdem Binden an `TvVpnService` | Manifest (`android:permission`) |
| `SUPPORTS_ALWAYS_ON`-Metadatum | Always-On-Unterstützung | neu V2 |
| **nicht** angefordert | Standort, Accessibility, Overlay, Kamera, Mikrofon, `QUERY_ALL_PACKAGES`, Kontakte, SMS, Speicher | unverändert ausgeschlossen |

`VpnService.prepare(activity)` ist ein **System-Consent-Dialog**; ohne Zustimmung wird kein Tunnel
errichtet. Die App fordert keine weiteren Laufzeitberechtigungen an; die
Benachrichtigungsberechtigung betrifft ausschließlich die FGS-Sichtbarkeit.

---

## 11. Native-Helper-Supply-Chain

| Feld | Wert |
| --- | --- |
| Quelle | `GeDefense/Mobile/0.28.0-beta1/Source/app/src/main/jniLibs` (byte-identisch) |
| Dateien | `libgedefense_gaianet_v2.so` (arm64-v8a, x86_64) |
| Größen | arm64-v8a **3.588.356 B**; x86_64 **3.899.320 B** |
| SHA-256 (Dokumentationsteam berechnet, 29.10.2026) | arm64-v8a `d34fda6f06ed7809c386af243b55e55cadd20794f1413b94ada3a729b26fd15e`; x86_64 `9f393ce49032a84f75717174b09748c08e86ff831886a38f68d0ac12975394f3` |
| Byte-Identität zum Mobile-Dossier | **verifiziert** (gleiche Größe + gleicher SHA-256 wie Mobile-Originale am 29.10.2026) |
| Build-Einbindung | `abiFilters arm64-v8a, x86_64`; `jniLibs.useLegacyPackaging = true` (echte ausführbare Datei in `nativeLibraryDir`); `keepDebugSymbols` |
| Ausführung | Kindprozess der App, kein Root, kein Export, kein JNI im Paket-Hot-Path |
| Restpunkt | finaler, vom Projektteam bestätigter SHA-256-Eintrag im Release-Ledger; Integritätsprüfung zur Laufzeit (Self-Check) ist **NOT_TESTED** |

Der Helper ist ein **internes, vendortes Bauteil** (kein neues Drittanbieter-Runtime-Paket im
Sinne der SBOM-Politik). Externe Go-Module im Helper stammen aus dem Mobile-Dossier und werden
nicht als neue Runtime-Abhängigkeit der TV-App behauptet; Details/Supply-Chain-Liste des
Binaries sind im Mobile-Dossier dokumentiert.

---

## 12. Build, Packaging und Performance-Budgets

- **ABIs:** nur `arm64-v8a` und `x86_64` (TV-Praxis + Emulator); 32-bit wird nicht ausgeliefert.
- **APK-Größe:** zwei Helper-Binaries (~7,5 MB unkomprimiert) erhöhen die APK deutlich; endgültige
  Größe nach V2-Build **NOT_TESTED**.
- **Start/Scan:** V1-Beleg (Kaltstart 1,84–2,29 s, Emulator) bleibt Referenz; V2-Budgets
  (VPN-Startzeit, Telemetrie-Durchsatz, Batterie/Thermik) werden gemessen, sobald die
  Implementierung steht — **keine erfundenen Werte**.
- **Performance-Risiken:** Paketpfad im Helper (Go) statt JVM, Telemetrie-Framing, Karten-Rendering
  (großes PNG 2560×1280), FGS-Akkuverbrauch. Messplan in [TEST-PLAN.md](../TEST-PLAN.md).

---

## 13. Datenfluss End-to-End

```text
1) Erststart/Onboarding
   Setup → Consent (VpnService.prepare) → Profilwahl → TI-Sync → erste Prüfung
   → Schutz aktivieren (Auto-Start optional)

2) Laufender Betrieb
   App-Verkehr → TUN → GaiaNet-Helper
     ├─ Threat-Policy (ThreatIndex)        → ALLOW/ANNOTATE/CORRELATE/BLOCK
     ├─ Privacy-Policy (Profile)           → Block/Annotate
     └─ Telemetrie-Frames (bounded)        → TvFlowTelemetryReader
          → TvTrafficStore (Aggregation)  → TrafficApi → UI (Map/Apps/XDR)
          → XdrEngine (Korrelation)       → Evidence (lokal, HMAC)
          → XDR-UI/Report

3) Ausfall/Recovery
   Helper-Crash/Policy-Fehler → DEGRADED/FAILED (ehrlich) → TUN-Anker hält
   → Recovery startet Helper neu → Status erst wieder ACTIVE, wenn Datenpfad gesund

4) Nutzerkontrolle
   Schutz aus/Profil ändern/Auto-Start aus, Session-Zähler löschen, Evidenz exportieren/löschen
```

---

## 14. Offene Punkte und Annahmen

| Punkt | Status |
| --- | --- |
| VPN-Service/Helper-Integration, Telemetrie, XDR, Onboarding, V2-UI | **Code überwiegend vorhanden (Stand 29.10.2026)**; Compile/Laufzeit **NOT_TESTED** |
| V2-Screenshots | noch nicht vorhanden; Projektteam platziert sie unter `docs/screenshots` (keine Platzhalter erfunden) |
| Geo-Datenquelle/-lizenz, Länderabdeckung | offen; muss im SBOM/Quellenverzeichnis belegt werden |
| Policy-/Regel-Integrität (signierte Policy-Binaries?) | offen; derzeit kein Signaturmechanismus dokumentiert |
| Telemetrie-Retention/Persistenzdauer | Implementierungsdetail; muss in PRIVACY.md final belegt werden |
| Helper-Self-Check/Integritätsprüfung zur Laufzeit | **NOT_TESTED** |
| Always-On/Recovery auf realen TVs | **NOT_TESTED** (Emulator-, Geräte-Evidenz ausstehend) |
| Play-Policy/FGS-Deklaration (`specialUse`) | offen; vor Veröffentlichung zu prüfen |
| Batterie-/Thermik-Messung | **NOT_TESTED** |

---

## 15. Referenzen

- Architektur-Entwurf: `docs/V2-ARCHITECTURE.md` (dieses Dokument ersetzt/erweitert ihn).
- Verträge: `app/src/main/java/de/visiongaia/gedefense/tv/contract/V2Contracts.kt`,
  `Contracts.kt`; Modelle: `tv-core/src/main/kotlin/.../model/Traffic.kt`, `Vpn.kt`.
- Mobile-Referenz: `GeDefense/Mobile/0.28.0-beta1/Source/docs/datasheets/GeDefense-Mobile-Master-Architecture-EN.md`
  (Zwei-Prozess-Modell, `GeDefenseVpnService`, `NativeGaiaNet`, `SCM_RIGHTS`, XDR-/Traffic-Stores;
  Mobile-Fähigkeiten wie WireGuard/externe Tunnel sind **nicht** Teil von TV V2.0).
- Screenshots V1 (vorhanden): `docs/screenshots`; V2-Screenshots folgen.
