# GeDefense TV — Traffic-Map

> **Release-Tree 0.2.0-alpha1:** Dieses Dokument ist für den Quellstand `0.2.0-alpha1` (VersionCode 2) kuratiert. Evidenzangaben mit Datum 29.10.2026 beziehen sich auf den jeweils genannten Build; V2/V2.1-Funktionen sind Alpha und nicht vollständig auf realer TV-Hardware abgenommen.


**Version:** 2.0-plan · **Stand:** 29. Oktober 2026 · **Status:** Design/Plan ·
**Implementierung: NOT_TESTED** (UI/Telemetrie in Arbeit, keine V2-Screenshots vorhanden)

Die Traffic-Map zeigt, **wohin** der Fernseher aus Sicht der lokalen
On-Device-Loopback-VPN-Datenebene Verbindungen aufbaut – aggregiert nach Land, App und Domain.
Sie ist eine **lokale Visualisierung beobachteter Metadaten**, keine Inhaltsüberwachung und kein
Beweis über den tatsächlichen Standort eines Servers.

---

## 1. Was die Karte zeigt

| Ebene | Darstellung | Datenquelle |
| --- | --- | --- |
| Herkunft | Marker/Label des geschätzten Geräte-Herkunftslands | System-Locale/Netzwerk-Metadaten, **kein GPS** |
| Ziel-Länder | Linien/Bögen bzw. Marker zu Ländern mit beobachtetem Verkehr | lokale Telemetrie + Offline-IP→Land-Zuordnung |
| Intensität | Linienstärke/Fläche nach Bytes bzw. Flow-Anzahl | `CountryTraffic.bytes`/`flows` |
| Blockiert | Akzentmarkierung (Rot/Gold) für `BLOCK`-Flows | `CountryTraffic.blockedFlows`, `TrafficAction.BLOCK` |
| App-/Domain-Bezug | Detailpanel mit Top-Apps/Domains je Land | `AppTraffic.topCountries/topDomains` |
| Zustand | Banner „Schutz aktiv/eingeschränkt/aus“, Zähler, Stand | `TrafficSnapshot.state`, `VpnStatus` |

**Keine** Darstellung von: Payload-Inhalten, TLS-Klartexten, Bildschirminhalten, Standortdaten,
Geräte-IDs Dritter.

---

## 2. Datenquellen und Ableitung

```text
TUN-Verkehr → GaiaNet-Helper (DNS-Sicht, Flow-Metadaten)
   → begrenzte Telemetrie-Frames (2…1024 B/Frame)
   → TvFlowTelemetryReader (Validierung, UID→App, Geo-Land, Aktion)
   → TvTrafficStore (Aggregation, Caps)
   → TrafficApi.snapshot()/flows() → Karte + Detailpanels
```

- Ziel-Land: Offline-Zuordnung der Ziel-IP (Asset/Bibliothek im App-Build), keine externen
  Geo-Abfragen.
- Herkunft: `OriginInfo` aus Locale/Netz; optional manuelle Korrektur (V2.1+).
- Domain: nur wenn im lokalen DNS-Pfad tatsächlich beobachtet.

---

## 3. Grenzen und Fehlinterpretationsrisiken

| Grenze | Bedeutung |
| --- | --- |
| **Kein GPS** | Herkunft ist eine Schätzung aus Locale/Netz, nicht der Aufenthaltsort. |
| **Länder-Granularität** | Die Karte zeigt Länder, keine Städte/Regionen; innerhalb eines Landes kann der Server überall stehen. |
| **CDN/Shared Hosting** | Große CDNs und Cloud-Anbieter bedienen viele Dienste von denselben IP-Bereichen; ein Land bedeutet nicht „dieser Dienst sitzt dort“. |
| **Anycast/Edge** | Viele Dienste terminieren an wechselnden Edge-Standorten; Land kann je Session variieren. |
| **Verschlüsseltes DNS (DoT/DoH)** | Nutzt eine App eigenen verschlüsselten DNS, ist der Domainname für die TV-App **nicht sichtbar**; sichtbar bleiben IP/Land/Metadaten. Die UI muss das benennen, statt „keine Tracker“ zu suggerieren. |
| **TLS/QUIC-Inhalte** | Werden nie entschlüsselt (kein MITM); die Karte basiert nur auf Verbindungsmetadaten. |
| **Abdeckung** | Ohne aktives VPN (oder bei `DEGRADED`) ist die Karte unvollständig; sie darf nicht als vollständige Verkehrsübersicht erscheinen. |
| **Geo-Datenalter** | Offline-Zuordnung kann veraltet sein; Land kann falsch sein. |
| **App-Zuordnung** | UID→Paket gelingt nur für sichtbare/auflösbare Pakete; unbekannte UIDs bleiben ehrlich „unbekannt“. |

**Grundsatz:** Die Karte ist ein **Review-Werkzeug**, kein Beweis. Ein unbekanntes Land ist kein
Angriff; ein bekanntes Land ist kein Beweis für Sicherheit.

---

## 4. Farben und Legende (GLASS 2100, Redesign 2026)

| Element | Farbe (Token) | Bedeutung |
| --- | --- | --- |
| Umgebung/Karte | Obsidian `bgDeep`/`canvas` | ruhige Mineralläche, keine dekorativen Raster |
| Herkunft | Gold `accent` | geschätztes Geräte-Herkunftsland |
| Erlaubter Verkehr | Electric-Blue `electricBlue` | beobachtet, nicht blockiert |
| Blockiert | Rot `danger`/`critical` | lokal blockiert (Regel/Profil) |
| Korreliert/annotiert | Gold `warning`/`accentSoft` | XDR-/TI-Kontext ohne Block |
| „Keine Daten“ | Muted-Weiß `textMuted` | ehrlicher Leerzustand, **nicht** grün |

Legende immer **Text + Farbe** (nie Farbe allein); Zahlen als tabellarische Werte. Die Karte
verwendet das importierte `world_map_ambient.png` (2560×1280, aus dem Mobile-Dossier,
byte-identisch) als stille Hintergrundebene.

---

## 5. Interaktion (D-Pad)

- Karte ist fokussierbar; OK öffnet die Länder-Detailansicht, BACK schließt sie.
- Detailpanel listet Top-Apps/Domains mit Bytes, Flows und Aktion; Zeilen sind per D-Pad
  fokussierbar (keine Hover-/Touch-Abhängigkeit).
- Kein kontinuierliches Animieren der Karte; keine Partikel/Glows (Performance/Anti-Slop).
- Zustandswechsel (z. B. VPN aus) aktualisieren Banner und Karte sofort, ohne veraltete
  „geschützt“-Anzeige.

---

## 6. Performance-Budget

| Aspekt | Festlegung | Status |
| --- | --- | --- |
| Kartenbild | statisches PNG 2560×1280 (≈ 494 KB), einmal geladen | Assets vorhanden |
| Zeichnen | keine dauerhaften Animationen; Neuzeichnen nur bei Snapshot-Update | Design |
| Snapshot-Größe | Apps ≤ 200, Länder ≤ 64, Domains ≤ 200; Top-Listen ≤ 12 | Modell erzwungen |
| Update-Takt | moderate, gebündelte Aktualisierung (kein Frame-Polling) | **NOT_TESTED** |
| Speicher/CPU | Messung auf Emulator und realem TV offen | **NOT_TESTED** |

---

## 7. Datenschutz

- Alle Traffic-Metadaten bleiben **lokal**; kein Upload, keine Cloud-Analyse.
- Keine Inhalte, keine TLS-Entschlüsselung, kein Netzwerk-MITM.
- Domain-/App-Metadaten sind sensibel: Export nur auf Nutzeraktion, begrenzte Felder, keine
  Roh-Flow-Dumps (siehe [PRIVACY.md](../PRIVACY.md)).
- Nutzerkontrolle: Schutz aus, Profil ändern, Session-Zähler löschen (`TrafficApi.clearSession()`).

---

## 8. Evidenzstatus / geplante Abnahme

| Prüfung | Status |
| --- | --- |
| Karte rendert korrekte Länder/Aktionen für bekannte Test-Flows | **NOT_TESTED** (V2-Implementierung ausstehend) |
| Leerzustand ehrlich (kein „grün“) bei fehlender Beobachtung | **NOT_TESTED** |
| Verschlüsseltes DNS wird als „Domain nicht sichtbar“ erklärt | **NOT_TESTED** |
| D-Pad-Detailnavigation ohne Fokusfalle | **NOT_TESTED** |
| Kein Upload (Netzwerk-Trace/Proxy-Nachweis) | **NOT_TESTED** |
| Performance/Frame-Zeit auf Emulator + realem TV | **NOT_TESTED** |
| Screenshots der Map | **noch nicht vorhanden** (Projektteam platziert V2-Screenshots unter `docs/screenshots`) |

Die zugehörigen Testfälle stehen in [TEST-PLAN.md](../TEST-PLAN.md) (V2-Matrix).
