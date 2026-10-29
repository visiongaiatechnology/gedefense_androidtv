# GeDefense TV — Onboarding (Erststart-Assistent)

> **Release-Tree 0.2.0-alpha1:** Dieses Dokument ist für den Quellstand `0.2.0-alpha1` (VersionCode 2) kuratiert. Evidenzangaben mit Datum 29.10.2026 beziehen sich auf den jeweils genannten Build; V2/V2.1-Funktionen sind Alpha und nicht vollständig auf realer TV-Hardware abgenommen.


**Version:** 2.0-plan · **Stand:** 29. Oktober 2026 · **Status:** Design/Plan ·
**Implementierung: NOT_TESTED** (keine V2-Läufe, keine Screenshots vorhanden)

Der Onboarding-Assistent führt beim ersten Start durch Einrichtung, Aufklärung und Einwilligung.
Er ist **kein Marketing-Flow**: Jeder Schritt erklärt, was die App lokal tut, welche Rechte/
Consents nötig sind und was passiert, wenn der Nutzer ablehnt. Alle Schritte sind vollständig per
D-Pad bedienbar; es gibt keine Touch-/Hover-Abhängigkeit.

---

## 1. Ablauf (geplant)

| # | Schritt | Inhalt | Aktion/Weiter |
| --- | --- | --- | --- |
| 1 | **Willkommen** | Sir-Quacksec-Animation (überspringbar), Produktname/Version, „Lokale Sicherheitskonsole“ | OK/Skip → 2 |
| 2 | **Was die App tut** | Ehrliche Fähigkeiten: sichtbare lokale Metadaten, App-Inventar (sichtbarer Teil), Hardening-Hinweise, TI, lokale Evidenz | Weiter → 3 |
| 3 | **Was die App nicht tut** | Kein vollständiges Inventar, kein systemweiter Flow-/Port-Monitor, kein privilegiertes EDR, keine Cloud-Telemetrie | Weiter → 4 |
| 4 | **VPN-Aufklärung** | Lokales Loopback-VPN, kein externer Server; gefiltert werden DNS-/Verbindungsmetadaten; **keine** Inhalts-/TLS-Entschlüsselung; Akku-/Kompatibilitätshinweise; Konflikt mit anderen VPN-Apps | Weiter → 5 |
| 5 | **VPN-Consent** | System-Dialog über `VpnService.prepare(activity)`; Ablehnung = kein Schutz, App bleibt nutzbar | Zustimmen/Ablehnen |
| 6 | **Benachrichtigung** | Hinweis auf dauerhafte FGS-Benachrichtigung (Android verlangt sie für den VPN-Dienst); `POST_NOTIFICATIONS` | Erlauben/Überspringen |
| 7 | **Profilwahl** | Off / Konservativ / Ausgewogen (Default) / Streng – Wirkung und Fehlblockungsrisiko erklärt | Auswählen → 8 |
| 8 | **Threat-Intelligence-Sync** | Sync-Modal mit Fortschritt (completed/total), Logo; Fehler/Offline werden ehrlich gezeigt, letzter Cache bleibt nutzbar | Weiter → 9 |
| 9 | **Erste Prüfung** | Scan starten; Ergebnis kann `PARTIAL`/„Teilweise Sicht“ sein – wird erklärt | Weiter → 10 |
| 10 | **Schutz aktivieren** | Start des Loopback-VPN; Auto-Start (optional); Status `ACTIVE`/`DEGRADED`/`FAILED` ehrlich | Abschließen |
| 11 | **Abschluss** | Kurzübersicht: Schutzstatus, Profil, letzte Prüfung, nächste Schritte | → Home |

Ein **Skip/Abbrechen** ist an jeder Stelle möglich; die App startet dann im ungeschützten Zustand
und zeigt das ehrlich an (keine „geschützt“-Behauptung). Der Assistent kann über die Einstellungen
erneut geöffnet werden.

---

## 2. Bedeutung der Einwilligungen (was der Nutzer zustimmt)

| Einwilligung | Was sie technisch bedeutet | Was sie **nicht** bedeutet |
| --- | --- | --- |
| **VPN-Consent** (`VpnService.prepare`) | Android erlaubt der App, ein TUN-Interface zu besitzen; der Verkehr der Apps läuft durch den lokalen Datenplan | Kein externer VPN-Anbieter, keine Datenweitergabe an VGT/Dritte, kein Standortzugriff |
| **FGS-Benachrichtigung** | Android zeigt eine dauerhafte Benachrichtigung für den laufenden VPN-Dienst | Kein Werbe-/Tracking-Kanal; keine Push-Nachrichten |
| **Auto-Start** (optional) | VPN startet nach Geräte-/App-Start erneut, wenn Consent bereits erteilt wurde | Kein stilles Aktivieren ohne vorherige Zustimmung; jederzeit abschaltbar |
| **Always-On** (Systemeinstellung) | Android hält den VPN-Dienst aktiv und blockiert bei Ausfall | Kein Root, keine System-App-Rechte |
| **TI-Sync** | Lädt öffentliche Threat-Intelligence-Feeds per HTTPS (9 Quellen) | Kein Upload von Geräte-/App-Daten |
| **Detaillierte Telemetrie** (optional, V2-Einstellung) | erlaubt ausführlichere lokale Traffic-Metadaten (mehr Kategorien/Details) | Keine Inhalte, kein Upload; jederzeit abschaltbar |

**Keine** Einwilligung wird vorausgewählt oder erzwungen. Ohne VPN-Consent bleibt die App als
Diagnose-Tool nutzbar.

---

## 3. Sir Quacksec (Willkommens-Animation)

- Erscheint beim App-Start (geplant: einmal pro Start), ist **überspringbar** (OK/BACK) und
  blockiert nie die Bedienung.
- D-Pad-sicher, kurze Animation (kein Endlos-Loop), respektiert Reduced-Motion sofern verfügbar.
- Keine Audio-Autoplay-/Mikrofon-Nutzung; keine Netzwerkabhängigkeit.
- Asset: `res/drawable-nodpi/sir_quacksec.png` (vom Nutzer bereitgestellt; siehe SBOM).

## 4. TI-Sync-Popup

- Zeigt Fortschritt (`completed`/`total`) während des Feed-Syncs; Logo/Brand dezent.
- Bei Fehler/Offline: ehrlicher Zustand, letzter Cache bleibt nutzbar, Stale-Status sichtbar.
- Kein Fake-Fortschritt; Abbruch/Fehler werden nicht als Erfolg dargestellt.
- Das Popup blockiert keine sicherheitskritische Aktion und ist per D-Pad bedienbar.

---

## 5. Fehler- und Ablehnungsfälle

| Situation | Erwartetes Verhalten |
| --- | --- |
| VPN-Consent abgelehnt | Kein Tunnel; Status `OFF`/`UNSUPPORTED`; ehrliche Erklärung + erneuter Versuch möglich |
| VPN-Start schlägt fehl | Status `FAILED` mit Ursache; keine Schutzbehauptung; Recovery/erneuter Versuch |
| Helper-Ausfall nach Start | Status `DEGRADED`; TUN-Anker bleibt; UI erklärt Einschränkung |
| Benachrichtigung verweigert | FGS läuft gemäß Android-Regeln weiter; ehrlicher Hinweis, dass die Benachrichtigung nicht sichtbar ist |
| TI-Sync offline | Fehler/Stale sichtbar; letzter Feed bleibt nutzbar |
| Erste Prüfung `PARTIAL` | Erklärung der Sichtbarkeitsgrenzen; kein „sauber“-Claim |
| Nutzer bricht Onboarding ab | App bleibt nutzbar; Schutz inaktiv; Hinweis in Home/Settings |

---

## 6. UX- und Barrierefreiheitsregeln

- Nur wenige Schritte pro Ansicht, klare primäre Aktion, sichtbarer 4-dp-Gold-Fokusring.
- Fortschrittsanzeige (Schritt x/y) und klare Zurück-Navigation; BACK verlässt das Onboarding
  nach Bestätigung, nicht versehentlich.
- Texte in 10-Fuß-Größe (15–92 sp), Status immer Glyph + deutsches Label, keine Farbe allein.
- Keine Dark Patterns: „Überspringen“ ist gleichwertig sichtbar, Ablehnung wird nicht versteckt.
- Keine Telemetrie/„Analyse“-Opt-ins im Onboarding.

---

## 7. Evidenzstatus

| Prüfung | Status |
| --- | --- |
| Onboarding erstmaliger Pfad inkl. Consent-Dialog | **NOT_TESTED** |
| Ablehnungs-/Skip-Pfade | **NOT_TESTED** |
| Sir-Quacksec-Animation, Skip per D-Pad | **NOT_TESTED** |
| TI-Sync-Popup Fortschritt/Fehler | **NOT_TESTED** |
| Erste Prüfung + Statusübergang zu ACTIVE | **NOT_TESTED** |
| Screenshots des Onboardings | **noch nicht vorhanden** (Projektteam platziert V2-Screenshots) |

Die Abnahmefälle stehen in [TEST-PLAN.md](../TEST-PLAN.md) (V2-Matrix).
