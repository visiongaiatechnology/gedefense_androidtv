# GeDefense TV — Design-DNA (VGT GLASS 2100, Redesign 2026)

> **Release-Tree 0.2.0-alpha1:** Dieses Dokument ist für den Quellstand `0.2.0-alpha1` (VersionCode 2) kuratiert. Evidenzangaben mit Datum 29.10.2026 beziehen sich auf den jeweils genannten Build; V2/V2.1-Funktionen sind Alpha und nicht vollständig auf realer TV-Hardware abgenommen.


**Version:** 2.0 · **Stand:** 29. Oktober 2026 · **Status:** Design-DNA dokumentiert; Runtime-
Tokens implementiert; **visuelle QA auf dem Android-TV-Emulator (API 36, 1080p) belegt**;
reale TV-Hardware **NOT_TESTED**

Dieses Blatt ist die verbindliche Design-DNA für GeDefense TV nach dem VGT-GLASS-2100-Standard.
Grundlage der Tokenwerte ist der reale Code: **`app/src/main/java/.../ui/TvTheme.kt` ist die
Laufzeit-Quelle der Wahrheit**; die XML-Ressourcen (`res/values/colors.xml`, `dimens.xml`,
`styles.xml`) spiegeln diese Werte für Drawables/Selectors und sind vorhanden.

> **Redesign-Hinweis:** Die ursprüngliche Salbei-/Graphit-Richtung wurde nach Nutzerfeedback
> durch die **Original-GeDefense-Identität** ersetzt: Obsidian-Mineral + metallisches Gold +
> Electric-Blue, Original-Logo, weiße Textfamilie. Alle Tokenwerte unten stammen aus dem
> aktuellen Code (Stand 29.10.2026).

---

## 1. Produkt-DNA

```text
PRODUCT: GeDefense TV
├── Purpose            Sicherheitslage eines Fernsehers verständlich bewerten, Risiken erklären,
│                      manuelle Härtung empfehlen, Befunde lokal nachvollziehbar protokollieren.
├── Audience           Sicherheitsbewusste TV-Nutzer, Technik-affine Haushalte, VGT-Testgeräte.
├── Primary Task       Scan starten → Gesamtstatus verstehen → wichtigsten Befund erklären →
│                      nächsten manuellen Schritt ausführen.
├── Density            mittel-niedrig: wenige Kernaussagen pro Bildschirm, Details in zweiter Ebene
├── Trust Level        hoch: Sicherheitsprodukt; Aussagen müssen belegt und einschränkungsehrlich sein
├── Emotional Tone     ruhig, souverän, präzise, nicht alarmistisch
├── Visual Energy      niedrig-dosiert; ein Fokus, ruhige Flächen, keine Dauerbewegung
├── Spatial Depth      flach-geschichtet (Z0–Z4) ohne 3D, ohne Backdrop-Blur
├── Interaction Model  D-Pad-Fernbedienung (up/down/left/right/OK/BACK), kein Touch/Hover
├── Motion Level       minimal: Focus-Scale 1.02/140 ms, Eingang 220 ms, keine Ambient-Animation
├── 3D Level           TIER 0 — kein 3D (kein Mehrwert, Performance-/A11y-Kosten)
├── Accessibility      10-Fuß-Lesbarkeit, sichtbarer Fokus, Status nie nur über Farbe
├── Performance        kein Blur, keine Endlos-Animation, View-System ohne AndroidX
└── Brand Signature    Original-GeDefense-Logo + Obsidian-Mineralläche + Gold-Lichtkante
```

**Ein-Satz-Designziel:** *„Dieses Interface fühlt sich an wie ein ruhiges, präzises
Sicherheitsinstrument im Wohnzimmer – teuer, zurückhaltend, diagnostisch, ohne Hacker-Klischee.“*

### Produktcharakter und Farblehre

Nach GLASS 2100 ist für GeDefense/Security vorgesehen: dunkles Mineral/Graphit, ruhige
Security-Farbwelt, sparsame Zustandsfarben — **kein** Neon-Cyan + Rot + Fake-Terminal. Die
konkrete Produktidentität:

- **Umgebung:** Obsidian-Mineral (fast schwarzes Blau-Grau) statt reinem Schwarz.
- **Pigment:** metallisches Gold als **Brand/Primary/Warning** (Logo, Primäraktion, Regeln).
- **Schutzlicht:** Electric-Blue als **Live/Info**-Farbe (aus dem Schild-Juwel des Logos).
- **Text:** durchgehend Weiß-Familie (≥ 82 % Weiß) — Hierarchie über Größe/Gewicht, **nie**
  durch Ausgrauen.
- **Status:** Grün nur für verifiziert/gesund, Rot nur für kritisch/hoch; immer Glyph + Label.

---

## 2. Farbsystem (implementierte Tokens aus `TvTheme.kt`)

### 2.1 Umgebung und Flächen

| Token | ARGB/RGB | Rolle |
| --- | --- | --- |
| `bgDeep` | `(4,7,10)` | Z0 Umgebung, Wurzelhintergrund (Obsidian) |
| `bg` | `(8,12,17)` | Z0 Fläche |
| `canvas` | `(11,16,22)` | Z1 Inhaltsfläche |
| `canvasRaised` | `(14,20,27)` | Z1 angehobene Inhaltsfläche |
| `glassPanel` | `argb(222, 19,26,34)` | Z2 Glasfläche (funktional, hohe Deckkraft) |
| `glassPanelSoft` | `argb(184, 15,21,28)` | Z2 Navigation/Rail |
| `glassStroke` | `argb(82, 201,162,75)` | Gold-Kante der Glasflächen |
| `glassStrokeCool` | `argb(64, 120,156,190)` | kühle Kante für sekundäre Flächen |
| `glassHighlight` | `argb(38, 244,236,214)` | warme Lichtkante |
| `scrimHeavy` | `argb(236, 6,9,13)` | Z4 Banner/Overlay-Scrim |

### 2.2 Pigment (Gold) und Schutzlicht (Blue)

| Token | RGB | Rolle |
| --- | --- | --- |
| `accent` | `(230,185,92)` | metallisches Gold: Brand, Primäraktion, Regeln |
| `goldBright` | `(247,214,138)` | heller Gold-Highlight/Fokusring |
| `accentSoft` | `(164,126,52)` | sekundäre Goldfläche |
| `accentDim` | `(58,45,20)` | Fokus-/Auswahlfüllung (dunkel) |
| `electricBlue` | `(90,169,230)` | Electric-Blue: Live/Info |
| `gemBlue` | `(64,140,230)` | Juwel-Blau (Logo-nahe Akzente) |
| `blueDim` | `(24,44,64)` | blaue Fläche (dunkel) |

### 2.3 Text

| Token | RGB | Rolle |
| --- | --- | --- |
| `textPrimary` | `(255,255,255)` | Primärtext |
| `textSecondary` | `(234,240,245)` | Sekundärtext |
| `textMuted` | `(220,228,236)` | Labels, Sekundärinformation |
| `textDim` | `(201,211,221)` | Versions-/Fußzeileninfo |

**Regel:** Text bleibt Weiß-Familie; Gold ist **nicht** die Standard-Textfarbe (nur Brand/
Primary/Warning, z. B. Überschriften-Akzente, Buttons, aktive Rail-Einträge).

### 2.4 Funktionsfarben

| Token | RGB | Semantik |
| --- | --- | --- |
| `info` | `(90,169,230)` | neutrale Information/Live (Electric-Blue) |
| `success` | `(79,209,165)` | verifiziert/gesund (Grün) |
| `warning` | `(230,185,92)` | Aufmerksamkeit (Gold/Bronze) |
| `danger` | `(239,106,90)` | hohes Risiko/Fehler |
| `critical` | `(240,75,75)` | kritisch; nur mit Glyph + Text |

**Regeln:** Rot ist echte Aufmerksamkeit vorbehalten. Kein „Dauer-Rot“ als Produktidentität,
keine Regenbogenpalette, kein Gradient-Text, keine Statusfarbe ohne Text/Glyph.

---

## 3. Glas-Materialgrammatik (Z0–Z4) für TV

Auf Android TV wird **kein Backdrop-Blur** als Grundmaterial eingesetzt: Er kostet GPU-Leistung
und verschlechtert auf vielen TV-SoCs Kontrast und Textschärfe. Die Glasidentität entsteht
stattdessen durch **präzise geschichtete Transluzenz, Gold-Kantenlicht und sparsame Tiefe** —
dieselbe Materialfamilie, ohne Performance-/Lesbarkeitsrisiko.

| Ebene | TV-Umsetzung | Tokens |
| --- | --- | --- |
| **Z0 Environment** | ruhige Obsidian-Mineralläche, keine Raster/Dot-Grids | `bgDeep`, `bg` |
| **Z1 Content Canvas** | großzügige Inhaltsfläche, nahezu opak für Lesbarkeit | `canvas`, `canvasRaised` |
| **Z2 Glass Surface** | Rail, Panels, Karten mit funktionaler Grenze; Gold-Kante | `glassPanelSoft`, `glassStroke`, `glassHighlight` |
| **Z3 Floating Glass** | Banner/Overlay (kurzlebig), keine schwebenden Dauerflächen | `scrimHeavy`, `glassStroke` |
| **Z4 Modal/Critical** | klare, stabile Overlays mit hohem Kontrast | `scrimHeavy`, `textPrimary` |

Verbindlich:

1. Eine Glasfläche muss eine **funktionale Grenze** darstellen (Navigation, Panel, Overlay) –
   keine Karten-in-Karten-in-Karten.
2. Ein Lichtmodell: warme Gold-Kante oben/links gedacht, Schatten minimal.
3. Textkontrast wird auf der **zusammengesetzten** Fläche bewertet (Deckkraft berücksichtigen).
4. Kein Blur als Hierarchie-Ersatz; ohne Glas-Effekt bleibt die Komposition lesbar.

---

## 4. Typografie

- **Schrift:** Android-System-Sans (keine gebündelte Font, keine CDN-Abhängigkeit). Keine
  Display-Font-Experimente.
- **Skala (10-Fuß-Distanz, aus `TvTheme.kt`):**

| Rolle | Token | Größe |
| --- | --- | --- |
| Score | `TEXT_SCORE_SP` | 92 sp |
| Display | `TEXT_DISPLAY_SP` | 64 sp |
| Titel | `TEXT_TITLE_SP` | 44 sp |
| Überschrift | `TEXT_HEADING_SP` | 32 sp |
| Body | `TEXT_BODY_SP` | 24 sp |
| Label | `TEXT_LABEL_SP` | 20 sp |
| Caption | `TEXT_CAPTION_SP` | 18 sp |
| Micro | `TEXT_MICRO_SP` | 15 sp |

- Section Labels: Caption + `letterSpacing 0.18`, `allCaps` – nur für kurze Rubriken, nie für
  Fließtext.
- Wortmarke „GeDefense“ in Titelgröße + „TV“ in Labelgröße mit erhöhtem Tracking; daneben das
  Original-Logo.
- Zahlen für Metriken: tabellarische Ziffern bevorzugt; keine dekorativen Monospace-„Terminals“.
- Keine Gradient-Texte, keine Schatten-Texte, keine überbreiten Zeilen.

---

## 5. Fokus- und Interaktionsrhythmus

Die Fernbedienung ist die einzige verlässliche Eingabe. Der Fokus ist Teil des Designs:

| Element | Ausführung |
| --- | --- |
| Fokusring | 4 dp (`FOCUS_STROKE_DP` = `dimens.xml tv_focus_stroke`), Gold (`goldBright`), zusätzlich dunkle Gold-Füllung |
| Fokus-Motion | Focus-Scale 1.02 in 140 ms (`MOTION_FAST`); keine Ambient-Animation |
| Rail-Auswahl | Gold-Balken links + Gold-Text; unfokussierte Zeilen ohne Container |
| Listenzeilen | unfokussiert flach, fokussiert mit Ring/Fläche – kein Dauer-Container |
| Radien | Panel 20 dp (`RADIUS_PANEL_DP`), Control 14 dp (`RADIUS_CONTROL_DP`) |
| Overscan | 48 dp (`OVERSCAN_DP`) an allen Rändern |
| Railbreite | 300 dp (`RAIL_WIDTH_DP`) |
| Eingangsmotion | 220 ms (`MOTION_ENTER`), Baseline sichtbar (kein Alpha-0-Risiko) |
| Banner | kurze Fades; Anzeige ~2,6 s |
| Navigation | D-Pad; OK aktiviert; BACK: screen-lokal → Back-Stack → HOME; LEFT führt zur Rail |
| Hover/Touch | **keine** Abhängigkeit; Touch ist optionaler Nebeneffekt |

Interaktionsrhythmus: **ein primärer Fokus pro Ansicht**, wenige primäre Aktionen, Details in
zweiter Ebene. Home ist hero-first (Hero-Panel, Canvas-Score-Ring, vier KPI-Tiles, Top-Befunde).
„Riskante“ Aktionen (Löschen) benötigen bewusste zweistufige Bestätigung und sichtbare
Konsequenz; beim Navigieren wird nie eine riskante Aktion ausgelöst.

---

## 6. Brand-Assets

| Asset | Datei | Dimension | Verwendung |
| --- | --- | --- | --- |
| Original-Logo | `res/drawable-nodpi/gedefense_logo.png` | 512×512 | Rail-Brandlockup, Settings/About-Brandblock |
| TV-Launcher-Banner | `res/drawable-nodpi/tv_banner.png` | 640×360 | Leanback-Launcher-Banner |
| App-Icon | `res/drawable-nodpi/ic_tv_launcher.png` | 512×512 | Launcher-/App-Icon |
| Hero-Watermark | `res/drawable-nodpi/brand_watermark.png` | 900×900 | dezente Watermark im Home-Hero |

Quelle: Original-GeDefense-Asset aus dem Mobile-Dossier (VGT-eigenes Asset). Die Generierung/
Ablage ist über `tools/generate_brand_assets.py` nachvollziehbar. **Hinweis:** Launcher-Darstellung
auf unprovisioniertem Emulator nicht prüfbar; `LEANBACK_LAUNCHER`-Intent und Banner-Ressource
sind statisch belegt.

---

## 7. Zustände (Design for States)

Pflichtzustände für sicherheitsrelevante Flächen:

- initial / loading (echter Fortschritt statt Fake-Spinner, wenn messbar),
- loaded (vollständig),
- **partial** (eingeschränkte Sichtbarkeit) – deutlich anders als „loaded“,
- **stale** (veraltete Daten) – mit Zeit-/Quellenangabe,
- **unknown** (nicht prüfbar) – niemals grün,
- offline / permission-denied / degraded / error,
- selected, disabled, destructive-pending, success,
- **restart-summary** (letzter Lauf nach Force-Stop/Neustart) mit ehrlichem Hinweis, dass Details
  ggf. nicht im Speicher liegen.

Regel: „Unbekannt/eingeschränkt/veraltet“ muss **textuell und ikonisch** von „geprüft/sicher“
unterscheidbar sein. Farbe allein ist nie ausreichend.

---

## 8. Verbotene Muster (Anti-Slop-Gate)

Für GeDefense TV ausdrücklich **verboten**:

1. Sichtbare Hintergrund-Gitter, Dot-Matrix, Scanlines, Hex-Frames, „Fake-Terminal“-Text.
2. Neon-Cyan-/Cyberpunk-Palette, Dauer-Glow, Leucht-Orbs, zufällige Partikel.
3. Jede Information in einer gleich aussehenden Glas-Card („Kartenwand“); Karten-in-Karten.
4. Gradient-Text, dekorative Charts ohne Datenfunktion, Fake-KPIs.
5. Status nur über Farbe; Rot als Dekoration; Schädel-/Warn-Icon-Flut.
6. Hover-only-Hilfen, Icon-only-Buttons ohne Label, Mini-Labels unter 15 sp.
7. Touch-/Maus-Abhängigkeit oder Gesten als einziger Weg.
8. Endlos-Animationen ohne Zustandsbezug; bewegbare Hintergründe.
9. Riesige Border-Radien und Soft-Shadows auf jedem Element.
10. Backdrop-Blur als Selbstzweck oder als Hierarchie-Ersatz.
11. Graue Textfarbe als Hierarchie-Ersatz (statt Größe/Gewicht) – Redesign-Korrektur.

---

## 9. Performance- und A11y-Budget

### Performance

| Budget | Festlegung | Status |
| --- | --- | --- |
| Rendering | View-System, keine AndroidX/Compose, kein WebView | implementiert |
| Blur | **kein** Backdrop-Blur in V1 | bewusst |
| Animationen | Focus 140 ms, Eingang 220 ms, keine Ambient-/Dauerbewegung | implementiert |
| Kaltstart (Debug, Emulator, Software-GPU) | `am start -W` **1,81–2,29 s**; Bootstrap 191–261 ms; `navigate(HOME)` 118–135 ms; ~1,4 s Window/Theme/Inflate (Emulator-Anteil) | **belegt (Emulator)** |
| Performance-Fix | TI-Status O(1): `navigate` vorher 4.519 ms → nachher 118–135 ms | **belegt** |
| Frame-Ziel | 60 fps auf TV-Hardware; keine Long Tasks im Main-Thread | **NOT_TESTED** auf realer Hardware |
| Speicher | keine Bild-/3D-Kacheln; Brand-PNGs komprimiert | implementiert |

Bewusst **nicht** verwendet: dauerhafte Hintergrundschleifen, aggressives Polling,
Backdrop-Blur-Rendering, WebView, 3D/Canvas-Dekoration.

### Accessibility

| Anforderung | Umsetzung | Status |
| --- | --- | --- |
| Kontrast Text | Weiß-Familie auf dunklen Flächen, Ziel ≥ 4,5:1 (WCAG AA); im Emulator visuell geprüft | **PASS (Emulator, visuell)**; formale Messung nicht dokumentiert |
| Fokus sichtbar | 4 dp Gold-Ring + Fläche + Textfarbe | implementiert (Code), Emulator-Screenshots |
| Status nicht farbabhängig | Glyph + deutsches Label (`statusLabel`/StatusPill) | implementiert; Screenshots |
| 10-Fuß-Lesbarkeit | 15–92 sp | implementiert; Screenshots |
| Remote-only bedienbar | D-Pad-Verträge, `initialFocus`, `handleBack`; kein Touch-Zwang | **PASS (Emulator)** |
| Textskalierung/Reflow | sp-basierte Größen; keine festen Textboxen | **NOT_TESTED** |
| Reduced Motion | keine Ambient-Animation; kurze Fades unkritisch | Designentscheidung, **NOT_TESTED** |

---

## 10. Visual-QA-Gate (Status)

| # | Prüfung | Status |
| --- | --- | --- |
| 1 | Product DNA vorhanden, eigenständiger Markeneindruck | **PASS (Emulator)** – Original-Logo, Obsidian/Gold, Screenshots |
| 2 | Keine dekorativen Hintergrundgitter/Dot-Grids | **PASS (Code + Screenshots)** |
| 3 | Glas-Materialsprache konsistent, keine Karteninflation | **PASS (Emulator, visuell)** |
| 4 | Farbtheorie/Kontrast geprüft | **PARTIAL** – visuell begutachtet (Weiß-Familie, ≥ 4,5:1), keine formale Messung |
| 5 | Primärer Fokus/Lesefluss/Makro-Hierarchie | **PASS (Emulator, Screenshots)** |
| 6 | Bedienpfade per D-Pad erreichbar | **PASS (Emulator)** |
| 7 | Emulator-Renderprüfung | **PASS (1080p-Screenshots)**; reale TV-Hardware **NOT_TESTED** |
| 8 | Empty/Loading/Error/Permission/Stale/Offline-Zustände | **PARTIAL** – Teil-/Restart-/Empty-Zustände belegt; Offline/Error nicht vollständig |
| 9 | Motion reduziert/deaktivierbar | Design: nur kurze Fades/Scale; nicht separat getestet |
| 10 | Keine Performance-Einbußen | **PASS (Emulator Kaltstart)**, reale Hardware offen |
| 11 | Ohne Blur/Gradient/Shadow/3D weiterhin attraktiv und bedienbar | Designentscheidung (kein Blur/keine Gradienten) |
| 12 | Screenshots/Previews mit Korrekturrunde | **PASS** – Redesign-Runde nach Nutzerfeedback (Screenshots → 80–96) |

**Konsequenz:** Design-DNA und Emulator-Render sind belegt; reale TV-Hardware (OEM-Panel,
Launcher-Darstellung, Fernbedienung) bleibt **NOT_TESTED**. Keine „fertig“-Bewertung für
Produktionsrelease ohne reale Geräte-Evidenz.

---

## 11. Implementierungsbindung

| Artefakt | Rolle |
| --- | --- |
| `app/src/main/java/de/visiongaia/gedefense/tv/ui/TvTheme.kt` | **Laufzeit-Quelle der Wahrheit** für Tokens/Geometrie/Typo/Motion |
| `app/src/main/res/values/colors.xml`, `dimens.xml`, `styles.xml`, `strings*.xml` | XML-Spiegel für Drawables/Selectors/Theme – vorhanden |
| `app/src/main/res/drawable/*` | Glass-Panels, Status-Pills, Focus-Selectors, Buttons |
| `app/src/main/res/drawable-nodpi/*.png` | Original-Logo, Banner, App-Icon, Hero-Watermark |
| `TvMainActivity.kt` | Rail, Overscan, Fokus-/Back-Rhythmus, Banner |
| `ui/Screen.kt` (`TvRoute`, `ScreenHost`, `TvScreen`) | Navigations-/Fokus-Verträge |
| `ui/components/*` | GlassPanel, FocusableAction, FocusableRow, StatusPill, GlyphView, GlyphBadge, InitialsBadge, MetricTile, RingGaugeView, TvProgressBar, ScreenScaffold, SectionHeader, EmptyState, FindingRow |
| `ui/screens/*.kt` + `ui/ScreenRegistry.kt` | Home, Check, Findings, FindingDetail, Apps, Hardening, ThreatIntel, Evidence, Settings, About |
| `build.gradle.kts`/Fonts | Systemschrift, keine CDN-/Font-Abhängigkeiten |

Bei Abweichung zwischen XML und `TvTheme.kt` gilt `TvTheme.kt`; die Abweichung ist zu beheben.
Änderungen an der Design-DNA erfordern eine bewusste Aktualisierung dieses Dokuments.

---

## 12. V2-UI-Elemente (Planung, NOT_TESTED)

V2 ergänzt die bestehende DNA um Schutz-, Traffic- und Onboarding-Oberflächen. Es gelten
unverändert: Obsidian/Gold/Electric-Blue-Palette, Weiß-Familie, 4-dp-Gold-Fokusring, keine
Hintergrundgitter, keine Karteninflation, Status nur mit Glyph + Label.

| Element | Designvorgabe | Status |
| --- | --- | --- |
| Schutz-Dashboard (`PROTECTION`) | ein primärer Zustand (aktiv/degraded/aus/fehlerhaft), wenige klare Aktionen (Start/Stop/Profil), rote Farbe nur für echte Störung | **in Arbeit, NOT_TESTED** |
| Traffic-Map (`TRAFFIC`) | ruhige Karte, Gold = Herkunft/Brand, Blau = erlaubt, Rot = blockiert, Gold = korreliert; Legende mit Text; keine Partikel/Glows | **in Arbeit, NOT_TESTED** |
| XDR (`XDR`) | erklärbare Befundzeilen (Regel, Quelle, Zeit, Konfidenz), keine Malware-Ästhetik | **in Arbeit, NOT_TESTED** |
| Onboarding | Schritt-Indikator, ehrliche FGS/VPN-Erklärung, „Überspringen“ gleichwertig sichtbar, keine Dark Patterns | **in Arbeit, NOT_TESTED** |
| Sir Quacksec | Willkommens-Overlay, einmal pro Start, per D-Pad überspringbar, kurze Motion, keine Audio-/Netzpflicht | **in Arbeit, NOT_TESTED** |
| TI-Sync-Modal | Fortschritt completed/total, Logo dezent, Fehler/Stale ehrlich, kein Fake-Fortschritt | **in Arbeit, NOT_TESTED** |

Asset: `res/drawable-nodpi/sir_quacksec.png` (vom Nutzer bereitgestellt, 749×820;
Provenienz im SBOM). Kartenhintergrund: `world_map_ambient.png` (2560×1280, byte-identisch aus
dem Mobile-Dossier). V2-Screenshots sind **noch nicht vorhanden**; sie werden erst nach
Bereitstellung unter `docs/screenshots/` referenziert.
