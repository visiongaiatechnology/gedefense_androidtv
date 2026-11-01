# GeDefense Titan TV — Architektur (V3 / Titan Engine)

| Attribut | Wert |
| :--- | :--- |
| **Produkt / Release** | GeDefense TV **0.3.0-alpha1**, VersionCode **4** („Titan Engine“, V3) |
| **Module** | `:tv-core` (Pure-JVM-Domäne) · `:app` (Android-Plattform, UI) · `:core` (vendored, unverändert) |
| **Pakete** | `de.visiongaia.gedefense.tv.core.titan.*` (`:tv-core`), `de.visiongaia.gedefense.tv.platform.titan.*`, `…contract.TitanApi`, `…ui.screens` (`:app`) |
| **Konzeptquelle** | [docs/TITAN-TV-CONCEPT.md](TITAN-TV-CONCEPT.md) (Masterkonzept, byte-identisch zum Brain-Dokument) |
| **Status** | **Verifiziert:** Domain-Harness (6624/0), Build/Lint/Release (Exit 0), Level-1-Emulator, Witness-Runtime (lokal). **Offen:** Level 3 (Root) = NOT_TESTED, reale TV-Hardware, Produktions-Signatur. |
| **Dokumenttyp** | Technische Architektur, abgeglichen mit dem tatsächlichen Code — keine Markt-/Feature-Behauptungen |

**Evidenzregel dieses Dokuments:** Was hier als „implementiert“ beschrieben wird, ist im Quellcode
vorhanden und wurde vom Doku-Team gelesen. Was nicht gelaufen ist (Level-3-Root-Lauf, reale
TV-Hardware, echtes 2K-/4K-Framebuffer, Fuzz-/Negativtests), steht ausdrücklich als **NOT_TESTED**
und wird nicht als Erfolg behauptet. Belegte Läufe (JVM-Harness 6624/0, Build/Lint/Release,
Level-1-Emulator, lokale Witness-Runtime, Übersetzungscheck) sind mit Zahlen in §13 dokumentiert;
die verbindliche Abnahme führt der Lead ([TEST-PLAN.md](../TEST-PLAN.md) §9.4).

---

## 1. Zielbild und Abgrenzung

Titan erweitert GeDefense TV um eine **dynamische, privilegienabhängige Endpoint-Sicht**. Die App
bleibt **ein einziges APK**: Es gibt keinen separaten Root-Fork. Zur Laufzeit wird ermittelt, welche
Fähigkeiten das konkrete Gerät tatsächlich hergibt, und die UI zeigt ausschließlich die *effektiv*
verfügbaren Fähigkeiten.

Titan ersetzt **kein** EDR/XDR mit Kernel-Sensor und behauptet keinen vollständigen Schutz. Die
Grenzen sind Produktbestandteil (Zero Snake Oil):

| Titan kann (nur bei bestätigter Fähigkeit) | Titan kann nicht / behauptet nicht |
| --- | --- |
| Socket→Prozess→Paket-Zuordnung soweit `/proc` lesbar ist | Vollständige Netzwerksicht auf fremde Apps (Level 1/2) |
| FIM-Delta gegen persistente Plant-Pfade (`/data/local/tmp`, `/system/bin`, …) | Unveränderbarkeit von `/system` oder Beweis „kein Rootkit“ |
| Reversible Containment-Aktionen über eine *allow-listete* Shell (Ausnahme: expliziter ADB-Lockdown) | Freie Shell-Kommandos, Löschen von Partitionen, Persistenz-Unterdrückung |
| Lokale, signierte Witness-Checkpoints der Evidenzkette | Push-/Netzwerkzustellung an ein Smartphone (Alpha-Gap) |
| Ehrliche Status-/Capability-Anzeige je Privilegstufe | Automatische Eskalation, stilles Root, „Garantie“ gegen Malware |

**Nicht-Ziele in 0.3.0-alpha1:** Shizuku-Binder-Kommando-Bridge (nur Erkennung), Mobile-Pairing/
Push-Zustellung, Quarantäne-Verschlüsselung der Binärdaten (nur Metadaten-MAC-Kette), Löschen von
Funden/Dateien, Kernel-/Syscall-Monitoring.

---

## 2. Drei-Stufen-Privilegmodell (Code: `titan/model/TitanPrivilege.kt`, `TitanCapabilityMatrix.kt`)

### 2.1 Stufen und Bedeutung

| Stufe | Enum | Voraussetzung | Bedeutung im Code |
| --- | --- | --- | --- |
| Level 1 | `TitanPrivilegeLevel.STANDARD` | jede TV-App, kein Sonderrecht | Alle Titan-Capabilities **leer**; Sichtbarkeit `PARTIAL` |
| Level 2 | `TitanPrivilegeLevel.SHIZUKU` | Shizuku/ADB-Bridge **erreichbar** | Nur Erkennung; **keine Kommandoausführung** in dieser Alpha |
| Level 3 | `TitanPrivilegeLevel.ROOT` | `su`-Kanal **vom Nutzer bestätigt** (`rootShellConfirmed`) | Alle Capabilities; Sichtbarkeit `FULL` |

**Zentrale Ehrlichkeitsregel:** Eine Stufe über `STANDARD` ist niemals das Ergebnis einer Datei-
oder Einzelprobe, sondern setzt einen **bestätigten Kommandokanal** voraus. Das wird im
Datenmodell erzwungen (`TitanPrivilegeSnapshot.init`):

- `level == ROOT` ⇒ `rootShellConfirmed == true`,
- `level == SHIZUKU` ⇒ `shizukuBridgeAvailable == true`,
- `rootShellConfirmed` ⇒ Stufe `ROOT` oder `SHIZUKU`.

### 2.2 Root-Qualität (Dirty-Root-Audit)

`TitanRootKind` unterscheidet `NONE`, `MANAGED`, `DIRTY`, `UNKNOWN`.

- `TitanPrivilegeSnapshot.dirtyRootSuspected` ist wahr, wenn `su`-Kandidaten existieren **und** kein
  bekannter Root-Manager gefunden wurde. Ein Dirty Root ist ein **eigener Sicherheitsbefund**
  (typisch für vorkonfigurierte Billig-TV-Boxen: jede App kann `su` ohne Prompt nutzen). Er hebt die
  Privilegstufe **nicht** an und wird als Note/Befund ausgewiesen.
- `TitanBuildIntegrity` ist passiv lesbar (ohne Privileg): `testKeys`, `debuggableBuild`,
  `selinuxEnforcing` (tri-state), `adbTcpExposed`, `selinuxRaw` (≤ 32 Zeichen, nie Nutzereingabe).

### 2.3 Theoretische vs. effektive Fähigkeiten

`TitanCapabilityMatrix` trennt bewusst zwei Begriffe:

| Stufe | `theoreticalCapabilities` | `effectiveCapabilities` |
| --- | --- | --- |
| `STANDARD` | leer | immer leer |
| `SHIZUKU` | `SOCKET_PROVENANCE`, `APP_FREEZE` | nur bei `shizukuBridgeAvailable == true` |
| `ROOT` | alle 7 Capabilities | nur bei `rootShellConfirmed == true` |

Effektive Sichtbarkeit ist `FULL` **nur** bei bestätigtem Root-Kanal, sonst `PARTIAL`. **UI, Report
und Evidenz dürfen ausschließlich die effektive Menge konsumieren.** Das ist der zentrale
Zero-Snake-Oil-Guard: Ein gefundenes `su`-File schaltet nichts frei.

**Alpha-Realität Level 2:** Die theoretische Shizuku-Menge enthält `SOCKET_PROVENANCE` und
`APP_FREEZE`, aber es gibt in `0.3.0-alpha1` **keine Shizuku-Binder-Kommando-Bridge**. Der einzige
Aktivierungspfad (`TitanController.activate`) setzt `shizukuBridgeAvailable` bei reinem
Shizuku-Fund ausdrücklich auf `false` und meldet „Bridge nicht verfügbar“ (`NOTE_SHIZUKU_BRIDGE_MISSING`).
Level 2 ist damit **detection-only** und erreicht nie effektive Capabilities; FIM-/Socket-Lesevorgänge
setzen den bestätigten Root-Kanal voraus.

### 2.4 Capability-Katalog

| Capability-ID | Enum | Bedeutung | Stufe (theoretisch) |
| --- | --- | --- | --- |
| `socket-provenance` | `SOCKET_PROVENANCE` | Socket→PID→Paket-Zuordnung + Feed-Abgleich | Shizuku/Root |
| `deep-inventory-fim` | `DEEP_INVENTORY_FIM` | FIM-Delta auf persistenten Plant-Pfaden | Root |
| `app-freeze` | `APP_FREEZE` | reversible App-Deaktivierung/Reaktivierung | Shizuku/Root |
| `network-quarantine` | `NETWORK_QUARANTINE` | UID-basierte Outbound-Quarantäne (iptables) | Root |
| `adb-lockdown` | `ADB_LOCKDOWN` | ADB-over-TCP-Port schließen | Root |
| `process-kill` | `PROCESS_KILL` | einzelnen Prozess beenden | Root |
| `quarantine-vault` | `QUARANTINE_VAULT` | Binary in geschützten Vault verschieben | Root |

---

## 3. Modulübersicht (6 Module)

| # | Modul | Domäne (`:tv-core`) | Plattform (`:app`) |
| --- | --- | --- | --- |
| 1 | **Privilege-Gate & Dirty-Root-Audit** | `TitanPrivilegeLevel`, `TitanPrivilegeSnapshot`, `TitanBuildIntegrity`, `TitanCapabilityMatrix` | `platform/titan/privilege/TitanPrivilegeGate` |
| 2 | **Socket-Provenance (C2/Botnet)** | `RawSocket`, `SocketObservation`, `SocketSnapshot`, Parser-/Engine-Typen | `platform/titan/collect/TitanSocketCollector` |
| 3 | **FIM / Anti-Planting** | `FimStatus`, `FimBaseline`, `FimSnapshot`, `FimConfig`, `TitanFimPolicy` | `platform/titan/collect/TitanFimCollector` + `TvTitanStore` |
| 4 | **Response-Engine (Containment)** | `TitanShellCommand`, `TitanCommandFactory`, `TitanContainmentPolicy`, `TitanActionResult` | `platform/titan/privilege/TitanShell` + `TitanResponseEngine` |
| 5 | **Witness-Protokoll** | `TitanWitnessCheckpoint`, `TitanWitnessStatus`, `witness/TitanWitnessCheckpointFactory` | `TvTitanStore`-Persistenz, kein Netzwerk-Pairing |
| 6 | **TITAN-LIVE-UI** | `TitanStatus`, `TitanStatusComposer` | `contract/TitanApi`, `data/titan/TitanController`, Screen `TitanScreen` (`TvRoute.TITAN`), Home-Strip |

Regel: Die Domäne bleibt **Android-frei** (keine `android.*`-Imports, keine Dateisystemzugriffe).
Alle `/proc`, `su`, Keystore- und Storage-Zugriffe liegen in `:app`.

---

## 4. Domänenmodell in `:tv-core`

### 4.1 Socket-Provenance (`titan/model/TitanSocket.kt`)

```text
/proc/net/tcp|tcp6|udp|udp6  ──►  RawSocket (protokoll, addrs, ports, state, uid, inode)
                                        │
/proc/<pid>/fd  ──► inode→PID ──────────┤  join über inode
/proc/<pid>/status ──► UID→Paket ───────┤
                                        ▼
                              SocketObservation
                       (+ risk, threatFeedIds, severity, packageName?)
                                        │
                                        ▼
                                  SocketSnapshot (bounded ≤ 512 Beobachtungen)
```

| Typ | Inhalt / Invariante |
| --- | --- |
| `SocketProtocol` | `TCP`, `TCP6`, `UDP`, `UDP6`; mappt auf `/proc/net/<file>`; `isV6`, `isStream` |
| `SocketState` | 12 Zustände inkl. `ESTABLISHED`, `LISTEN`, `TIME_WAIT`, `UNKNOWN`; `isConnected` |
| `SocketRisk` | `NONE`, `THREAT_FEED_MATCH` (nur feed-belegt), `UNATTRIBUTED` (Sichtbarkeitslücke, **kein** Malware-Urteil), `ADB_EXPOSED` |
| `RawSocket` | Ports 0–65535, UID ≤ 2 000 000 000, Inode ≥ 0 |
| `SocketObservation` | `pid` und `packageName` dürfen `null` sein (nicht zuordenbar); Feed-IDs nur bei `THREAT_FEED_MATCH`; `subject` = Paket / Remote:Port / Protokoll für Evidenz/Dedupe |
| `SocketSnapshot` | `observations ≤ 512`, `attributableSockets ≤ totalSockets`, `truncated`-Flag, `visibility`, `note` |
| `SocketProvenanceConfig` | harte Caps: `maxSockets 4096`, `maxObservations 512`, `maxProcessEntries 4096`, `adbPort 5555` |

**Parser (`titan/proc/ProcNetParser`, pure JVM):** liest die Kernel-Tabellen als Text und dekodiert
jede Zeile feldweise (`sl`, lokal, remote, `st`, UID, Inode). Eigenschaften:

- dekodiert IPv4 (Little-Endian-Wort → Dotted Quad) und IPv6 (vier Little-Endian-Wörter → RFC-5952-
  Kompaktform), Ports aus Hex;
- `st` wird auf die dokumentierten Zustände abgebildet, alles andere ist `UNKNOWN` — der Parser
  „rät“ keinen Zustand;
- fehlerhafte Zeilen werden **übersprungen**, nie geworfen; Zeilen-/Zeilenanzahl-Caps
  (`DEFAULT_ROW_CAP 4096`, `MAX_SCAN_LINES 65536`) machen feindliche/abgeschnittene Tabellen harmlos;
- `parseAll` verarbeitet in fester Reihenfolge TCP → TCP6 → UDP → UDP6 (deterministisch).

**Engine (`titan/proc/SocketProvenanceEngine`, pure JVM):** korreliert dekodierte Kernel-Zeilen mit
Prozess-/Paket-Herkunft und Threat-Index. Verbindliche Regeln:

- **Aufnahme:** nur „lebende“ Verbindungszustände plus ein `LISTEN` auf dem ADB-Port
  (`SocketProvenanceConfig.adbPort`, Default 5555); idle `LISTEN`/`CLOSE`/`TIME_WAIT` und
  `0.0.0.0:0`/`::0`-Remote-Ziele sind keine Outbound-Beobachtungen und werden übersprungen.
- **Attribution:** primär die UID aus der Socket-Tabelle; nur bei UID `0` (unset) fällt die Engine
  auf `uidByPid[pid]` zurück. PID kommt aus dem Inode-Join; Paket ist der lexikografisch kleinste
  gültige Kandidat der effektiven UID (deterministisch).
- **Bewertung:** Threat-Index-Match ⇒ `THREAT_FEED_MATCH` (`CRITICAL`); ADB-Port ⇒ `ADB_EXPOSED`
  (`HIGH`); fehlende PID/Paket ⇒ `UNATTRIBUTED` (`MEDIUM`); sonst `NONE` ohne Severity.
- **Sichtbarkeit (Zero Snake Oil):** `FULL` nur bei **nicht abgeschnittenem** Pass **und** mehr als
  der Hälfte zuordenbarer Beobachtungen; sonst `PARTIAL`. Jede Überschreitung von Socket-/Prozess-/
  Beobachtungs-Cap setzt `truncated`; ein gekappter Pass kann nie `FULL` werden.

**Ehrlichkeitsgrenze:** Auf Level 1 ist `/proc/<pid>/fd` fremder Prozesse nicht lesbar; der
reguläre Collector-Pfad ist der bestätigte Root-Kanal. Nur wenn dieser fehlschlägt **und**
`/proc/net/*` für diesen Prozess lesbar ist, liest der Collector die Tabelle direkt — dann
ausdrücklich `PARTIAL` (keine Vollständigkeitsbehauptung). Nicht zuordenbare Sockets werden als
`UNATTRIBUTED`/„App unbekannt“ geführt, **nie** als vertrauenswürdig.

### 4.2 FIM / Anti-Planting (`titan/model/TitanFim.kt`)

Feste, **nicht nutzerkonfigurierbare** Watch-Policy (`TitanFimPolicy.DEFAULT_ROOTS`):

| Pfad | rekursiv | maxDepth | Begründung |
| --- | --- | --- | --- |
| `/data/local/tmp` | ja | 2 | häufigster Ablageort für Exploits/Miner |
| `/system/bin` | nein | 1 | Systemintegrität |
| `/system/xbin` | nein | 1 | Systemintegrität |
| `/vendor/bin` | nein | 1 | OEM-/Vendorintegrität |
| `/system/etc/init` | nein | 1 | Boot-Persistenz |
| `/data/adb/modules` | ja | 3 | Magisk-Modul-Persistenz |

| Typ | Inhalt / Invariante |
| --- | --- |
| `FimStatus` | `BASELINE_CREATED`, `MATCHES_BASELINE`, `NEW_FILE`, `MODIFIED`, `UNREADABLE` |
| `FimWatchRoot` | Pfad muss `TitanFimPolicy.isSafeAbsolutePath` genügen; `maxDepth ∈ 0..6` |
| `FimFileObservation` | `sha256` ist genau dann `null`, wenn `UNREADABLE`; Status/Hash/Rechte-Format validiert |
| `FimScannedFile` | Plattform-Eingabe (Pfad, Watch-Root, Größe, mtime, Rechte, `readable`, optional Hash) — Domäne hasht nicht selbst |
| `FimBaseline` / `FimBaselineEntry` | ≤ 4096 Einträge, Pfade eindeutig — Basis für Delta |
| `FimSnapshot` | ≤ 512 Beobachtungen, Zähler `newFiles`/`modifiedFiles`/`unreadableFiles`/`scannedFiles`, `deltaCount` |
| `FimConfig` | `maxFilesPerRoot 512`, `maxTotalFiles 2048`, `maxHashBytes 64 MiB`, Roots ≤ 32 |

Die Domäne berührt **nie** das Dateisystem: `:app` hasht lesbare Dateien und übergibt
`FimFileObservation`. Unlesbare Einträge bleiben `UNREADABLE` — kein stilles „clean“.

**Engine (`titan/fim/FimEngine`, pure JVM):** vergleicht eine gescannte Dateiliste
(`FimScannedFile`) gegen die persistierte `FimBaseline` und liefert `FimComparison` (Snapshot +
neu zu persistierende Baseline + `baselineChanged`). Regeln:

- erster Lauf ⇒ `BASELINE_CREATED` für lesbare Dateien; danach `MATCHES_BASELINE` bei gleichem
  SHA-256 **und** gleicher Größe, sonst `MODIFIED`; unbekannter Pfad ⇒ `NEW_FILE`;
  `readable == false` ⇒ `UNREADABLE` (nie eine Baseline-Zeile löschen);
- **keine Lösch-Erkennung:** fehlende Baseline-Einträge werden beibehalten („no deletion claim“);
- harte Bounds (`maxFilesPerRoot`, `maxTotalFiles`, `MAX_ENTRIES`, `MAX_OBSERVATIONS`) mit
  `truncated`-Signal; deterministische Sortierung (Delta zuerst, dann Pfad);
- Sichtbarkeit `FULL` nur ohne unlesbare Einträge und mit mindestens einer Beobachtung.

### 4.3 Containment-Modell (`titan/model/TitanContainment.kt`)

| Typ | Inhalt |
| --- | --- |
| `TitanContainmentAction` | `FREEZE_APP`, `RESTORE_APP`, `ISOLATE_NETWORK_UID`, `RELEASE_NETWORK_UID`, `KILL_PROCESS`, `CLOSE_ADB_PORT`; `isReversible` ist für alle außer `CLOSE_ADB_PORT` wahr (dort ausdrücklich explizit/nicht still) |
| `TitanActionReason` | `USER_INITIATED`, `C2_SOCKET`, `UNATTRIBUTED_SOCKET`, `FIM_TAMPER`, `ADB_EXPOSURE` (Evidenz-Kontext) |
| `TitanActionFailure` | `NOT_AUTHORIZED`, `NOT_SUPPORTED`, `INVALID_TARGET`, `PROTECTED_TARGET`, `RATE_LIMITED`, `LIMIT_REACHED`, `COMMAND_FAILED`, `VERIFICATION_FAILED`, `UNAVAILABLE` |
| `TitanActionTarget` | mindestens eine ID (`packageName`/`uid`/`pid`), Regex-/Bereichsvalidierung |
| `TitanActionResult` | `ok`, `verified`, `failure`, einzeiliges `detail` ohne Secrets; `ok == false` ⇒ `failure != null` |
| `TitanVaultEntry` | UUID, Dateiname, Original-Pfad (nur Watch-Root), SHA-256, Größe, Zeit, Rechte |

### 4.4 Status / Scan-Modell (`titan/model/TitanStatus.kt`, `TitanStatusComposer.kt`)

`TitanStatus` ist der **einzige** Zustand, den UI, Report und Evidenz konsumieren:

| Feld | Bedeutung |
| --- | --- |
| `level`, `visibility` | effektive Stufe/Sichtbarkeit (nicht theoretisch) |
| `capabilities` | effektive `TitanCapability`-Menge |
| `privilege`, `sockets`, `fim` | letzte Snapshots (stale = eigener Capture-Zeitstempel, nicht umgedeutet) |
| `witness` | `UNAVAILABLE`/`READY`/`PAIRED`/`DEGRADED` (siehe §7) |
| `activeContainments` | Anzahl aktiver Containments |
| `lastScanOutcome` | `NEVER`/`RUNNING`/`COMPLETED`/`PARTIAL`/`FAILED` |
| `attentionRequired` | abgeleitet: C2-Treffer **oder** FIM-Delta > 0 **oder** Dirty-Root-Verdacht |

`TitanStatusComposer.compose(...)` ist pur und deterministisch: Es erfindet kein Ergebnis für ein
Modul, das nicht lief, leitet die Capability-Menge aus dem bestätigten Snapshot ab, sammelt
Hinweise (`MessageRef`) in stabiler Reihenfolge und setzt die **Gesamt-Sichtbarkeit auf das
schwächste erfolgreich gelaufene Modul** (ein `PARTIAL`-Socket- oder FIM-Pass kann keine
`FULL`-Gesamtsicht erzeugen). `TitanStatus.empty()` ist der ehrliche Startzustand (`STANDARD`,
`PARTIAL`, keine Capabilities, `NEVER`).

### 4.5 Root-Shell und Containment-Gate (`titan/response/`)

**`TitanShellCommand`** ist die einzige ausführbare Einheit. Invarianten:

- Programm muss in `ALLOWED_PROGRAMS` stehen: `pm`, `am`, `iptables`, `setprop`, `stop`, `kill`,
  `chmod`, `mv`, `mkdir`, `cmd`, `getprop`, `id` sowie die **nur lesenden** Introspectionsbefehle
  `find`, `stat`, `sha256sum`, `cat`, `ls` (für FIM-/`/proc`-Collector über den Root-Kanal). Die
  Allowlist enthält **kein destruktives Werkzeug** (kein `rm`, `dd`, `mkfs`, `mount`, `sh`).
- Jedes Argument muss `[A-Za-z0-9_./:@+=,%-]+` (≤ 512 Zeichen) erfüllen; max. 16 Argumente.
- Kein generisches `exec`; keine freien Strings; `auditLine()` ist secret-frei (Tag + Programm).

**`TitanCommandFactory`** erzeugt nur die feste, reversible Aktionsmenge:

| Aktion | Kommando (Auszug) | Verifikationsprobe |
| --- | --- | --- |
| Freeze | `pm disable-user --user 0 <pkg>` | `cmd package list packages -d` |
| Restore | `pm enable <pkg>` | — |
| Force-Stop | `am force-stop <pkg>` | — |
| UID-Quarantäne | `iptables -w -I OUTPUT 1 -m owner --uid-owner <uid> -j DROP` | `iptables -w -L OUTPUT -n -v` |
| UID-Freigabe | `iptables -w -D OUTPUT …` | dieselbe |
| Prozess-Kill | `kill -9 <pid>` (PID ≥ 2) | `kill -0 <pid>` |
| ADB-Lockdown | `setprop service.adb.tcp.port -1` + `stop adbd` | `getprop service.adb.tcp.port` |
| Vault | `mkdir -p /data/local/gedefense_vault` + `chmod 700`; `mv <watched> → vault`; `chmod 000` | — |
| FIM-Lesen | `find <root> -maxdepth <n> -type f -print`, `stat -c %a:%s:%Y`, `sha256sum -- <path>` | — |
| Socket-Lesen | `cat /proc/net/<table>`, `ls -ln /proc/<pid>/fd`, `cat /proc/<pid>/status` | — |

Zielvalidierung: Paketnamen per Regex, UID **nur ≥ 10 000** (keine System-UIDs), PID ≥ 2,
Vault-Quelle nur innerhalb der Watch-Policy, Dateiname `[A-Za-z0-9._-]{1,128}`. Lese-Kommandos sind
auf `/proc/`, `/sys/`, FIM-Watch-Roots bzw. `/data/`-Verzeichnislisten begrenzt (`readProcTable`,
`listDirectory`, `statFile`, `sha256File`, `readProcessStatus`). Kein `..`, keine
Shell-Metazeichen. **Es gibt keinen Löschbefehl** — Quarantäne ist Verschieben + Rechte-Entzug.

**`TitanContainmentPolicy`** ist das Fail-Safe-Gate *vor* jeder Ausführung:

1. Zielstruktur je Aktion prüfen (`INVALID_TARGET`),
2. Capability der Aktion muss in der **effektiven** Menge liegen (`NOT_AUTHORIZED`),
3. geschützte Ziele ablehnen (`PROTECTED_TARGET`): System-/Launcher-/Settings-/IME-Pakete,
   eigene UID/PID, PID 1, UID < 10 000,
4. Limit aktiver Containments (`LIMIT_REACHED`, Default 16),
5. Rate-Limit (`RATE_LIMITED`, Default 8 Aktionen / 60 s Fenster; Historie begrenzt).

Die Standardliste geschützter Pakete umfasst u. a. `android`, `com.android.systemui`,
`com.android.settings`, `com.android.tv.settings`, `com.android.shell`, beide PackageInstaller,
`com.android.vending`, `com.google.android.gms/gsf`, TV-Provider/-Launcher und beide Standard-IMEs.
Das ist die **No-Brick-Schicht**: Ein versehentlich deaktiviertes Nutzer-Medienpaket ist per
Fernbedienung wiederherstellbar; Systemkomponenten sind per Design unerreichbar.

---

## 5. Plattformadapter in `:app`

| Baustein | Aufgabe | Stand |
| --- | --- | --- |
| `platform/titan/privilege/TitanPrivilegeGate` | passive Privilegdetektion (`su`-Pfade, Root-Manager-Marker, SELinux, test-keys, ADB-TCP, Shizuku-Präsenz); liefert `TitanPrivilegeSnapshot` ohne Prompt | integriert — **Level 1 belegt (keine Marker)**, Level 3 **NOT_TESTED** |
| `platform/titan/privilege/TitanShell` | kontrollierter Executor für allow-listete Kommandos über den bestätigten `su`-Kanal; führt nur `TitanShellCommand` aus | integriert — **Laufzeit NOT_TESTED** |
| `platform/titan/privilege/TitanResponseEngine` | Policy-Gate → Plattform-Zielguard → Ausführung → Verifikationsprobe → `TitanActionResult` | integriert — **Laufzeit NOT_TESTED** |
| `platform/titan/privilege/TitanResponseGuards` | `TitanTargetGuard` (System-UID < 10 000, aufgelöster Launcher/Settings/IME), `TitanVaultGuard` (Symlink-Vorprüfung des Vault-Pfads), `TitanProcessProbe` (Absenz über `/proc/<pid>/status`, nur ENOENT = weg) | integriert — **Laufzeit NOT_TESTED** |
| `platform/titan/collect/TitanSocketCollector` | liest `/proc/net/{tcp,tcp6,udp,udp6}` (über den bestätigten Kanal), mappt Inode→PID→UID→Paket, gleicht mit `ThreatIndex` ab | integriert — **Laufzeit NOT_TESTED** |
| `platform/titan/collect/TitanFimCollector` | Walker über die festen Watch-Roots, SHA-256/Rechte, Delta gegen persistierte Baseline | integriert — **Laufzeit NOT_TESTED** |
| `data/TvTitanStore` | Persistenz von letztem Titan-Status, FIM-Baseline, Vault-Metadaten, Witness-Sequenz/Checkpoint | integriert — **Laufzeit NOT_TESTED** |
| `data/titan/TitanController` | Implementierung von `TitanApi`: ein begrenzter Worker-Thread (`gedefense-titan`, `MIN_PRIORITY`), gecachter UI-Status, Scan-/Aktivierungs-/Aktionspfad, Evidenz-Anbindung | integriert — **Level 1 belegt** (`titan scan ms=445 level=STANDARD caps=0`), Level 3 **NOT_TESTED** |
| `data/titan/TitanEvidenceRecorder` | bounded Evidenz-Schreiber: nur die wichtigsten Zeilen (Privileg, Threat-Treffer, unattributierte Sockets, ADB, FIM-Delta, Containment, Witness) mit hartem Per-Scan-Cap; wirft nie in den Scan-Pfad | integriert — **Laufzeit NOT_TESTED** |
| `data/titan/TitanWitnessCoordinator` | erzeugt/persistiert lokale Witness-Checkpoints aus dem Ledger-Tail; `READY` ohne `PAIRED`-Behauptung; fail-soft ohne Key-Custody/leeres Ledger | integriert — **Laufzeit NOT_TESTED** |
| `contract/TitanContracts.kt` (`TitanApi`) | UI-Vertrag: `status`, `scanNow`, `refreshPrivilege`, `activate`, `contain`, `vaultEntries`, `witnessStatus`, `latestCheckpoint`, `refreshWitnessCheckpoint` | integriert |
| `TvServices` | Container um `titan: TitanApi` erweitert (Bootstrap/Test-Konstruktor) | integriert |
| UI `TITAN LIVE` + Home-Strip | neuer Reiter `TITAN` (`TitanScreen`) mit D-Pad-Containment; kompakter Titan-Status im Home-Screen | integriert — **Level-1-Rendering + Screenshots belegt**; Level-3-Containment-UI **NOT_TESTED** |
| Lokalisierung | Titan-Texte in **7 Locale-Verzeichnissen** (Basis + 6 Übersetzungen) | integriert — Übersetzungscheck **PASS** (0 Probleme, je 890 String-Keys, je 9 Plural-Gruppen) |

**Collector-Details (honest gating zuerst):**

- `TitanSocketCollector` liefert ohne effektive `SOCKET_PROVENANCE`-Capability einen expliziten
  leeren `PARTIAL`-Snapshot mit Katalog-Note (nie „clean“). Gelesen wird über den bestätigten
  Root-Kanal und die allow-listete `readProcTable`-Aktion. Nur wenn der Kanal fehlschlägt **und**
  die Datei für diesen Prozess lesbar ist, wird `/proc/net/*` direkt per `File` gelesen — dann
  ausdrücklich `PARTIAL`, weil ein unprivilegierter Tabellenread keine vollständige Abdeckung
  beweisen kann. Kernel-Inhalte sind hostile Input: Byte-Caps, `ProcNetParser`, keine
  Parser-Exception nach außen.
- `TitanFimCollector` liefert ohne effektive `DEEP_INVENTORY_FIM` einen leeren `PARTIAL`-Snapshot.
  Mit Capability laufen alle Dateisystemzugriffe über den Root-Kanal mit rein lesenden Kommandos
  (`find`, `stat`, `sha256sum`); Pfade werden gegen FIM-Policy/Root validiert, Fremdpfade verworfen.
  Dateien über `FimConfig.maxHashBytes` gelten als unlesbar (`truncated`), das gesamte Pass hat ein
  Wall-Clock-Budget; die Baseline wird aus `TvTitanStore` geladen, per `FimEngine` verglichen und
  bei Änderung persistiert.

**Kanal-Executor (`TitanShell`):** führt ausschließlich `TitanShellCommand` aus, als
`su -c "<shellLine>"`. Sicherheitsdetails:

- `su` wird aus einer **festen Kandidatenliste** aufgelöst (`/system/bin/su`, `/system/xbin/su`,
  `/sbin/su`, `/data/local/xbin/su`, …), nicht aus dem geerbten `PATH`; nur wenn kein Kandidat
  existiert, fällt der Executor auf den Namen `su` zurück.
- `TitanBoundedProcess` ist der **einzige Prozess-Ausführungspunkt** („chokepoint“): zugelassen
  sind exakt drei Aufruf-Formen — `su -c <zeile>` (Zeile wird erneut gegen Charset und
  `ALLOWED_PROGRAMS` geprüft, max. 8192 Zeichen, max. 4 argv-Elemente), `getenforce` (ohne
  Argumente) und `getprop <property>` (Property-Name per Regex). Alles andere wird **vor**
  `ProcessBuilder` abgelehnt.
- Kindprozesse erhalten keine zusätzlichen Nutzdaten, laufen in einem App-eigenen
  Arbeitsverzeichnis und haben ein hartes Wall-Clock-Timeout (Probe 5 s, Ausführung 8 s; clamp
  250 ms–30 s) sowie harte Ausgabegrenzen (`execute` 64 KiB, Tabellenlesen 256 KiB, clamp
  512 B–512 KiB); ein Drain-Thread verwirft Überlauf, Timeout killt den Prozess forciert.
- `readTable` liefert `null` bei „nicht gestartet“, Timeout, Exit ≠ 0 oder Truncation — eine
  abgeschnittene Tabelle wird **nicht** als vollständig geparst.
- Kommando-Argumente und Rohausgabe werden **nie** geloggt; im Log erscheint nur der `auditTag`.
- Fehler werden zu `TitanShellResult` mit explizitem `TitanActionFailure`; keine Methode wirft bei
  fehlendem `su`, hängendem Prompt oder gekilltem Prozess. `ok` bedeutet nur „Prozess lief mit
  Exit 0“ — die Wirkungsprüfung ist ein separater Schritt im `TitanResponseEngine`.

**Keine neuen Android-Berechtigungen:** Titan nutzt ausschließlich passive Detektion und den
vom Nutzer bestätigten `su`-Shell-Kanal; es werden keine neuen Permissions ergänzt. Das Manifest
erhält gezielte `<queries>`-Pakete für bekannte Root-Manager (`com.topjohnwu.magisk`,
`me.weishu.kernelsu`, `me.bmax.apatch`, `eu.chainfire.supersu`) und Shizuku
(`moe.shizuku.privileged.api`), damit Package Visibility „nicht sichtbar“ nicht als „nicht
vorhanden“ fehldeutet — **kein** `QUERY_ALL_PACKAGES`.

**Threading-Vertrag (`TitanApi`):** `status()`, `state()`, `vaultEntries()`, `witnessStatus()`
sind gecachte O(1)-Lesezugriffe für den UI-Thread. `scanNow`, `refreshPrivilege`, `activate`,
`contain` laufen auf dem begrenzten Hintergrund-Worker und melden über Listener auf dem
Main-Thread. `scanNow` lehnt parallele Läufe mit `false` ab (AtomicBoolean-Guard).

**Einstellungen (persistiert in `TvSettingsStore`):** `titan.consent_granted` (Default **false** —
nur nach erfolgreicher `activate()` gesetzt), `titan.socket_guard_enabled` (Default **true**),
`titan.fim_guard_enabled` (Default **true**). Ein Scan wiederholt die Root-Bestätigung nur, wenn der
Consent bereits erteilt wurde und `su`-Kandidaten vorhanden sind; sonst bleibt er passiv. Guards
werden in der UI erklärt und sind abschaltbar; ohne effektive Capability erzeugen sie leere
Snapshots mit `PARTIAL` statt Falschaussagen.

**Honesty-Vertrag des Contracts:** Ein Scan hebt **nie** die Privilegstufe an und triggert **nie**
einen Root-Prompt. Nur `activate()` — eine ausdrückliche Nutzeraktion mit Consent — darf die
Root-Bestätigungsprobe (`id` über den Root-Kanal) ausführen. Verweigert der Nutzer, bleibt die
Stufe `STANDARD` und jede erhöhte Capability meldet „nicht verfügbar“. Ein `su`-Prompt im
Hintergrund ist damit strukturell ausgeschlossen. Passive Scans wiederholen die Root-Probe nur,
wenn der Nutzer bereits einmal zugestimmt hat.

**Lesegrenzen:** FIM- und Socket-Lesevorgänge laufen regulär über den bestätigten Root-Kanal
(Android-`/proc`-Restriktionen für fremde Prozesse). Ein Socket-Direktread ohne Kanal ist nur der
ausdrücklich `PARTIAL` gekennzeichnete Fallback; FIM hat keinen unprivilegierten Pfad. Auf Level 1
melden beide Module `PARTIAL` bzw. „nicht verfügbar“ — sie behaupten keine Sicht, die sie nicht
haben.

---

## 6. Vertrauensgrenzen und Bedrohungsdelta

Neu gegenüber V1/V2 (Details: [THREAT-MODEL.md](../THREAT-MODEL.md) §16 ff.):

| Grenze | Verlauf | Risiko | Gegenmaßnahme im Code |
| --- | --- | --- | --- |
| T-01 App ↔ Root-Shell | `su -c` mit allow-listeten Programmen | Injection, Zerstörung, Brick | `TitanShellCommand`-Charset + feste Programm-Whitelist + `TitanCommandFactory` ohne freie Strings |
| T-02 App ↔ `/proc` | fremde Prozess-/Socket-Metadaten | Falschzuordnung, Fehlalarm | Inode-Join, UID→Paket nur bei Lesbarkeit; `UNATTRIBUTED` statt Verdacht |
| T-03 App ↔ Dateisystem (FIM/Vault) | Watch-Roots, Vault-Pfad | Path-Traversal, Löschen | `isSafeAbsolutePath`, `isWatched`, kein Löschkommando, `chmod 000` |
| T-04 App ↔ Containment-Ziel | `pm`/`iptables`/`kill` auf fremde Apps | Brick, Selbstausschluss | Policy-Gate: geschützte Pakete, UID ≥ 10 000, PID ≠ 1/self, Rate-/Mengenlimits |
| T-05 App ↔ Evidenz | Titan-Ereignisse im Ledger | Beweislastumkehr/Fälschung | HMAC-Kette (Core), secret-freie Attribute, deterministische Factory |
| T-06 App ↔ Nutzer | Root-Consent, „geschützt“-Aussage | Scheinsicherheit | Effektiv-Capabilities, Notes, `attentionRequired`; keine Auto-Eskalation |

**Fähigkeitsgrenze, die dokumentiert bleiben muss:** Level 2 (Shizuku) ist in dieser Alpha
**detection-only**. Es gibt in `0.3.0-alpha1` keine Shizuku-Binder-Kommando-Bridge; die
theoretischen Shizuku-Capabilities werden nur dann effektiv, wenn ein real bestätigter Kanal
existiert — was ohne Bridge nicht der Fall ist. Root-Aktionen laufen ausschließlich über den
nutzerbestätigten `su`-Shell-Kanal.

---

## 7. Evidenz-Ereignisse (`titan/events/TitanEventFactory.kt`)

Alle Titan-Befunde werden als bestehende XDR-Lite-`TvEvent`s in die lokale HMAC-Evidenzkette
geschrieben. Feste Collector-/Rule-IDs:

| Collector | Rule | EventClass | Wann |
| --- | --- | --- | --- |
| `titan-gate` | `titan-root-audit` | `TV_DEVICE_STATE` | erhöhter Kanal, Dirty Root, SELinux permissive, test-keys, ADB exposed |
| `titan-socket` | `titan-c2-socket` | `TV_TI_MATCH` | Socket matcht ThreatIndex (Schwere `CRITICAL`) |
| `titan-socket` | `titan-unattributed-socket` | `TV_DEVICE_STATE` | nicht zuordenbarer Socket (Sichtbarkeitslücke) |
| `titan-socket` | `titan-adb-exposed` | `TV_DEVICE_STATE` | ADB-Port exponiert/listening |
| `titan-fim` | `titan-fim-delta` | `TV_ENFORCEMENT` | neuer/geänderter Eintrag in Watch-Root |
| `titan-response` | `titan-containment` | `TV_ENFORCEMENT` | jede ausgeführte **oder abgelehnte** Aktion |
| `titan-witness` | `titan-witness-checkpoint` | `TV_DEVICE_STATE` | lokaler Witness-Checkpoint erzeugt |

Eigenschaften: deterministisch (außer Event-UUID), bounded, secret-frei. Subjekt/Attribute werden
auf 160/256 Zeichen gekürzt, Zeilenumbrüche entfernt. Es werden **keine** Dateiinhalte, keine
vollständigen Socket-Tabellen und keine Nutzerdaten übernommen. Die Payload enthält nur
Klassifikation, Endpunkt, Paket-/UID-Bezug, Hash-Präfix und Fehlercode.

**Bounded Recorder:** `data/titan/TitanEvidenceRecorder` schreibt pro Scan nur die wichtigsten
Zeilen (Privilegzustand, Threat-Treffer, unattributierte Sockets, ADB-Exposure, FIM-Delta,
Containment, Witness) mit hartem Per-Scan-Cap und **wirft nie in den Scan-Pfad**; ein degradiertes
Ledger erscheint über die normale Evidenz-Gesundheitsanzeige.

---

## 8. Witness-Protokoll (Alpha-Stand)

| Aspekt | Stand 0.3.0-alpha1 |
| --- | --- |
| Checkpoint-Modell | `TitanWitnessCheckpoint(sequence, issuedAtMillis, ledgerDigestHex, macHex)` — beide Hex-Felder 64 Zeichen, validiert |
| Erzeugung | `titan/witness/TitanWitnessCheckpointFactory`: `ledgerDigest` = SHA-256 über `GD-WD-1\n` + je Zeile (atMillis, type, subject, pipe-getrennt) (max. 200 Zeilen); `macHex` = HMAC-SHA256 über `GD-TW-1\ndeviceId\nsequence\nissuedAtMillis\nledgerDigestHex` |
| Verifikation | recompute + `MessageDigest.isEqual` (konstante Vergleichszeit), fail-closed (`false` bei Format-/Key-/Provider-Fehler, nie eine Exception in die UI) |
| Zustand | `TitanWitnessState`: `UNAVAILABLE`, `READY`, `PAIRED`, `DEGRADED`; `UNAVAILABLE` = ehrlicher Default |
| Pairing / Mobile-Push | **nicht implementiert (Alpha-Gap)**. Es gibt kein QR-Pairing, keinen LAN-/mDNS-Transport und keine Push-Zustellung |
| Konsequenz | `PAIRED` wird **nie** ohne echten Gegenpart behauptet; `TitanWitnessStatus.ready(...)` trägt explizit die Note „nicht gekoppelt“ |

Damit ist die Formel aus dem Konzept (Heartbeat, Sofort-Eskalation aufs Smartphone) ausdrücklich als
spätere Stufe gekennzeichnet. Die lokale Checkpoint-Kette ist die ehrliche Vorstufe.

---

## 9. Fail-Safe- und No-Brick-Regeln (verbindlich)

1. **Kein Root-Exploit:** Titan erlangt keine Root-Rechte selbst; es nutzt ausschließlich einen
   vom Nutzer bestätigten Kanal.
2. **Keine Eskalation durch Beobachtung:** Scans/Anzeigen lösen nie einen `su`-Prompt aus.
3. **Kein Löschen, keine Partitionsschreibzugriffe:** Das Command-Factory-Enum enthält keine
   Delete-/Format-/Mount-Operation; Vault = `mv` + `chmod 000`.
4. **Jede Aktion reversibel** (Ausnahme: ADB-Lockdown, explizit nicht still) mit definiertem
   Inversen (`restoreApp`, `releaseUid`).
5. **Geschützte Ziele unerreichbar:** System-UI/Settings/Launcher/IME/Installer/GSF/Eigene UID/PID 1.
6. **Rate-/Mengenlimits:** max. 16 aktive Containments, 8 Aktionen/60 s.
7. **Capability-Gating vor Aktion:** Ohne effektive Capability wird nichts ausgeführt
   (`NOT_AUTHORIZED`).
8. **Kein stiller Fehler:** Fehlschläge tragen `TitanActionFailure` und werden als Evidenz
   protokolliert; `verified` unterscheidet „Befehl lief“ von „Wirkung geprüft“.
9. **Level 1 ohne Crash:** Fehlende Rechte führen zu `UNAVAILABLE`/leeren Capabilities, nicht zu
   Abstürzen oder falschen „geschützt“-Aussagen.
10. **Bounded alles:** Socket-/FIM-/Prozess-Caps, Argumentlängen, Notiz-/Feed-Anzahl, Rate-Limit.
11. **Recovery bleibt möglich:** `RESTORE_APP`/`RELEASE_NETWORK_UID` sind von Aktiv-/Rate-Limits
    ausgenommen — die Rücknahme einer Containment-Aktion darf nie durch ein Limit blockiert werden.
12. **Kein Kaltstart-Root-Vertrauen:** Ein persistierter ROOT-Status wird beim Kaltstart auf
    `STANDARD` zurückgesetzt; erneute nutzerbestätigte Aktivierung ist erforderlich.
13. **Plattform-Zielguard:** Zusätzlich zur Domänenliste werden System-UIDs (< 10 000) sowie der
    aufgelöste Launcher-, Settings- und IME-Paketname abgelehnt (OEM-Schutz).
14. **Vault-Pfad-Guard:** Vor dem ersten Root-Kommando wird geprüft, dass der feste Vault-Pfad fehlt
    oder ein echtes Verzeichnis ist (kein Symlink); die verbleibende TOCTOU-Lücke zwischen Prüfung
    und `mkdir`/`mv` ist dokumentiert.
15. **Absenz nur mit Beweis:** Ein Kill gilt erst als verifiziert, wenn `/proc/<pid>/status` echtes
    ENOENT liefert — nicht bei jedem Non-Zero-Exit.

---

## 10. Daten- und Datenschutzdelta

Titan verarbeitet **lokal**: Socket-Metadaten (Protokoll, Endpunkt, UID, PID, Paketname),
FIM-Metadaten (Pfad, SHA-256, Größe, mtime, Rechte), Privileg-/Build-Fakten, Containment-Aktionen
und Witness-Checkpoints. Es gibt **keinen** Upload, keine Cloud-Analyse, keine Inhaltsauswertung,
kein TLS-MITM und keine Standortnutzung. Details: [PRIVACY.md](../PRIVACY.md) §11,
[DATA-SAFETY.md](../DATA-SAFETY.md) §7.

Speicherorte: Titan-Status/Baseline/Vault-Metadaten im privaten App-Verzeichnis; Evidenz in der
HMAC-Kette (`noBackupFilesDir/evidence/`); Vault unter `/data/local/gedefense_vault`
(nur bei Root, Metadaten-MAC-Kette lokal). Löschung: App-Daten löschen/deinstallieren bzw.
Evidence-Clear (Evidenz), Vault-Dateien bleiben systemseitig bestehen und sind zu dokumentieren.

---

## 11. TITAN-LIVE-UI (VGT GLASS 2100)

Der neue Reiter `TITAN LIVE` folgt der bestehenden Design-DNA (Obsidian/Mineral-Gold/Electric-Blue,
programmatische Views, 10-Fuß-Typografie, sichtbarer Fokusring) und dem Ehrlichkeitsmodell:

- **Status-Hero:** Stufe, effektive Sichtbarkeit, aktivierte/verfügbare Capabilities, Aktivierungs-
  Button und „letzter Lauf“ (`TitanStatusHero`); Aktivierung nur angeboten, wenn passive Marker
  (`su`-Pfad, Root-Manager oder Shizuku-Installation) gefunden wurden.
- **Socket-Bereich (`TitanSocketSection`):** Liste der Beobachtungen mit App-Zuordnung oder
  „App unbekannt“, Risiko-Pill nur bei Feed-Treffer; Freeze-/Isolate-Aktionen nur für Capability-
  Inhaber und nur über Zwei-Schritt-Bestätigung.
- **FIM-Bereich (`TitanFimSection`):** Delta-Zähler und Pfade; unlesbare Einträge sichtbar als
  solche; kein „clean“.
- **Vault (`TitanVaultSection`)** und **Witness (`TitanWitnessSection`):** Vault-Metadaten;
  Witness-Status ehrlich „nicht gekoppelt“, Checkpoint-Aktion lokal.
- **Guards (`TitanGuardSection`):** Socket-/FIM-Guard-Schalter (persistiert, Default an).
- **Bestätigungs-Overlay (`TitanConfirmationOverlay`):** jede privilegien- oder schadensrelevante
  Aktion ist zweistufig, Default-Fokus auf „Abbrechen“, BACK schließt das Overlay statt den Screen
  zu verlassen.
- **Home-Strip (`TitanHomeStrip`):** kompakter Titan-Status (Stufe/letzter Lauf) im Home-Screen.
- Alle Zustände ohne Root/Shizuku: Hinweis statt Fehler, keine Crash-Pfade; D-Pad-vollständig.
- **Kein Sicherheits-Score:** Titan rendert keinen erfundenen Score, nur belegte Zustände und
  Capabilities.

**Lokalisierungsstand:** Titan-Texte liegen in **allen 7 Locale-Dateien** (`values`/`values-en`,
`values-de`, `values-fr`, `values-ja`, `values-ru`, `values-zh-rCN`, je 171 Titan-String-Einträge,
Stand 31.10.2026). Die sprachliche Qualität der Übersetzungen ist **NOT_TESTED**; fehlende Keys
fallen auf den Default-Katalog zurück.

Verbindliche UI-Regel: Es wird **keine** „geschützt“-/„sauber“-Aussage gerendert, wenn
`capabilities` leer sind oder `visibility != FULL` — analog zur V1-Invariante.

---

## 12. Invarianten des Titan-Engine (verbindlich)

1. `level > STANDARD` ⇒ bestätigter Kommandokanal (`rootShellConfirmed`/`shizukuBridgeAvailable`).
2. UI/Report/Evidenz konsumieren ausschließlich `effectiveCapabilities`, nie `theoreticalCapabilities`.
3. `visibility == FULL` nur bei bestätigtem Root-Kanal.
4. Keine Aktion ohne `TitanActionDecision.allowed == true`.
5. Keine freie Shell, kein `exec(String)`, keine Nutzereingabe in Kommandos.
6. Kein Löschen, kein Partitionsschreiben, jede Aktion reversibel (ADB-Lockdown explizit).
7. Dirty Root ist ein Befund, keine Freigabe.
8. `UNATTRIBUTED`/`UNREADABLE` sind Sichtbarkeitslücken, keine Malware-/Clean-Urteile.
9. Alle Cap-Grenzen sind hart; Truncation wird signalisiert (`truncated`/Notes).
10. Evidenz bleibt append-only und fail-closed (Core-Regeln unverändert).

---

## 13. Test- und Verifikationsstrategie (Stand 31.10.2026)

Die verbindliche Matrix steht in [TEST-PLAN.md](../TEST-PLAN.md) §9. Kurzfassung:

| Bereich | Prüfung | Status |
| --- | --- | --- |
| `:tv-core` Domäne | JVM-Harness `:tv-core:tvTitanCheck` für Parser, FIM-Delta, Policy, Command-Factory, Event-Factory, Composer, Witness-Codec | **PASS** – 6624 / FAIL 0, 17 Tests, Exit 0; Regression (tvCoreCheck 554/0, tvV2Check 4398/0, tvKineticCheck 3025/0) Exit 0 |
| Build | `:app:compileDebugKotlin`, `:app:assembleDebug` | **PASS** – Exit 0; Debug-APK **8.811.121 B** (SHA-256 `2fb107…b2d4`) |
| Lint | `:app:lintDebug` | **PASS** – Exit 0, **0 Errors / 305 Warnings** (`dist/lint-results-debug.txt`) |
| Release | `:app:assembleRelease` | **PASS (Alpha-signiert)** – Exit 0; `app-release.apk` **6.522.110 B**, SHA-256 `da4110…f2934`, **CN=VisionGaiaTechnology GeDefense TV Alpha** (nicht Debug-Key); Produktions-/Upload-Signatur offen |
| Level-1-Verhalten (Nicht-Root) | App starten, TITAN LIVE, Scan | **PASS (Emulator)** – Level `STANDARD`, 7× „Unavailable“, ehrliche Passivmodus-Erklärung, kein Aktivierungs-Button, `titan scan ms=754 level=STANDARD caps=0`, kein AndroidRuntime-Crash, Status persistiert |
| Onboarding/D-Pad/Home | D-Pad, Rail, Home-Strip | **PASS (PARTIAL, Emulator)** – Onboarding abgeschlossen; LEFT → Rail, DOWN×7 → „Titan Live“, OK → Screen; Home-Strip „Titan · Level 1 · Standard“/„Open Titan“; Level-3-Containment-Dialoge **NOT_TESTED** |
| Level-3 (Root) | Freeze/Restore/UID-Quarantäne/Kill auf Testgerät, Verifikation, Evidenz, Restore | **NOT_TESTED** – kein Root-Gerät belegt (Emulator ohne `su`; produktives Google-TV ohne `adb root`) |
| Level-2 (Shizuku) | Nur Erkennung; Kommando-Bridge fehlt bewusst | **Alpha-Gap**, Erkennung auf Emulator: keine Marker |
| FIM | Baseline-Erstlauf, neues/geändertes File, unlesbarer Pfad | Engine **PASS (JVM)**; Collector-Laufzeit **NOT_TESTED** |
| Socket-Provenance | `/proc`-Parser, Inode-Zuordnung, nicht zuordenbare Sockets, ADB-Port | Engine/Parser **PASS (JVM)**; Collector-Laufzeit **NOT_TESTED** |
| Witness | Checkpoint erzeugen/verifizieren | **PASS (Runtime, Emulator)** – `state=READY`, `checkpoints=1`, `prefix=82b6992b31d31034`, `sequence=1`; `witness-checkpoint`-Event, Ledger gesund (9 Records); UI „Checkpoints: 1 · Last checkpoint: just now“ + Unpaired-Note; Mobile-Push **nicht ausgeliefert** |
| Evidenz | Ledger gesund, Titan-Events | **PASS (PARTIAL, Emulator)** – Ledger gesund, 9 Records inkl. Witness-Event; vollständige Titan-Event-Matrix Level 3 **NOT_TESTED** |
| Übersetzungen | `tools/check_translations.py --include-plurals` | **PASS** – 0 Probleme, 6 Locales (Basis + 6), je 890 String-Keys, je 9 Plural-Gruppen |
| Multi-Resolution | Density 426 (2K-äquivalent) / 640 (4K-äquivalent) | **PASS (Density)**; Framebuffer blieb 1920×1080 → **echtes 2K/4K-Framebuffer NOT_TESTED** |
| Security-Audit | Unabhängiges Read-only-Review | **PARTIAL** – kein kritischer Befund/Injection-Blocker; Laufzeit-Vollprüfung offen, Alpha-Befunde siehe unten |

**Verifizierte Evidenz (Lead-Lauf 31.10.2026, final):** Emulator Android 16 Google TV, API 36, AVD
`gedefense_tv`, 1920×1080 (320 dpi). Screenshots `titan-13-final-scan.png`,
`titan-14-onboarding.png`, `titan-15-after-onboarding.png`, `titan-02-passive-scan.png`,
`titan-03-sections.png`, `titan-04-home.png`, `titan-05-evidence.png` in `docs/screenshots/`.
Level-3-Pfad ist ausschließlich
JVM-Harness-verifiziert; ein realer Root-Lauf bleibt **NOT_TESTED**.

### 13.1 Alpha-Sicherheitsbefunde (Audit 31.10.2026)

Das unabhängige Read-only-Audit fand **keinen kritischen Befund und keinen Shell-Injection-Blocker**.
Die verbleibenden Alpha-Befunde (TF-01…TF-12) sind ehrlich zu dokumentieren und in
[SECURITY.md](../SECURITY.md) §17 gelistet; Kurzfassung: FIM-Coverage-Gap bei ungewöhnlichen
Dateinamen (TF-01), Parser-Fehler ≠ „keine Verbindungen“ (TF-02), Kill-Verifikation nur über
`/proc`-ENOENT (TF-03), Gesamt-Sichtbarkeit = schwächstes Modul (TF-04, behoben),
Recovery-Ausnahme von Limits (TF-05, behoben), einmalige `su`-Freigabe kann mehrere Prompts
auslösen (TF-06), Vault-Symlink/TOCTOU (TF-07, Guard vorhanden, Rest-Race dokumentiert),
Cold-Start-Root-Vertrauen (TF-08, behoben), leere `find`-Ausgabe ≠ „Root fehlt“ (TF-09),
`QUARANTINE_VAULT` ohne UI-Aufrufer / `CLOSE_ADB_PORT` irreversibel und nicht exponiert (TF-10),
Shared-UID-Misattribution (TF-11, in Arbeit), OEM-Pakete außerhalb der Blocklist (TF-12,
Plattformguard vorhanden). Mehrere Fixes sind im Code, ihre **Laufzeitwirksamkeit ist NOT_TESTED**.

---

## 14. Offene Punkte und Alpha-Lücken

| Punkt | Status |
| --- | --- |
| Shizuku-Binder-Kommando-Bridge | **nicht ausgeliefert** (detection-only) |
| Mobile-Pairing/Push des Witness-Protokolls | **nicht ausgeliefert** (lokale Checkpoints verifiziert) |
| Verschlüsselung der Vault-Binärdaten | **nicht implementiert** (nur Metadaten-/MAC-Kette); Quarantäne ohne UI-Aufrufer (TF-10) |
| Root-Gerätelauf (Magisk/KernelSU/APatch) | **NOT_TESTED** (Kommandopfad nur JVM-verifiziert) |
| Reale TV-Hardware (≥ 2 OEM-Profile) | **NOT_TESTED** |
| Echtes 2K-/4K-Framebuffer-Rendering | **NOT_TESTED** (nur Density 426/640 auf 1080p-Framebuffer) |
| Produktions-/Upload-Signatur | **OFFEN** (Release mit Alpha-Zertifikat signiert) |
| Unabhängige Vollprüfung der Titan-Laufzeitpfade | **OFFEN** (Read-only-Audit ohne Blocker; SECURITY §17/§18) |
| Fuzz-/Negativtests (`/proc`-Parser, Ledger-Tail, Command-Factory) | **NOT_TESTED** (JVM-Assertions vorhanden) |

---

*Verwandte Dokumente: [TITAN-TV-CONCEPT.md](TITAN-TV-CONCEPT.md) · [ARCHITECTURE.md](../ARCHITECTURE.md) ·
[THREAT-MODEL.md](../THREAT-MODEL.md) · [SECURITY.md](../SECURITY.md) · [TEST-PLAN.md](../TEST-PLAN.md) ·
[PRIVACY.md](../PRIVACY.md) · [DATA-SAFETY.md](../DATA-SAFETY.md)*
