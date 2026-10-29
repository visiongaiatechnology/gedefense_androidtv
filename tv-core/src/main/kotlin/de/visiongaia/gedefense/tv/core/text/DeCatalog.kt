package de.visiongaia.gedefense.tv.core.text

import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.PassthroughTextCatalog
import de.visiongaia.gedefense.tv.core.model.TextCatalog

/**
 * Complete German catalog for every message key emitted by the tv-core engines, rule engine and
 * report renderer.
 *
 * The catalog is intentionally a plain map without Android resources so that the domain layer stays
 * JVM-testable. [resolve] never throws: an unknown key falls back to the visible passthrough form
 * (`key` or `key(arg0, arg1)`), and [isDefined] makes missing translations test-detectable.
 *
 * Keys must match the [MessageRef] pattern: lowercase letters and digits per dot-separated segment,
 * 2..8 segments. Placeholders use the positional `{0}`..`{7}` syntax.
 */
object DeCatalog : TextCatalog {

    // Android's ICU regex engine rejects an escaped brace (`\{`). Character classes are portable
    // between the desktop JVM (test harness) and Android, so the catalog uses them instead.
    private val ARG_PATTERN = Regex("[{]([0-7])[}]")

    private val entries: Map<String, String> = mapOf(
        // Patch policy (model.PatchPolicy).
        "patch.current" to "Patch-Stand aktuell (Alter: {0} Tage).",
        "patch.aging" to "Patch-Stand alternd (Alter: {0} Tage); Aktualisierung prüfen.",
        "patch.outdated" to "Patch-Stand veraltet (Alter: {0} Tage); Hersteller-Update prüfen.",
        "patch.critically_outdated" to "Patch-Stand kritisch veraltet (Alter: {0} Tage).",
        "patch.unknown" to "Patch-Stand nicht verfügbar oder ungültig; keine Aussage möglich.",

        // Evidence store (model.EvidenceHealth).
        "evidence.unavailable" to "Lokaler Evidenzspeicher nicht verfügbar.",

        // Scan engine fault isolation.
        "collector.timeout" to "Zeitbudget des Collectors überschritten; Ergebnis unvollständig.",
        "collector.failed" to "Collector ist mit einem internen Fehler abgebrochen.",
        "collector.cancelled" to "Collector wurde wegen Abbruch beendet.",
        "collector.invalidresult" to "Collector lieferte ein nicht zuordenbares Ergebnis.",

        // Score contributions.
        "score.finding.critical" to "Kritischer Befund: {0}",
        "score.finding.high" to "Hoher Befund: {0}",
        "score.finding.medium" to "Mittlerer Befund: {0}",
        "score.finding.low" to "Niedriger Befund: {0}",
        "score.finding.info" to "Prüfhinweis ohne Punktabzug: {0}",
        "score.patch.current" to "Patch-Stand aktuell; kein Punktabzug.",
        "score.patch.aging" to "Patch-Stand alternd (Alter: {0} Tage).",
        "score.patch.outdated" to "Patch-Stand veraltet (Alter: {0} Tage); Hersteller-Update prüfen.",
        "score.patch.critically_outdated" to "Patch-Stand kritisch veraltet (Alter: {0} Tage).",
        "score.patch.unknown" to "Patch-Stand nicht verfügbar; Bewertung wird begrenzt.",
        "score.coverage.partial" to "Teilweise Sichtbarkeit: das Ergebnis kann nicht als stark bewertet werden.",
        "score.coverage.stale" to "Veraltete Daten: das Ergebnis kann nicht als stark bewertet werden.",
        "score.coverage.none" to "Keine ausreichende Sichtbarkeit: kein numerischer Score möglich.",
        "score.cap.partial" to "Begrenzt wegen teilweiser Sichtbarkeit.",
        "score.cap.stale" to "Begrenzt wegen veralteter Daten.",
        "score.cap.patchunknown" to "Begrenzt, weil der Patch-Stand nicht verfügbar ist.",
        "score.contributions.compacted" to "{0} weitere Beiträge zusammengefasst.",
        "score.band.strong" to "Stark",
        "score.band.moderate" to "Moderat",
        "score.band.weak" to "Schwach",
        "score.band.unknown" to "Unbekannt",
        "score.band.insufficientcoverage" to "Nicht ausreichend abgedeckt",

        // Hardening rules (DefaultHardeningRules).
        "hardening.adb.enabled.title" to "ADB-/Debugging-Zugriff ist aktiviert",
        "hardening.adb.enabled.why" to "Aktives ADB erlaubt autorisierten Debug-Befehlen und App-Installationen den Zugriff auf das Gerät.",
        "hardening.adb.enabled.recommendation" to "Debugging in den Entwickleroptionen deaktivieren und die ADB-Autorisierungen zurücksetzen.",
        "hardening.adb.unknown.title" to "ADB-Status nicht lesbar",
        "hardening.adb.unknown.why" to "Die Einstellung konnte nicht gelesen werden; ein aktives ADB kann daher nicht ausgeschlossen werden.",
        "hardening.adb.unknown.recommendation" to "Debugging-Status in den Systemeinstellungen manuell prüfen und deaktivieren, wenn es nicht benötigt wird.",
        "hardening.devoptions.enabled.title" to "Entwickleroptionen sind aktiviert",
        "hardening.devoptions.enabled.why" to "Entwickleroptionen sind Voraussetzung für viele Debug- und Sideload-Funktionen und auf einem Alltagsfernseher selten erforderlich.",
        "hardening.devoptions.enabled.recommendation" to "Entwickleroptionen in den Systemeinstellungen deaktivieren, wenn sie nicht für Tests benötigt werden.",
        "hardening.devoptions.unknown.title" to "Status der Entwickleroptionen nicht lesbar",
        "hardening.devoptions.unknown.why" to "Die Einstellung konnte nicht gelesen werden; ein aktiver Debug-Zugang kann daher nicht ausgeschlossen werden.",
        "hardening.devoptions.unknown.recommendation" to "Status der Entwickleroptionen in den Systemeinstellungen manuell prüfen.",
        "hardening.unknownsources.enabled.title" to "Eigene App darf unbekannte Quellen installieren",
        "hardening.unknownsources.enabled.why" to "Wenn die eigene App Pakete aus unbekannten Quellen installieren darf, können Sideload-Pakete ohne Store-Prüfung auf das Gerät gelangen.",
        "hardening.unknownsources.enabled.recommendation" to "Das Sonderrecht für unbekannte Apps in den Systemeinstellungen für die eigene App entziehen.",
        "hardening.unknownsources.unknown.title" to "Installationsrecht für unbekannte Quellen nicht lesbar",
        "hardening.unknownsources.unknown.why" to "Das Sonderrecht konnte nicht gelesen werden; eine Freigabe für Sideload-Pakete kann daher nicht ausgeschlossen werden.",
        "hardening.unknownsources.unknown.recommendation" to "Berechtigung für unbekannte Quellen in den Systemeinstellungen manuell prüfen.",
        "hardening.testkeys.detected.title" to "Build mit Test-Keys oder Debug-Build erkannt",
        "hardening.testkeys.detected.why" to "Der Build trägt Test-Keys, ist als 'userdebug' oder 'eng' gebaut und damit kein produktionsüblicher Auslieferungsbuild; Vertrauenszusagen sind eingeschränkt.",
        "hardening.testkeys.detected.recommendation" to "Offiziellen Produktions-Build des Herstellers prüfen und bei Bedarf ein Update installieren.",
        "hardening.deviceadmin.detected.title" to "Aktiver Geräteadministrator: {0}",
        "hardening.deviceadmin.detected.why" to "Geräteadministratoren erhalten weitreichende Rechte auf dem Gerät. Die App kann nicht bewerten, ob dieser Administrator vertrauenswürdig ist.",
        "hardening.deviceadmin.detected.recommendation" to "In den Systemeinstellungen prüfen, ob der Administrator benötigt wird, und die Rechte sonst entziehen.",
        "hardening.accessibility.detected.title" to "Aktiver Accessibility-Dienst außerhalb bekannter Systempakete: {0}",
        "hardening.accessibility.detected.why" to "Accessibility-Dienste können Bildschirminhalte und Eingaben beobachten; ein zusätzlicher Dienst auf einem Fernseher ist erklärungsbedürftig.",
        "hardening.accessibility.detected.recommendation" to "Den Accessibility-Dienst deaktivieren, wenn er nicht bewusst installiert wurde, und die Herkunft der App prüfen.",
        "hardening.installer.detected.title" to "App aus einer Nicht-Store-Quelle sichtbar: {0}",
        "hardening.installer.detected.why" to "Mindestens eine sichtbare App wurde nicht über einen bekannten Store installiert; das ist ein Prüfhinweis, kein Malware-Nachweis.",
        "hardening.installer.detected.recommendation" to "Installationsquelle der App prüfen und die App bei fehlendem Vertrauen entfernen.",

        // Collector descriptors (used by the Android platform layer).
        "collector.platform.title" to "Plattform und Build",
        "collector.platform.description" to "Android-Version, API-Level, Hersteller, Gerät, Build und Patch-Stand aus öffentlichen Build-APIs.",
        "collector.appinventory.title" to "App-Inventar",
        "collector.appinventory.description" to "Sichtbare Apps mit Version, Installationsquelle und Signaturhinweisen im Rahmen der Paket-Sichtbarkeit.",
        "collector.apps.title" to "App-Inventar",
        "collector.apps.description" to "Sichtbare Apps mit Version, Installationsquelle und Signaturhinweisen im Rahmen der Paket-Sichtbarkeit.",
        "collector.hardening.title" to "Hardening-Prüfung",
        "collector.hardening.description" to "Debugging, unbekannte Quellen, Geräteadministratoren, Accessibility und Sideload-Hinweise.",
        "collector.connectivity.title" to "Verbindungsstatus",
        "collector.connectivity.description" to "Aktiver Netzwerkpfad und Link-Metadaten; kein systemweiter Flussmonitor.",
        "collector.threatintel.title" to "Threat Intelligence",
        "collector.threatintel.description" to "Lokaler Feed-Status und ausschließlich tatsächlich beobachtete Indikatoren.",
        "collector.sensorhealth.title" to "Sensor- und Berechtigungsstatus",
        "collector.sensorhealth.description" to "Verfügbarkeit und Sichtbarkeit der einzelnen Prüfbereiche.",

        // Collector status and error keys (platform layer + scan UI).
        "collector.permission_required" to "Für diese Prüfung fehlt eine Berechtigung; der Bereich bleibt unsichtbar.",
        "collector.unsupported" to "Diese Prüfung wird von der Plattform nicht unterstützt.",
        "collector.restricted" to "Die Plattform schränkt diese Prüfung ein; nur ein Teil ist sichtbar.",
        "collector.partial_coverage" to "Nur teilweise Abdeckung; es fehlt ein belastbarer Gesamtwert.",
        "collector.stale" to "Die Daten dieser Prüfung sind veraltet.",
        "collector.platform.failed" to "Plattformprüfung fehlgeschlagen; Build-Daten sind nicht verfügbar.",
        "collector.apps.failed" to "App-Inventar fehlgeschlagen; sichtbare Apps sind nicht verfügbar.",
        "collector.hardening.failed" to "Hardening-Prüfung fehlgeschlagen; Einstellungen sind nicht verfügbar.",
        "collector.hardening.evaluationfailed" to "Hardening-Bewertung fehlgeschlagen; Beobachtungen bleiben unausgewertet.",
        "collector.connectivity.failed" to "Verbindungsprüfung fehlgeschlagen; Netzwerkstatus ist nicht verfügbar.",
        "collector.sensorhealth.failed" to "Sensor-/Berechtigungsprüfung fehlgeschlagen.",
        "collector.threatintel.failed" to "Threat-Intelligence-Prüfung fehlgeschlagen; Feed-Status ist nicht verfügbar.",

        // App-level status keys used by the platform/UI layer.
        "coverage.packagevisibility" to "Paket-Sichtbarkeit eingeschränkt: Die App-Liste ist nicht vollständig.",
        "coverage.partial" to "Nur teilweise Sichtbarkeit: keine vollständige Abdeckung.",
        "evidence.initializing" to "Evidenzspeicher wird initialisiert.",
        "evidence.degraded" to "Evidenzspeicher arbeitet eingeschränkt.",
        "evidence.recordfailed" to "Evidenzeintrag konnte nicht gespeichert werden.",
        "evidence.clearfailed" to "Evidenzdaten konnten nicht vollständig gelöscht werden.",
        "evidence.cleared" to "Lokale Evidenzdaten wurden gelöscht.",
        "export.ok" to "Export abgeschlossen.",
        "export.partial" to "Export nur teilweise abgeschlossen.",
        "export.cancelled" to "Export abgebrochen.",
        "export.failed" to "Export fehlgeschlagen.",
        "export.unavailable" to "Export ist auf diesem Gerät nicht verfügbar.",
        "scan.cancelled" to "Scan wurde abgebrochen; Ergebnisse sind unvollständig.",
        "scan.failed" to "Scan ist fehlgeschlagen; es liegen keine belastbaren Ergebnisse vor.",
        "ti.syncok" to "Threat-Intelligence-Synchronisierung erfolgreich.",
        "ti.syncpartial" to "Threat-Intelligence-Synchronisierung nur teilweise erfolgreich.",
        "ti.syncfailed" to "Threat-Intelligence-Synchronisierung fehlgeschlagen.",
        "ti.keyunavailable" to "Sicherer Schlüssel für den Feed-Cache nicht verfügbar; Synchronisierung bleibt gesperrt.",
        "ti.stale" to "Threat-Intelligence-Daten sind veraltet; sie bleiben als veraltet gekennzeichnet.",
        "sensor.permission.title" to "Berechtigung für optionale Prüfung fehlt",
        "sensor.permission.why" to "Ohne diese Berechtigung bleibt der zugehörige Bereich unsichtbar und wird nicht als geprüft gewertet.",
        "sensor.permission.recommendation" to "Berechtigung nur erteilen, wenn die optionale Funktion bewusst genutzt werden soll.",
        "sensor.evidence.title" to "Evidenzlage der Prüfbereiche",
        "sensor.evidence.why" to "Fehlende Evidenz bedeutet eingeschränkte Sichtbarkeit, nicht Abwesenheit von Risiken.",

        // Event class labels (XDR event schema).
        "event.device_state" to "Gerätezustand",
        "event.app_inventory" to "App-Inventar",
        "event.connectivity" to "Verbindungsstatus",
        "event.ti_match" to "Threat-Intelligence-Treffer",
        "event.sensor_health" to "Sensorzustand",
        "event.enforcement" to "Durchsetzungsaktion",

        // XDR-light incidents (TvXdrEngine).
        "xdr.repeatedblock.title" to "Wiederholte blockierte Verbindungen: {0} ({1})",
        "xdr.repeatedblock.why" to "Die App {0} hat im Beobachtungsfenster {1} blockierte Verbindungen ausgelöst; das ist ein Prüfhinweis, kein Malware-Nachweis.",
        "xdr.repeatedblock.recommendation" to "Herkunft und Verhalten der App prüfen; keine automatische Löschung.",
        "xdr.trackerblock.title" to "Blockierte Tracker-/Telemetrieverbindung: {0} ({1})",
        "xdr.trackerblock.why" to "Für die App {0} wurde eine blockierte Verbindung der Kategorie {1} beobachtet; die Blockierung belegt kein Fehlverhalten, sondern eine aktive Filterregel.",
        "xdr.trackerblock.recommendation" to "Filterprofil prüfen und bei Bedarf eine bewusste Ausnahme dokumentieren.",
        "xdr.newapp.title" to "Neue App mit ausgehendem Datenverkehr: {0}",
        "xdr.newapp.why" to "Für die App {0} wurde erstmals ausgehender Verkehr beobachtet; neu bedeutet nicht unsicher.",
        "xdr.newapp.recommendation" to "Installationsquelle und Berechtigungen der App prüfen.",
        "xdr.c2match.title" to "Threat-Intelligence-Treffer: {0}",
        "xdr.c2match.why" to "Das Ziel {0} der App {1} entspricht einem lokalen C2-Indikator ({2}); bewertet wird ausschließlich der lokale Feed-Treffer.",
        "xdr.c2match.recommendation" to "Verbindung blockiert lassen und App- sowie Gerätequelle prüfen.",
        "xdr.corridor.title" to "Datenverkehr in ein Risikoland: {0}",
        "xdr.corridor.why" to "Die App {0} hat Verkehr in das Land {1} erzeugt; die Geo-Zuordnung ist allein kein Beweis für Fehlverhalten und bleibt ein Hinweis.",
        "xdr.corridor.recommendation" to "Nur beobachten; keine automatische Maßnahme.",
        "xdr.correlated.title" to "Korrelierte Auffälligkeiten: {0}",
        "xdr.correlated.why" to "Mehrere unabhängige lokale Signale betreffen die App {0}: {1}. Die Korrelation ist ein Prüfhinweis, kein Urteil.",
        "xdr.correlated.recommendation" to "Befunde gemeinsam prüfen; die TV-XDR-Sicht korreliert nur lokal beobachtbare Signale.",

        // Report renderer: labels and sections.
        "report.title" to "GeDefense TV – Sicherheitsbericht",
        "report.subject" to "Lokale Sicherheitsdiagnostik für Android TV",
        "report.label.reportid" to "Berichts-ID",
        "report.label.generated" to "Erstellt (UTC)",
        "report.label.device" to "Geräte-ID (pseudonym)",
        "report.label.scanid" to "Scan-ID",
        "report.label.started" to "Scan gestartet (UTC)",
        "report.label.completed" to "Scan abgeschlossen (UTC)",
        "report.label.scanstate" to "Scan-Status",
        "report.label.platform" to "Plattform",
        "report.label.android" to "Android",
        "report.label.api" to "API-Level",
        "report.label.patch" to "Patch-Stand",
        "report.label.coverage" to "Sichtbarkeit",
        "report.label.score" to "Bewertung",
        "report.label.band" to "Einstufung",
        "report.label.capreason" to "Begrenzung",
        "report.label.findings" to "Befunde",
        "report.label.error" to "Fehler",
        "report.label.lastsync" to "Letzte Synchronisierung (UTC)",
        "report.line" to "{0}: {1}",
        "report.scanstate.completed" to "Abgeschlossen",
        "report.scanstate.partial" to "Teilweise abgeschlossen",
        "report.scanstate.cancelled" to "Abgebrochen",
        "report.scanstate.failed" to "Fehlgeschlagen",
        "report.visibility.full" to "Vollständig",
        "report.visibility.partial" to "Teilweise",
        "report.visibility.stale" to "Veraltet",
        "report.visibility.none" to "Nicht verfügbar",
        "report.capability.supported" to "Unterstützt",
        "report.capability.permissionrequired" to "Berechtigung erforderlich",
        "report.capability.unsupported" to "Nicht unterstützt",
        "report.capability.failed" to "Fehlgeschlagen",
        "report.coverage.full" to "Vollständig sichtbar; keine Einschränkung der Abdeckung gemeldet.",
        "report.coverage.partial" to "Nur teilweise sichtbar; die Bewertung ist eingeschränkt.",
        "report.coverage.stale" to "Daten sind veraltet; die Bewertung ist eingeschränkt.",
        "report.coverage.none" to "Keine ausreichende Sichtbarkeit; es wird kein numerischer Score ausgewiesen.",
        "report.severity.critical" to "Kritisch",
        "report.severity.high" to "Hoch",
        "report.severity.medium" to "Mittel",
        "report.severity.low" to "Niedrig",
        "report.severity.info" to "Hinweis",
        "report.confidence.low" to "Niedrig",
        "report.confidence.medium" to "Mittel",
        "report.confidence.high" to "Hoch",
        "report.policy.none" to "Keine",
        "report.policy.observe" to "Beobachten",
        "report.policy.recommendmanual" to "Manuelle Empfehlung",
        "report.policy.escalate" to "An Nutzer eskalieren",
        "report.section.metadata" to "Metadaten",
        "report.section.scope" to "Prüfumfang",
        "report.section.limitations" to "Grenzen der Aussage",
        "report.section.freshness" to "Datenfrische",
        "report.section.posture" to "Sicherheitsbewertung",
        "report.section.collectors" to "Prüfbereiche",
        "report.section.findings" to "Befunde",
        "report.section.inventory" to "App-Inventar",
        "report.section.threatintel" to "Threat Intelligence",
        "report.section.evidence" to "Lokale Evidenz",
        "report.scope.text" to "Dieser Bericht bewertet ausschließlich lokal sichtbare Zustände dieses Fernsehers. Nicht sichtbare Bereiche werden als eingeschränkte Sichtbarkeit ausgewiesen und niemals als sicher gewertet.",
        "report.freshness.text" to "Bericht erstellt: {0}; Scan abgeschlossen: {1}; Patch-Bewertung: {2}",
        "report.score.value" to "{0} von 100 ({1})",
        "report.score.none" to "Kein numerischer Wert; Einstufung: {0}",
        "report.score.contributions" to "Beiträge zur Bewertung",
        "report.score.contribution" to "{0} Punkte: {1}",
        "report.score.cap" to "Begrenzung: {0}",
        "report.findings.none" to "Keine Befunde im sichtbaren Bereich.",
        "report.finding.header" to "{0} – {1}",
        "report.finding.component" to "Betroffene Komponente: {0}",
        "report.finding.why" to "Begründung: {0}",
        "report.finding.evidence" to "Evidenz: {0} ({1})",
        "report.finding.confidence" to "Konfidenz: {0}",
        "report.finding.visibility" to "Sichtbarkeit: {0}",
        "report.finding.policy" to "Empfohlene Aktion: {0}",
        "report.finding.recommendation" to "Empfehlung: {0}",
        "report.inventory.visible" to "Sichtbare Apps: {0}",
        "report.inventory.restricted" to "Hinweis: Die Paket-Sichtbarkeit kann die App-Liste einschränken; sie ist kein vollständiges Inventar.",
        "report.inventory.delta" to "Änderungen zum letzten Stand: {0} neu, {1} geändert, {2} entfernt.",
        "report.inventory.nobaseline" to "Kein Vergleichsstand vorhanden.",
        "report.inventory.unavailable" to "App-Inventar nicht verfügbar.",
        "report.threatintel.feeds" to "Feeds: {0} gesamt, {1} verfügbar, {2} frisch, {3} veraltet.",
        "report.threatintel.never" to "Noch keine Feed-Synchronisierung.",
        "report.threatintel.unhealthy" to "Feed-Synchronisierung nicht gesund.",
        "report.threatintel.note" to "Hinweis: {0}",
        "report.evidence.healthy" to "Evidenzspeicher intakt, {0} Einträge.",
        "report.evidence.unhealthy" to "Evidenzspeicher eingeschränkt: {0}",
        "report.collector.line" to "{0}: {1}, Sichtbarkeit {2}, {3} Befunde",
        "report.value.never" to "Nie",
        "report.footer.disclaimer" to "Dieser Bericht ist eine lokale Momentaufnahme. Er ersetzt keine professionelle Sicherheitsprüfung und keine Herstellerangaben.",

        // Report limitations (honest scope statements required by the datasheet).
        "report.limit.nosystemwideflows" to "Kein systemweiter Netzwerkfluss-, Port- oder Prozessmonitor; sichtbar sind nur eigene Telemetrie und öffentlich zugängliche API-Daten.",
        "report.limit.noprivilegedsensor" to "Keine privilegierten Endpoint-, Kernel- oder Fremd-App-Dateizugriffe; die App ist kein vollständiger EDR-Sensor.",
        "report.limit.packagevisibility" to "Die App-Liste ist durch die Paket-Sichtbarkeit ab Android 11 begrenzt; sie ist kein vollständiges Inventar.",
        "report.limit.patchnotvulnerability" to "Ein alter Patch-Stand belegt nicht automatisch eine konkrete Verwundbarkeit; Patch-Bulletins und OEM-Hinweise sind separat zu prüfen.",
        "report.limit.nointegrity" to "Build-Metadaten und Fingerprint sind kein Integritäts- oder Firmware-Vertrauensbeweis.",
        "report.limit.localonly" to "Alle Auswertungen erfolgen lokal; V1 überträgt keine Telemetrie.",
        "report.limit.observeonly" to "V1 beobachtet und empfiehlt; es werden keine Änderungen automatisch durchgesetzt.",
    )

    /** All keys with a German translation. */
    val keys: Set<String> get() = entries.keys

    /** Number of translated keys. */
    val size: Int get() = entries.size

    /** True when [key] has a German translation. */
    fun isDefined(key: String): Boolean = entries.containsKey(key)

    /** Returns the sorted, distinct candidate keys that have no translation. */
    fun missingKeys(candidateKeys: Collection<String>): List<String> =
        candidateKeys.filterNot(::isDefined).distinct().sorted()

    override fun resolve(ref: MessageRef): String {
        val template = entries[ref.key] ?: return PassthroughTextCatalog.resolve(ref)
        if (ref.args.isEmpty()) return template
        return ARG_PATTERN.replace(template) { match ->
            val index = match.groupValues[1].toInt()
            ref.args.getOrNull(index) ?: match.value
        }
    }
}
