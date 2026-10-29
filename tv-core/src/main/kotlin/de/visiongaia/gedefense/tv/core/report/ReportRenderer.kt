package de.visiongaia.gedefense.tv.core.report

import de.visiongaia.gedefense.tv.core.model.SecurityReport
import de.visiongaia.gedefense.tv.core.model.TextCatalog

/**
 * Renders a [SecurityReport] to the local export formats.
 *
 * The renderer may only format information that is present in the report. It must:
 *  - state scope and limitations explicitly (datasheet requirement for every report);
 *  - label partial/stale/unknown data instead of implying completeness;
 *  - contain no secrets, no raw exception text and no unverified claims;
 *  - produce deterministic output for identical input and locale-independent JSON.
 */
interface ReportRenderer {
    /** Human-readable German report designed for TV display and plain-text export. */
    fun renderText(report: SecurityReport, catalog: TextCatalog): String

    /** Machine-readable JSON export. Stable key order, escaping, no locale-dependent numbers. */
    fun renderJson(report: SecurityReport): String
}
