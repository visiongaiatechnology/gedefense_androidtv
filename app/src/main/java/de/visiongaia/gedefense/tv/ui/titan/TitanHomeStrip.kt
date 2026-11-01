package de.visiongaia.gedefense.tv.ui.titan

import android.content.Context
import android.view.View
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.readService
import de.visiongaia.gedefense.tv.ui.components.toneColor

/**
 * Compact Home entry into the Titan Live screen.
 *
 * One D-pad stop with the confirmed level, the last passive pass and the real counters of the last
 * scan. The strip never expands into a card block: it keeps the Home hero + KPI composition intact.
 */
internal object TitanHomeStrip {

    fun build(context: Context, services: TvServices, onOpen: () -> Unit): View {
        val status = readService { services.titan.status() } ?: TitanStatus.empty(System.currentTimeMillis())
        val row = FocusableRow(context, interactive = true)
        row.setCard(true)
        row.setLeading(TitanText.levelGlyph(status.level), toneColor(context, TitanText.levelTone(status.level)))
        row.setTitle(
            context.getString(R.string.titan_strip_title) +
                " · " +
                context.getString(TitanText.levelLabelRes(status.level)),
        )
        row.setSubtitle(buildSubtitle(context, status))
        row.addTrailingText(context.getString(R.string.titan_strip_open), TvTheme.accent)
        row.setChevronVisible(true)
        row.contentDescription = rowTitle(context, status) + ". " + buildSubtitle(context, status)
        row.setOnClickListener { onOpen() }
        return row
    }

    private fun rowTitle(context: Context, status: TitanStatus): String =
        context.getString(R.string.titan_strip_title) + " " + context.getString(TitanText.levelLabelRes(status.level))

    private fun buildSubtitle(context: Context, status: TitanStatus): String {
        val parts = mutableListOf<String>()
        parts += if (status.lastScanAtMillis > 0L) {
            context.getString(R.string.titan_strip_last_scan, TvFormat.relative(context, status.lastScanAtMillis))
        } else {
            context.getString(R.string.titan_strip_never)
        }
        status.sockets?.let { parts += context.getString(R.string.titan_strip_suspicious, it.suspiciousCount) }
        status.fim?.let { parts += context.getString(R.string.titan_strip_fim, it.deltaCount) }
        if (status.sockets == null && status.fim == null) {
            parts += context.getString(R.string.titan_strip_pending)
        }
        return parts.joinToString(" · ")
    }
}
