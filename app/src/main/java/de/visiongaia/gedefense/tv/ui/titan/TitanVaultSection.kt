package de.visiongaia.gedefense.tv.ui.titan

import android.view.View
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.core.titan.model.TitanCapability
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus
import de.visiongaia.gedefense.tv.core.titan.model.TitanVaultEntry
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.toneColor

/**
 * Quarantine vault section: read-only list of quarantined object metadata.
 *
 * Restore and delete are explicitly not part of this alpha, so the section offers no button that
 * cannot work - only the honest inventory and its provenance.
 */
internal object TitanVaultSection {

    private const val MAX_ROWS = 8

    fun build(container: LinearLayout, status: TitanStatus, entries: List<TitanVaultEntry>): List<View> {
        val context = container.context
        val meta = if (entries.isEmpty()) null else context.getString(R.string.titan_vault_meta, entries.size)
        TitanLayout.addSection(container, context.getString(R.string.titan_vault_section), meta)

        if (entries.isEmpty()) {
            val reasonRes = if (status.has(TitanCapability.QUARANTINE_VAULT)) {
                R.string.titan_vault_empty_none
            } else {
                R.string.titan_vault_empty_root
            }
            TitanLayout.addEmptyState(
                container,
                TvGlyph.TRASH,
                context.getString(R.string.titan_vault_empty_title),
                context.getString(reasonRes),
                note = context.getString(R.string.titan_vault_readonly),
            )
            return emptyList()
        }

        val focusables = mutableListOf<View>()
        for (entry in entries.take(MAX_ROWS)) {
            focusables += entryRow(container, entry)
        }
        if (entries.size > MAX_ROWS) {
            TitanLayout.addCaption(
                container,
                context.getString(R.string.titan_vault_truncated, entries.size - MAX_ROWS),
                topDp = 2,
            )
        }
        TitanLayout.addCaption(container, context.getString(R.string.titan_vault_readonly), topDp = 6)
        return focusables
    }

    private fun entryRow(container: LinearLayout, entry: TitanVaultEntry): View {
        val context = container.context
        val row = FocusableRow(context, interactive = false)
        row.setLeading(TvGlyph.TRASH, toneColor(context, TvTone.WARNING))
        row.setTitle(entry.fileName)
        row.setSubtitle(
            buildString {
                append(entry.originalPath)
                append("\n")
                append(context.getString(R.string.titan_vault_stored, TvFormat.relative(context, entry.storedAtMillis)))
                append(" · ")
                append(context.getString(R.string.titan_hash_prefix, entry.sha256.take(12)))
            },
        )
        row.setSubtitleMaxLines(3)
        TitanLayout.addRow(container, row, gapDp = 6)
        return row
    }
}
