package de.visiongaia.gedefense.tv.ui.titan

import android.view.View
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.core.titan.model.FimFileObservation
import de.visiongaia.gedefense.tv.core.titan.model.FimStatus
import de.visiongaia.gedefense.tv.core.titan.model.TitanCapability
import de.visiongaia.gedefense.tv.core.titan.model.TitanScanOutcome
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.toneColor

/**
 * System integrity (FIM anti-planting) section.
 *
 * Renders the hash delta against the persisted baseline. An unreadable path and a missing root channel
 * are stated explicitly; the section never converts "no delta" into a security claim.
 */
internal object TitanFimSection {

    private const val MAX_ROWS = 6

    fun build(
        container: LinearLayout,
        status: TitanStatus,
        fimGuardEnabled: Boolean,
        onScan: () -> Unit,
    ): List<View> {
        val context = container.context
        val snapshot = status.fim
        TitanLayout.addSection(container, context.getString(R.string.titan_fim_section))

        if (snapshot == null) {
            val reasonRes = when {
                !status.has(TitanCapability.DEEP_INVENTORY_FIM) -> R.string.titan_fim_empty_unavailable
                !fimGuardEnabled -> R.string.titan_fim_empty_guard
                status.lastScanOutcome == TitanScanOutcome.NEVER -> R.string.titan_empty_never
                else -> R.string.titan_empty_restart
            }
            val action = TitanLayout.addEmptyState(
                container,
                TvGlyph.SHIELD,
                context.getString(R.string.titan_fim_empty_title),
                context.getString(reasonRes),
                actionLabelRes = R.string.titan_action_start_check,
                onAction = onScan,
            )
            return listOfNotNull(action)
        }

        TitanLayout.addMetricRow(
            container,
            listOf(
                TitanMetric(
                    TvGlyph.ALERT,
                    if (snapshot.newFiles > 0) TvTone.WARNING else TvTone.NEUTRAL,
                    snapshot.newFiles.toString(),
                    context.getString(R.string.titan_fim_metric_new),
                ),
                TitanMetric(
                    TvGlyph.ALERT,
                    if (snapshot.modifiedFiles > 0) TvTone.WARNING else TvTone.NEUTRAL,
                    snapshot.modifiedFiles.toString(),
                    context.getString(R.string.titan_fim_metric_modified),
                ),
                TitanMetric(
                    TvGlyph.QUESTION,
                    TvTone.NEUTRAL,
                    snapshot.unreadableFiles.toString(),
                    context.getString(R.string.titan_fim_metric_unreadable),
                ),
                TitanMetric(
                    TvGlyph.EYE,
                    TvTone.INFO,
                    snapshot.scannedFiles.toString(),
                    context.getString(R.string.titan_fim_metric_scanned),
                ),
            ),
        )
        val baselineAt = snapshot.baselineAtMillis
        TitanLayout.addCaption(
            container,
            if (baselineAt != null && baselineAt > 0L) {
                context.getString(R.string.titan_fim_baseline, TvFormat.dateTime(context, baselineAt))
            } else {
                context.getString(R.string.titan_fim_baseline, context.getString(R.string.value_never))
            },
            topDp = 6,
        )
        if (snapshot.baselineCreated) {
            TitanLayout.addCaption(container, context.getString(R.string.titan_fim_baseline_created), topDp = 4)
        }

        val deltas = snapshot.observations.filter {
            it.status == FimStatus.NEW_FILE || it.status == FimStatus.MODIFIED || it.status == FimStatus.UNREADABLE
        }
        if (deltas.isEmpty()) {
            TitanLayout.addBody(container, context.getString(R.string.titan_fim_none_delta), topDp = 10)
        } else {
            val focusables = mutableListOf<View>()
            for (delta in deltas.take(MAX_ROWS)) {
                focusables += deltaRow(container, delta)
            }
            if (deltas.size > MAX_ROWS) {
                TitanLayout.addCaption(
                    container,
                    context.getString(R.string.titan_fim_truncated, deltas.size - MAX_ROWS),
                    topDp = 2,
                )
            }
            TitanLayout.addCaption(container, context.getString(R.string.titan_fim_delta_note), topDp = 4)
            return focusables
        }
        TitanLayout.addCaption(container, context.getString(R.string.titan_fim_delta_note), topDp = 4)
        return emptyList()
    }

    private fun deltaRow(container: LinearLayout, observation: FimFileObservation): View {
        val context = container.context
        val row = FocusableRow(context, interactive = false)
        row.setLeading(
            TitanText.fimStatusGlyph(observation.status),
            toneColor(context, TitanText.fimStatusTone(observation.status)),
        )
        row.setTitle(observation.path)
        val parts = mutableListOf(context.getString(TitanText.fimStatusLabelRes(observation.status)))
        observation.sha256?.let { hash ->
            parts += context.getString(R.string.titan_hash_prefix, hash.take(12))
        }
        observation.permissions?.let { permissions ->
            parts += context.getString(R.string.titan_permissions, permissions)
        }
        row.setSubtitle(parts.joinToString(" · "))
        row.setTrailing(
            StatusPill(
                context,
                context.getString(TitanText.fimStatusLabelRes(observation.status)),
                TitanText.fimStatusTone(observation.status),
                TitanText.fimStatusGlyph(observation.status),
            ),
        )
        row.contentDescription = observation.path + ": " + context.getString(TitanText.fimStatusLabelRes(observation.status))
        TitanLayout.addRow(container, row, gapDp = 6)
        return row
    }
}
