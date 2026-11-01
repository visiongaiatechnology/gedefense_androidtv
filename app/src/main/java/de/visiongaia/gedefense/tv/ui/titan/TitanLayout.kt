package de.visiongaia.gedefense.tv.ui.titan

import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.EmptyState
import de.visiongaia.gedefense.tv.ui.components.FocusableAction
import de.visiongaia.gedefense.tv.ui.components.MetricTile
import de.visiongaia.gedefense.tv.ui.components.SectionHeader
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.addSpacer
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.captionText
import de.visiongaia.gedefense.tv.ui.components.horizontalRow
import de.visiongaia.gedefense.tv.ui.components.toneColor

/** One KPI value of a Titan metric row: semantic glyph, real counter, explicit label. */
internal data class TitanMetric(
    val glyph: TvGlyph,
    val tone: TvTone,
    val value: String,
    val label: String,
)

/**
 * Composition helpers shared by the Titan sections.
 *
 * Grouping follows the product rule: sections are separated by spacing and the gold heading rule,
 * not by wrapping every block in another card. Glass surfaces stay reserved for the functional hero,
 * the confirmation step and the guard switches.
 */
internal object TitanLayout {

    fun addSection(container: LinearLayout, title: String, meta: String? = null) {
        if (container.childCount > 0) container.addSpacer(14)
        container.addView(SectionHeader(container.context, title, meta))
        container.addSpacer(6)
    }

    fun addBody(container: LinearLayout, text: CharSequence, topDp: Int = 8) {
        if (container.childCount > 0) container.addSpacer(topDp)
        container.addView(bodyText(container.context, text), matchWidth())
    }

    fun addCaption(container: LinearLayout, text: CharSequence, topDp: Int = 6) {
        if (container.childCount > 0) container.addSpacer(topDp)
        container.addView(captionText(container.context, text), matchWidth())
    }

    fun addRow(container: LinearLayout, row: View, gapDp: Int = 8) {
        container.addView(row, matchWidth())
        container.addSpacer(gapDp)
    }

    fun matchWidth(): LinearLayout.LayoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
    )

    fun wrapWidth(): LinearLayout.LayoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.WRAP_CONTENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
    )

    /** One row of real counters; every tile keeps its glyph + explicit label. */
    fun addMetricRow(container: LinearLayout, metrics: List<TitanMetric>, topDp: Int = 2) {
        if (metrics.isEmpty()) return
        val context = container.context
        val row = horizontalRow(context)
        metrics.forEachIndexed { index, metric ->
            val tile = MetricTile(context).apply {
                bind(metric.glyph, toneColor(context, metric.tone), metric.value, metric.label)
            }
            row.addView(
                tile,
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                    if (index < metrics.lastIndex) rightMargin = TvTheme.scaledDp(context, 8)
                },
            )
        }
        if (container.childCount > 0) container.addSpacer(topDp)
        container.addView(row, matchWidth())
    }

    /**
     * Honest empty state with the concrete reason and an optional next action.
     * Returns the focusable action so the screen can wire it into the D-pad focus chain.
     */
    fun addEmptyState(
        container: LinearLayout,
        glyph: TvGlyph,
        title: String,
        message: String,
        note: String? = null,
        actionLabelRes: Int? = null,
        onAction: (() -> Unit)? = null,
    ): View? {
        val context = container.context
        val empty = EmptyState(context, glyph)
        empty.set(glyph, title, message, note)
        if (container.childCount > 0) container.addSpacer(10)
        container.addView(empty, matchWidth())
        if (actionLabelRes == null || onAction == null) return null
        val action = FocusableAction.primary(context, actionLabelRes, TvGlyph.REFRESH).apply {
            setOnClickListener { onAction() }
        }
        container.addView(
            action,
            wrapWidth().apply { topMargin = TvTheme.scaledDp(context, 8) },
        )
        return action
    }

    /** Small "Prüfung starten" control used by empty states that still allow a passive scan. */
    fun addScanAction(container: LinearLayout, actionLabelRes: Int, onAction: () -> Unit): FocusableAction {
        val context = container.context
        val action = FocusableAction.primary(context, actionLabelRes, TvGlyph.REFRESH).apply {
            setOnClickListener { onAction() }
        }
        container.addView(
            action,
            wrapWidth().apply { topMargin = TvTheme.scaledDp(context, 8) },
        )
        return action
    }
}
