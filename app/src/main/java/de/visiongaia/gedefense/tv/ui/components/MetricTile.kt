package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.text.TextUtils
import android.view.Gravity
import android.view.ViewGroup
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * Compact KPI tile for the Home row: small semantic badge, 36sp value and 17sp label.
 *
 * Sized for a single 4-tile row at 1080p (~92dp tall). Callers pass real model values or an explicit
 * "—"; the tile never invents or pads values.
 */
class MetricTile @JvmOverloads constructor(
    context: Context,
    soft: Boolean = true,
) : LinearLayout(context) {

    private val badge = GlyphBadge(context, TvGlyph.DOT, TvTheme.accent, 24)
    private val valueView = TvTheme.textView(context, "—", TvTheme.TEXT_HEADING_SP, TvTheme.textPrimary, bold = true)
    private val labelView = TvTheme.textView(context, "", TvTheme.TEXT_MICRO_SP, TvTheme.textSecondary).apply {
        isSingleLine = true
        maxLines = 1
        ellipsize = TextUtils.TruncateAt.END
    }

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        isFocusable = false
        clipChildren = false
        clipToPadding = false
        minimumHeight = TvTheme.scaledDp(context, 44)
        setBackgroundResource(if (soft) R.drawable.bg_glass_panel_soft else R.drawable.bg_glass_panel)
        setPadding(
            TvTheme.scaledDp(context, 10),
            TvTheme.scaledDp(context, 6),
            TvTheme.scaledDp(context, 10),
            TvTheme.scaledDp(context, 6),
        )
        addView(
            badge,
            LayoutParams(TvTheme.scaledDp(context, 24), TvTheme.scaledDp(context, 24)).apply {
                rightMargin = TvTheme.scaledDp(context, 8)
                gravity = Gravity.CENTER_VERTICAL
            },
        )
        val column = verticalColumn(context)
        column.addView(valueView)
        column.addView(
            labelView,
            LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 1)
            },
        )
        addView(column, LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
    }

    fun bind(
        glyph: TvGlyph,
        glyphColor: Int,
        value: CharSequence,
        label: CharSequence,
        valueColor: Int = TvTheme.textPrimary,
    ) {
        badge.set(glyph, glyphColor)
        valueView.text = value
        valueView.setTextColor(valueColor)
        labelView.text = label
    }

    fun setValue(text: CharSequence, color: Int = TvTheme.textPrimary) {
        valueView.text = text
        valueView.setTextColor(color)
    }

    fun setLabel(text: CharSequence) {
        labelView.text = text
    }
}
