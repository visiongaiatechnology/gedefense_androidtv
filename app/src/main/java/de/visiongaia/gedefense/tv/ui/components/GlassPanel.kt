package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * Functional glass panel: obsidian gradient surface, fine gold edge, one inner highlight.
 *
 * Panels mark real boundaries (hero, posture, progress, notices, confirmation) - ordinary rows do
 * not get a panel. This keeps the composition structural instead of a card graveyard.
 */
class GlassPanel @JvmOverloads constructor(
    context: Context,
    soft: Boolean = false,
) : LinearLayout(context) {

    init {
        orientation = VERTICAL
        isFocusable = false
        clipChildren = false
        clipToPadding = false
        setBackgroundResource(if (soft) R.drawable.bg_glass_panel_soft else R.drawable.bg_glass_panel)
        setPadding(
            TvTheme.scaledDp(context, 18),
            TvTheme.scaledDp(context, 14),
            TvTheme.scaledDp(context, 18),
            TvTheme.scaledDp(context, 14),
        )
    }

    /** Compact variant for dense parameter blocks (still a functional boundary). */
    fun compact() {
        setPadding(
            TvTheme.scaledDp(context, 14),
            TvTheme.scaledDp(context, 10),
            TvTheme.scaledDp(context, 14),
            TvTheme.scaledDp(context, 10),
        )
    }

    companion object {
        fun column(context: Context, soft: Boolean = false): GlassPanel = GlassPanel(context, soft)
    }
}
