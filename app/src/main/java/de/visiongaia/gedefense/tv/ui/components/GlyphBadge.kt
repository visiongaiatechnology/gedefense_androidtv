package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.widget.FrameLayout
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * Circular glyph badge: a semantic icon (glyph + colour) on a tinted glass disc.
 *
 * Used as leading element of rows, checklist cards and metric tiles. The colour is decorative
 * reinforcement only - every use site also renders an explicit German label.
 */
class GlyphBadge @JvmOverloads constructor(
    context: Context,
    glyph: TvGlyph = TvGlyph.DOT,
    color: Int = TvTheme.accent,
    sizeDp: Int = 48,
) : FrameLayout(context) {

    private val glyphView = GlyphView(context, glyph, color, (sizeDp * 0.5f).toInt())
    private var currentColor: Int = color
    private var currentSizeDp: Int = sizeDp

    init {
        isFocusable = false
        isClickable = false
        applyBackground(color)
        addView(
            glyphView,
            LayoutParams(TvTheme.scaledDp(context, (sizeDp * 0.5f).toInt()), TvTheme.scaledDp(context, (sizeDp * 0.5f).toInt())).apply {
                gravity = Gravity.CENTER
            },
        )
    }

    fun set(glyph: TvGlyph, color: Int) {
        glyphView.glyph = glyph
        glyphView.glyphColor = color
        if (color != currentColor) {
            currentColor = color
            applyBackground(color)
        }
    }

    private fun applyBackground(color: Int) {
        background = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(alpha(color, 0.16f))
            setStroke(TvTheme.scaledDp(context, 1).coerceAtLeast(1), alpha(color, 0.55f))
        }
    }

    private fun alpha(color: Int, factor: Float): Int = android.graphics.Color.argb(
        (factor * 255).toInt().coerceIn(0, 255),
        android.graphics.Color.red(color),
        android.graphics.Color.green(color),
        android.graphics.Color.blue(color),
    )
}
