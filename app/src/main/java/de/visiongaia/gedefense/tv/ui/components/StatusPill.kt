package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.view.Gravity
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.ui.TvTheme

/** Semantic status tone. Colour is always paired with a glyph and a German label. */
enum class TvTone {
    NEUTRAL,
    SUCCESS,
    WARNING,
    DANGER,
    INFO,
    ACCENT,
}

fun toneColor(context: Context, tone: TvTone): Int = when (tone) {
    TvTone.NEUTRAL -> context.getColor(R.color.tv_text_secondary)
    TvTone.SUCCESS -> context.getColor(R.color.tv_success)
    TvTone.WARNING -> context.getColor(R.color.tv_warning)
    TvTone.DANGER -> context.getColor(R.color.tv_danger)
    TvTone.INFO -> context.getColor(R.color.tv_info)
    TvTone.ACCENT -> context.getColor(R.color.tv_accent)
}

fun toneBackgroundRes(tone: TvTone): Int = when (tone) {
    TvTone.NEUTRAL -> R.drawable.bg_pill_neutral
    TvTone.SUCCESS -> R.drawable.bg_pill_success
    TvTone.WARNING -> R.drawable.bg_pill_warning
    TvTone.DANGER -> R.drawable.bg_pill_danger
    TvTone.INFO -> R.drawable.bg_pill_info
    TvTone.ACCENT -> R.drawable.bg_pill_warning
}

/**
 * Status chip: glyph + German label on a tinted glass capsule.
 *
 * Informational only, never focusable - every action lives in a focusable control.
 */
class StatusPill @JvmOverloads constructor(
    context: Context,
    label: CharSequence = "",
    tone: TvTone = TvTone.NEUTRAL,
    glyph: TvGlyph = TvGlyph.DOT,
) : LinearLayout(context) {

    private val glyphView: GlyphView = GlyphView(context, glyph, toneColor(context, tone), 12)
    private val labelView = TvTheme.textView(context, label, TvTheme.TEXT_MICRO_SP, toneColor(context, tone), bold = true).apply {
        isSingleLine = true
        maxLines = 1
        ellipsize = android.text.TextUtils.TruncateAt.END
        maxWidth = TvTheme.scaledDp(context, 260)
    }

    private var currentTone: TvTone = tone

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        isFocusable = false
        isClickable = false
        setPadding(
            TvTheme.scaledDp(context, 8),
            TvTheme.scaledDp(context, 3),
            TvTheme.scaledDp(context, 10),
            TvTheme.scaledDp(context, 3),
        )
        setBackgroundResource(toneBackgroundRes(tone))
        addView(
            glyphView,
            LayoutParams(TvTheme.scaledDp(context, 14), TvTheme.scaledDp(context, 14)).apply {
                rightMargin = TvTheme.scaledDp(context, 6)
            },
        )
        addView(labelView)
        contentDescription = label
    }

    fun set(glyph: TvGlyph, label: CharSequence, tone: TvTone = currentTone) {
        if (currentTone != tone) {
            currentTone = tone
            setBackgroundResource(toneBackgroundRes(tone))
            glyphView.glyphColor = toneColor(context, tone)
            labelView.setTextColor(toneColor(context, tone))
        }
        glyphView.glyph = glyph
        labelView.text = label
        contentDescription = label
    }

    fun set(glyph: TvGlyph, labelRes: Int, tone: TvTone) {
        set(glyph, context.getString(labelRes), tone)
    }

    fun clear() {
        visibility = GONE
    }
}
