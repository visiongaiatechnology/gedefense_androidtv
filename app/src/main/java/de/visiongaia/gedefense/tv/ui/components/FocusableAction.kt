package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.view.Gravity
import android.view.animation.DecelerateInterpolator
import android.widget.LinearLayout
import android.widget.TextView
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * The single interactive control of the TV UI: focusable, OK-activatable, gold primary /
 * glass secondary / signal-red destructive, with a 4dp bright-gold focus ring and a gentle 1.02
 * focus scale (140 ms). No hover/touch dependency.
 */
class FocusableAction @JvmOverloads constructor(
    context: Context,
    label: CharSequence = "",
    style: Style = Style.SECONDARY,
    glyph: TvGlyph? = null,
) : LinearLayout(context) {

    enum class Style { PRIMARY, SECONDARY, DANGER }

    private val labelView: TextView
    private val glyphView: GlyphView?
    private val actionStyle: Style = style

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        isFocusable = true
        isFocusableInTouchMode = false
        isClickable = true
        setDefaultFocusHighlightEnabled(false)
        minimumHeight = TvTheme.scaledDp(context, 36)
        setPadding(
            TvTheme.scaledDp(context, 14),
            TvTheme.scaledDp(context, 6),
            TvTheme.scaledDp(context, 14),
            TvTheme.scaledDp(context, 6),
        )
        setBackgroundResource(backgroundRes(style))

        glyphView = glyph?.let {
            GlyphView(context, it, labelColor(style, focused = false), 14).apply {
                layoutParams = LayoutParams(TvTheme.scaledDp(context, 14), TvTheme.scaledDp(context, 14)).apply {
                    rightMargin = TvTheme.scaledDp(context, 6)
                }
            }
        }
        labelView = TvTheme.textView(
            context,
            label,
            TvTheme.TEXT_LABEL_SP,
            labelColor(style, focused = false),
            bold = true,
        ).apply {
            letterSpacing = 0.02f
            isSingleLine = true
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
            maxWidth = TvTheme.scaledDp(context, 300)
        }
        glyphView?.let { addView(it) }
        addView(labelView)
        contentDescription = label
        setOnFocusChangeListener { _, hasFocus ->
            applyFocusState(hasFocus)
            animate()
                .scaleX(if (hasFocus) 1.02f else 1f)
                .scaleY(if (hasFocus) 1.02f else 1f)
                .setDuration(TvTheme.MOTION_FAST)
                .setInterpolator(DecelerateInterpolator())
                .start()
        }
    }

    fun setLabel(text: CharSequence) {
        labelView.text = text
        contentDescription = text
    }

    fun setActionEnabled(enabled: Boolean) {
        isEnabled = enabled
        isFocusable = enabled
        alpha = if (enabled) 1f else 0.45f
    }

    private fun applyFocusState(hasFocus: Boolean) {
        labelView.setTextColor(if (hasFocus) focusedColor(actionStyle) else labelColor(actionStyle, focused = false))
        glyphView?.glyphColor = if (hasFocus) focusedColor(actionStyle) else labelColor(actionStyle, focused = false)
    }

    private fun focusedColor(style: Style): Int = when (style) {
        // Dark obsidian label stays on the bright gold ring for maximum contrast.
        Style.PRIMARY -> TvTheme.bgDeep
        Style.SECONDARY -> TvTheme.goldBright
        Style.DANGER -> TvTheme.textPrimary
    }

    private fun labelColor(style: Style, focused: Boolean): Int = when (style) {
        Style.PRIMARY -> TvTheme.bgDeep
        Style.SECONDARY -> if (focused) TvTheme.goldBright else TvTheme.textSecondary
        Style.DANGER -> if (focused) TvTheme.textPrimary else TvTheme.danger
    }

    private fun backgroundRes(style: Style): Int = when (style) {
        Style.PRIMARY -> R.drawable.sel_action_primary
        Style.SECONDARY -> R.drawable.sel_action_secondary
        Style.DANGER -> R.drawable.sel_action_danger
    }

    companion object {
        fun primary(context: Context, labelRes: Int, glyph: TvGlyph? = null): FocusableAction =
            FocusableAction(context, context.getString(labelRes), Style.PRIMARY, glyph)

        fun secondary(context: Context, labelRes: Int, glyph: TvGlyph? = null): FocusableAction =
            FocusableAction(context, context.getString(labelRes), Style.SECONDARY, glyph)

        fun danger(context: Context, labelRes: Int, glyph: TvGlyph? = null): FocusableAction =
            FocusableAction(context, context.getString(labelRes), Style.DANGER, glyph)
    }
}
