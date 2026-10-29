package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.LinearLayout
import android.widget.TextView
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * Generic row for checks, settings, collectors, feeds and evidence events.
 *
 * [interactive] rows are D-pad focusable (gold ring + gentle scale); static rows are plain reading
 * rows. [setCard] wraps a row as a standalone checklist card where a functional boundary exists.
 */
class FocusableRow @JvmOverloads constructor(
    context: Context,
    interactive: Boolean = true,
) : LinearLayout(context) {

    private val badge = GlyphBadge(context, TvGlyph.DOT, TvTheme.textSecondary, 26)
    private val titleView = TvTheme.textView(context, "", TvTheme.TEXT_BODY_SP, TvTheme.textPrimary).apply {
        maxLines = 2
        ellipsize = android.text.TextUtils.TruncateAt.END
    }
    private val subtitleView = TvTheme.textView(context, "", TvTheme.TEXT_MICRO_SP, TvTheme.textSecondary).apply {
        visibility = GONE
        maxLines = 2
        ellipsize = android.text.TextUtils.TruncateAt.END
    }
    private val trailingRow = horizontalRow(context)
    private val chevron = GlyphView(context, TvGlyph.CHEVRON, TvTheme.textSecondary, 16).apply {
        visibility = GONE
    }
    private var internalInteractive: Boolean = interactive
    private var cardStyle: Boolean = false

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        minimumHeight = TvTheme.scaledDp(context, 44)
        isFocusableInTouchMode = false
        setDefaultFocusHighlightEnabled(false)
        clipChildren = false
        setPadding(
            TvTheme.scaledDp(context, 12),
            TvTheme.scaledDp(context, 6),
            TvTheme.scaledDp(context, 12),
            TvTheme.scaledDp(context, 6),
        )
        addView(
            badge,
            LayoutParams(TvTheme.scaledDp(context, 26), TvTheme.scaledDp(context, 26)).apply {
                rightMargin = TvTheme.scaledDp(context, 8)
            },
        )
        val column = verticalColumn(context)
        column.addView(titleView)
        column.addView(
            subtitleView,
            LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 2)
            },
        )
        addView(column, LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        addView(trailingRow)
        addView(
            chevron,
            LayoutParams(TvTheme.scaledDp(context, 16), TvTheme.scaledDp(context, 16)).apply {
                leftMargin = TvTheme.scaledDp(context, 8)
            },
        )
        setInteractive(interactive)
        setOnFocusChangeListener { _, hasFocus ->
            titleView.setTextColor(if (hasFocus) TvTheme.goldBright else TvTheme.textPrimary)
            if (internalInteractive) {
                animate()
                    .scaleX(if (hasFocus) 1.006f else 1f)
                    .scaleY(if (hasFocus) 1.006f else 1f)
                    .setDuration(TvTheme.MOTION_FAST)
                    .setInterpolator(DecelerateInterpolator())
                    .start()
            }
        }
    }

    fun setInteractive(interactive: Boolean) {
        internalInteractive = interactive
        // Reading rows are D-pad focusable as well: content lists must be traversable with the
        // remote even when a row has no action of its own (OK does nothing on those rows).
        isFocusable = true
        isFocusableInTouchMode = false
        isClickable = interactive
        updateBackground()
    }

    /** Checklist-card variant: the row keeps a soft glass surface even when unfocused. */
    fun setCard(card: Boolean) {
        cardStyle = card
        updateBackground()
    }

    private fun updateBackground() {
        setBackgroundResource(if (cardStyle) R.drawable.sel_row_card else R.drawable.sel_row)
    }

    fun setLeading(glyph: TvGlyph?, color: Int = TvTheme.textSecondary) {
        if (glyph == null) {
            badge.visibility = GONE
        } else {
            badge.visibility = VISIBLE
            badge.set(glyph, color)
        }
    }

    fun setTitle(text: CharSequence) {
        titleView.text = text
        contentDescription = text
    }

    fun setSubtitle(text: CharSequence?) {
        subtitleView.text = text ?: ""
        subtitleView.visibility = if (text.isNullOrBlank()) GONE else VISIBLE
    }

    /** Reading rows that carry an explanation may need a third line (e.g. XDR incidents). */
    fun setSubtitleMaxLines(maxLines: Int) {
        subtitleView.maxLines = maxLines.coerceIn(1, 5)
    }

    fun setTrailing(view: View?) {
        trailingRow.removeAllViews()
        if (view != null) {
            trailingRow.addView(view)
            trailingRow.visibility = VISIBLE
        } else {
            trailingRow.visibility = GONE
        }
    }

    fun setChevronVisible(visible: Boolean) {
        chevron.visibility = if (visible) VISIBLE else GONE
    }

    fun addTrailingText(text: CharSequence, color: Int = TvTheme.textSecondary): TextView {
        val label = TvTheme.textView(context, text, TvTheme.TEXT_LABEL_SP, color)
        trailingRow.addView(label)
        trailingRow.visibility = VISIBLE
        return label
    }
}
