package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.view.ViewGroup
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * Empty / unavailable state: semantic badge, heading, explanation and optional note. It explains
 * why nothing is shown and what can be done next instead of a decorative placeholder.
 */
class EmptyState @JvmOverloads constructor(
    context: Context,
    glyph: TvGlyph = TvGlyph.INFO,
) : LinearLayout(context) {

    private val badge = GlyphBadge(context, glyph, TvTheme.accent, 56)
    private val titleView = TvTheme.textView(context, "", TvTheme.TEXT_HEADING_SP, TvTheme.textPrimary, bold = true)
    private val messageView = TvTheme.textView(context, "", TvTheme.TEXT_BODY_SP, TvTheme.textSecondary).apply {
        setLineSpacing(0f, 1.16f)
        maxWidth = TvTheme.scaledDp(context, 980)
    }
    private val noteView = TvTheme.textView(context, "", TvTheme.TEXT_CAPTION_SP, TvTheme.textSecondary).apply {
        setLineSpacing(0f, 1.16f)
        maxWidth = TvTheme.scaledDp(context, 980)
        visibility = GONE
    }

    init {
        orientation = VERTICAL
        isFocusable = false
        clipChildren = false
        setPadding(0, TvTheme.scaledDp(context, 8), 0, TvTheme.scaledDp(context, 8))
        addView(
            badge,
            LayoutParams(TvTheme.scaledDp(context, 56), TvTheme.scaledDp(context, 56)).apply {
                bottomMargin = TvTheme.scaledDp(context, 18)
            },
        )
        addView(titleView)
        addView(
            messageView,
            LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 10)
            },
        )
        addView(
            noteView,
            LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 12)
            },
        )
    }

    fun set(glyph: TvGlyph, title: CharSequence, message: CharSequence, note: CharSequence? = null) {
        badge.set(glyph, TvTheme.accent)
        titleView.text = title
        messageView.text = message
        noteView.text = note ?: ""
        noteView.visibility = if (note.isNullOrBlank()) GONE else VISIBLE
    }
}
