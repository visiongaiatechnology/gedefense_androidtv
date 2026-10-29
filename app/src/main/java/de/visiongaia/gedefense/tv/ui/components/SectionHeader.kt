package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * Section heading: gold brand rule + 32sp heading + optional trailing meta label.
 * The rule is the recurring typographic signature that separates content zones without cards.
 */
class SectionHeader @JvmOverloads constructor(
    context: Context,
    title: CharSequence = "",
    meta: CharSequence? = null,
) : LinearLayout(context) {

    private val titleView = TvTheme.textView(
        context,
        title,
        TvTheme.TEXT_HEADING_SP,
        TvTheme.textPrimary,
        bold = true,
    )
    private val metaView = TvTheme.textView(context, meta ?: "", TvTheme.TEXT_MICRO_SP, TvTheme.textSecondary).apply {
        letterSpacing = 0.12f
        isAllCaps = true
    }

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        isFocusable = false
        setPadding(0, TvTheme.scaledDp(context, 4), 0, TvTheme.scaledDp(context, 8))
        addView(View(context).apply {
            setBackgroundColor(context.getColor(R.color.tv_accent))
            layoutParams = LinearLayout.LayoutParams(TvTheme.scaledDp(context, 3), TvTheme.scaledDp(context, 15)).apply {
                rightMargin = TvTheme.scaledDp(context, 8)
            }
        })
        addView(titleView)
        addView(
            metaView,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                leftMargin = TvTheme.scaledDp(context, 10)
            },
        )
        metaView.visibility = if (meta.isNullOrBlank()) GONE else VISIBLE
    }

    fun setMeta(text: CharSequence?) {
        metaView.text = text ?: ""
        metaView.visibility = if (text.isNullOrBlank()) GONE else VISIBLE
    }

    fun setTitle(text: CharSequence) {
        titleView.text = text
    }
}
