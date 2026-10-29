package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.view.Gravity
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.core.model.Finding
import de.visiongaia.gedefense.tv.core.model.TextCatalog
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * Rich finding row: severity badge, title, component/category meta and an explicit severity chip.
 * Opening the row pushes the finding detail. Status is always glyph + German label (never colour only).
 */
class FindingRow(context: Context) : LinearLayout(context) {

    private val badge = GlyphBadge(context, TvGlyph.ALERT, TvTheme.warning, 26)
    private val titleView = TvTheme.textView(context, "", TvTheme.TEXT_BODY_SP, TvTheme.textPrimary, bold = true).apply {
        maxLines = 2
        ellipsize = android.text.TextUtils.TruncateAt.END
    }
    private val metaView = TvTheme.textView(context, "", TvTheme.TEXT_MICRO_SP, TvTheme.textSecondary).apply {
        maxLines = 2
        ellipsize = android.text.TextUtils.TruncateAt.END
    }
    private val pill = StatusPill(context)
    private var currentTone: TvTone = TvTone.WARNING

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        minimumHeight = TvTheme.scaledDp(context, 44)
        isFocusable = true
        isFocusableInTouchMode = false
        isClickable = true
        setDefaultFocusHighlightEnabled(false)
        setBackgroundResource(R.drawable.sel_row_card)
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
            metaView,
            LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 2)
            },
        )
        addView(column, LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        addView(
            pill,
            LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                leftMargin = TvTheme.scaledDp(context, 10)
            },
        )
        setOnFocusChangeListener { _, hasFocus ->
            titleView.setTextColor(if (hasFocus) TvTheme.goldBright else TvTheme.textPrimary)
            animate()
                .scaleX(if (hasFocus) 1.006f else 1f)
                .scaleY(if (hasFocus) 1.006f else 1f)
                .setDuration(TvTheme.MOTION_FAST)
                .setInterpolator(DecelerateInterpolator())
                .start()
        }
    }

    fun bind(finding: Finding, catalog: TextCatalog) {
        val title = resolveText(catalog, finding.title) ?: finding.title.key
        val category = context.getString(categoryLabelRes(finding.category))
        titleView.text = title
        metaView.text = context.getString(R.string.findings_row_meta, category, finding.component)
        currentTone = severityTone(finding.severity)
        badge.set(severityGlyph(finding.severity), toneColor(context, currentTone))
        pill.set(
            severityGlyph(finding.severity),
            context.getString(severityLabelRes(finding.severity)),
            currentTone,
        )
        contentDescription = "${context.getString(severityLabelRes(finding.severity))}: $title"
    }
}
