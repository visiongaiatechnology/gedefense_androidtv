package de.visiongaia.gedefense.tv.ui.titan

import android.content.Context
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.core.titan.model.TitanCapability
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeLevel
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableAction
import de.visiongaia.gedefense.tv.ui.components.GlassPanel
import de.visiongaia.gedefense.tv.ui.components.GlyphBadge
import de.visiongaia.gedefense.tv.ui.components.GlyphView
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.captionText
import de.visiongaia.gedefense.tv.ui.components.horizontalRow
import de.visiongaia.gedefense.tv.ui.components.toneColor
import de.visiongaia.gedefense.tv.ui.components.visibilityGlyph
import de.visiongaia.gedefense.tv.ui.components.visibilityLabelRes
import de.visiongaia.gedefense.tv.ui.components.visibilityTone
import de.visiongaia.gedefense.tv.ui.components.verticalColumn

/**
 * Titan status hero: confirmed privilege level, honest visibility, the seven capability shields and
 * the single activation control.
 *
 * The hero never shows a score. A capability is rendered as active only when the effective capability
 * set of the composed status contains it; otherwise it is labelled "Nicht verfügbar".
 */
internal class TitanStatusHero(context: Context) : GlassPanel(context) {

    /** Activation control, non-null only when a real channel marker was detected. */
    var activateAction: FocusableAction? = null
        private set

    private val levelBadge = GlyphBadge(context, TvGlyph.HALF, TvTheme.textSecondary, 56)
    private val levelTitle = TvTheme.textView(context, "", TvTheme.TEXT_HEADING_SP, TvTheme.textPrimary, bold = true)
    private val claimView = bodyText(context, "").apply {
        maxWidth = TvTheme.scaledDp(context, 640)
    }
    private val chipRow = horizontalRow(context)
    private val visibilityPill = StatusPill(context, "", TvTone.NEUTRAL, TvGlyph.HALF)
    private val outcomePill = StatusPill(context, "", TvTone.NEUTRAL, TvGlyph.CLOCK)
    private val lastScanView = captionText(context, "")
    private val capabilityLabel = TvTheme.sectionLabel(context, context.getString(R.string.titan_section_capabilities)).apply {
        setTextColor(TvTheme.accent)
    }
    private val capabilityGrid = verticalColumn(context)
    private val explanationTitle = TvTheme.textView(
        context,
        "",
        TvTheme.TEXT_LABEL_SP,
        TvTheme.accent,
        bold = true,
    )
    private val explanationBody = bodyText(context, "").apply {
        maxWidth = TvTheme.scaledDp(context, 760)
    }
    private val explanationNote = captionText(context, "").apply {
        maxWidth = TvTheme.scaledDp(context, 760)
    }
    private val channelNote = captionText(context, "").apply {
        maxWidth = TvTheme.scaledDp(context, 760)
        setTextColor(TvTheme.textPrimary)
    }
    private val actionRow = horizontalRow(context)
    private val hintView = captionText(context, "").apply {
        maxWidth = TvTheme.scaledDp(context, 760)
    }
    private val containmentPill = StatusPill(context, "", TvTone.WARNING, TvGlyph.LOCK)

    init {
        orientation = VERTICAL

        val topRow = horizontalRow(context)
        topRow.gravity = Gravity.TOP
        topRow.addView(
            levelBadge,
            LinearLayout.LayoutParams(TvTheme.scaledDp(context, 56), TvTheme.scaledDp(context, 56)).apply {
                rightMargin = TvTheme.scaledDp(context, 14)
            },
        )
        val column = verticalColumn(context)
        column.addView(levelTitle)
        column.addView(
            claimView,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 3)
            },
        )
        chipRow.addView(visibilityPill)
        chipRow.addView(
            outcomePill,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                leftMargin = TvTheme.scaledDp(context, 8)
            },
        )
        column.addView(
            chipRow,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 8)
            },
        )
        column.addView(
            lastScanView,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 6)
            },
        )
        topRow.addView(column, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        addView(topRow, matchWidth())

        addView(
            capabilityLabel,
            matchWidth().apply { topMargin = TvTheme.scaledDp(context, 16) },
        )
        addView(
            capabilityGrid,
            matchWidth().apply { topMargin = TvTheme.scaledDp(context, 4) },
        )

        addView(
            explanationTitle,
            matchWidth().apply { topMargin = TvTheme.scaledDp(context, 16) },
        )
        addView(
            explanationBody,
            matchWidth().apply { topMargin = TvTheme.scaledDp(context, 4) },
        )
        addView(
            explanationNote,
            matchWidth().apply { topMargin = TvTheme.scaledDp(context, 6) },
        )
        addView(
            channelNote,
            matchWidth().apply { topMargin = TvTheme.scaledDp(context, 6) },
        )
        addView(
            actionRow,
            matchWidth().apply { topMargin = TvTheme.scaledDp(context, 12) },
        )
        addView(
            hintView,
            matchWidth().apply { topMargin = TvTheme.scaledDp(context, 8) },
        )
    }

    fun bind(
        status: TitanStatus,
        activationAvailable: Boolean,
        activateLabelRes: Int,
        onActivate: (() -> Unit)?,
    ) {
        levelBadge.set(TitanText.levelGlyph(status.level), toneColor(context, TitanText.levelTone(status.level)))
        levelTitle.text = context.getString(TitanText.levelLabelRes(status.level))
        claimView.text = context.getString(TitanText.claimRes(status.level))

        visibilityPill.set(
            visibilityGlyph(status.visibility),
            context.getString(visibilityLabelRes(status.visibility)),
            visibilityTone(status.visibility),
        )
        outcomePill.set(
            TitanText.outcomeGlyph(status.lastScanOutcome),
            context.getString(TitanText.outcomeLabelRes(status.lastScanOutcome)),
            TitanText.outcomeTone(status.lastScanOutcome),
        )
        lastScanView.text = if (status.lastScanAtMillis > 0L) {
            context.getString(R.string.titan_last_scan, TvFormat.relative(context, status.lastScanAtMillis))
        } else {
            context.getString(R.string.value_never)
        }
        if (status.activeContainments > 0) {
            containmentPill.set(
                TvGlyph.LOCK,
                context.getString(R.string.titan_active_containments, status.activeContainments),
                TvTone.WARNING,
            )
            if (containmentPill.parent == null) {
                chipRow.addView(
                    containmentPill,
                    LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                    ).apply { leftMargin = TvTheme.scaledDp(context, 8) },
                )
            }
        }

        buildCapabilityGrid(status)

        val standardLevel = status.level == TitanPrivilegeLevel.STANDARD
        explanationTitle.visibility = if (standardLevel) VISIBLE else GONE
        explanationBody.visibility = if (standardLevel) VISIBLE else GONE
        explanationNote.visibility = if (standardLevel) VISIBLE else GONE
        if (standardLevel) {
            explanationTitle.text = context.getString(R.string.titan_level1_title)
            explanationBody.text = context.getString(R.string.titan_level1_body)
            explanationNote.text = context.getString(R.string.titan_level1_unavailable)
        }

        val showNoChannel = standardLevel && !activationAvailable
        channelNote.visibility = if (showNoChannel) VISIBLE else GONE
        if (showNoChannel) channelNote.text = context.getString(R.string.titan_no_channel_body)

        actionRow.removeAllViews()
        activateAction = null
        hintView.visibility = GONE
        if (activationAvailable && onActivate != null) {
            val action = FocusableAction.primary(context, activateLabelRes, TvGlyph.SHIELD).apply {
                setOnClickListener { onActivate() }
            }
            actionRow.addView(action)
            activateAction = action
            hintView.text = context.getString(R.string.titan_activation_hint)
            hintView.visibility = VISIBLE
        }
        actionRow.visibility = if (actionRow.childCount > 0) VISIBLE else GONE
    }

    private fun buildCapabilityGrid(status: TitanStatus) {
        capabilityGrid.removeAllViews()
        val capabilities = TitanCapability.values().toList()
        capabilities.chunked(CAPABILITIES_PER_ROW).forEachIndexed { rowIndex, rowCapabilities ->
            val row = horizontalRow(context)
            rowCapabilities.forEachIndexed { index, capability ->
                row.addView(
                    capabilityTile(capability, status.has(capability)),
                    LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                        if (index < rowCapabilities.lastIndex) rightMargin = TvTheme.scaledDp(context, 10)
                    },
                )
            }
            // Keep the 4-column grid aligned when the last row is shorter.
            repeat(CAPABILITIES_PER_ROW - rowCapabilities.size) {
                row.addView(View(context), LinearLayout.LayoutParams(0, 1, 1f))
            }
            capabilityGrid.addView(
                row,
                matchWidth().apply { if (rowIndex > 0) topMargin = TvTheme.scaledDp(context, 6) },
            )
        }
    }

    private fun capabilityTile(capability: TitanCapability, available: Boolean): View {
        val tile = horizontalRow(context)
        val color = if (available) toneColor(context, TvTone.SUCCESS) else TvTheme.textSecondary
        tile.addView(
            GlyphView(context, TitanText.capabilityGlyph(capability), color, 16),
            LinearLayout.LayoutParams(TvTheme.scaledDp(context, 16), TvTheme.scaledDp(context, 16)).apply {
                rightMargin = TvTheme.scaledDp(context, 7)
                gravity = Gravity.CENTER_VERTICAL
            },
        )
        val column = verticalColumn(context)
        column.addView(
            TvTheme.textView(
                context,
                context.getString(TitanText.capabilityLabelRes(capability)),
                TvTheme.TEXT_MICRO_SP,
                TvTheme.textPrimary,
                bold = true,
            ),
        )
        column.addView(
            TvTheme.textView(
                context,
                context.getString(
                    if (available) R.string.titan_capability_active else R.string.titan_capability_inactive,
                ),
                TvTheme.TEXT_MICRO_SP,
                color,
            ),
        )
        tile.addView(column, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        return tile
    }

    private fun matchWidth(): LinearLayout.LayoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
    )

    private companion object {
        const val CAPABILITIES_PER_ROW = 4
    }
}
