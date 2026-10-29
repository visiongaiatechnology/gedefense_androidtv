package de.visiongaia.gedefense.tv.ui.screens

import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.GlassPanel
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.addSpacer
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.horizontalRow
import de.visiongaia.gedefense.tv.ui.components.readService

/**
 * Settings (2026 redesign): original logo brand block, only settings that actually take effect are
 * interactive. Evidence retention is informational (automatic rotation is V2); the destructive
 * delete action lives in EVIDENCE behind a two-step confirmation. Telemetry is a statement.
 */
internal class SettingsScreen(services: TvServices) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.SETTINGS

    private var firstRow: View? = null

    override fun initialFocus(): View? = firstRow ?: super.initialFocus()

    override fun build(scaffold: ScreenScaffold) {
        scaffold.setEyebrow(text(R.string.settings_eyebrow))
        scaffold.setTitle(text(R.string.settings_title))
        scaffold.setSubtitle(text(R.string.settings_subtitle))

        scaffold.content.addView(buildBrandBlock(), matchParams())

        scaffold.addSection(text(R.string.settings_section_data))
        val autoSync = buildAutoSyncRow()
        firstRow = autoSync
        scaffold.content.addView(autoSync, matchParams())
        scaffold.content.addSpacer(10)
        scaffold.content.addView(buildRetentionInfoRow(), matchParams())

        scaffold.addSection(text(R.string.settings_section_appearance))
        scaffold.content.addView(buildUiScaleRow(), matchParams())

        scaffold.addSection(text(R.string.settings_section_privacy))
        scaffold.content.addView(
            noticePanel(
                TvGlyph.SHIELD,
                TvTone.INFO,
                text(R.string.settings_telemetry_title),
                text(R.string.settings_telemetry_body),
            ),
            matchParams(),
        )
        scaffold.content.addSpacer(12)
        scaffold.content.addView(
            noticePanel(
                TvGlyph.CHECK,
                TvTone.NEUTRAL,
                text(R.string.settings_local_processing),
                text(R.string.settings_local_processing_body),
            ),
            matchParams(),
        )

        scaffold.addSection(text(R.string.settings_section_app))
        scaffold.content.addView(
            parameterPanel(
                infoRow(text(R.string.settings_version), text(R.string.about_version, services.appVersionName, services.appVersionCode)),
                infoRow(text(R.string.settings_device_id), services.deviceId),
            ),
            matchParams(),
        )

        val aboutRow = FocusableRow(context, interactive = true)
        aboutRow.setLeading(TvGlyph.SHIELD, TvTheme.accent)
        aboutRow.setTitle(text(R.string.settings_about_row))
        aboutRow.setSubtitle(text(R.string.settings_about_row_desc))
        aboutRow.setChevronVisible(true)
        aboutRow.setOnClickListener { host.navigate(TvRoute.ABOUT) }
        scaffold.content.addView(aboutRow, matchParams())

        val evidenceRow = FocusableRow(context, interactive = true)
        evidenceRow.setLeading(TvGlyph.EXPORT, TvTheme.electricBlue)
        evidenceRow.setTitle(text(R.string.settings_open_evidence))
        evidenceRow.setSubtitle(text(R.string.settings_open_evidence_desc))
        evidenceRow.setChevronVisible(true)
        evidenceRow.setOnClickListener { host.navigate(TvRoute.EVIDENCE) }
        scaffold.content.addView(evidenceRow, matchParams())

        scaffold.addSection(text(R.string.settings_section_limits))
        scaffold.content.addView(bodyText(context, text(R.string.settings_limits_body), TvTheme.textSecondary), matchParams())

        scaffold.hideActions()
    }

    private fun buildBrandBlock(): View {
        val panel = GlassPanel(context, soft = true)
        val row = horizontalRow(context)
        val logo = ImageView(context).apply {
            setImageResource(R.drawable.gedefense_logo)
            scaleType = ImageView.ScaleType.FIT_CENTER
            contentDescription = text(R.string.brand_logo_description)
        }
        row.addView(
            logo,
            LinearLayout.LayoutParams(TvTheme.scaledDp(context, 84), TvTheme.scaledDp(context, 84)).apply {
                rightMargin = TvTheme.scaledDp(context, 20)
            },
        )
        val column = column()
        column.addView(TvTheme.textView(context, text(R.string.app_name), TvTheme.TEXT_HEADING_SP, TvTheme.textPrimary, bold = true))
        column.addView(
            bodyText(context, text(R.string.brand_rail_caption), TvTheme.accent),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 4)
            },
        )
        row.addView(column, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        panel.addView(row)
        return panel
    }

    private fun buildAutoSyncRow(): FocusableRow {
        val enabled = readService { services.settings.tiAutoSyncEnabled() } ?: false
        val row = FocusableRow(context, interactive = true)
        row.setCard(true)
        row.setLeading(TvGlyph.REFRESH, TvTheme.electricBlue)
        row.setTitle(text(R.string.settings_ti_auto_sync))
        row.setSubtitle(text(R.string.settings_ti_auto_sync_desc))
        val pill = StatusPill(
            context,
            text(if (enabled) R.string.settings_state_enabled else R.string.settings_state_disabled),
            if (enabled) TvTone.SUCCESS else TvTone.NEUTRAL,
            if (enabled) TvGlyph.CHECK else TvGlyph.CROSS,
        )
        row.setTrailing(pill)
        row.contentDescription = "${text(R.string.settings_ti_auto_sync)}: " +
            text(if (enabled) R.string.settings_state_enabled else R.string.settings_state_disabled)
        row.setOnClickListener {
            val next = readService { services.settings.tiAutoSyncEnabled() }?.not() ?: true
            readService { services.settings.setTiAutoSyncEnabled(next) }
            readService { services.threatIntel.schedulePeriodicSync(next) }
            pill.set(
                if (next) TvGlyph.CHECK else TvGlyph.CROSS,
                text(if (next) R.string.settings_state_enabled else R.string.settings_state_disabled),
                if (next) TvTone.SUCCESS else TvTone.NEUTRAL,
            )
            row.contentDescription = "${text(R.string.settings_ti_auto_sync)}: " +
                text(if (next) R.string.settings_state_enabled else R.string.settings_state_disabled)
            notify(text(if (next) R.string.settings_state_enabled else R.string.settings_state_disabled))
        }
        return row
    }

    /** Informational row only: automatic retention/pruning is deferred and must not look active. */
    private fun buildRetentionInfoRow(): FocusableRow {
        val row = FocusableRow(context, interactive = false)
        row.setCard(true)
        row.setLeading(TvGlyph.CLOCK, TvTheme.accent)
        row.setTitle(text(R.string.settings_retention_info_title))
        row.setSubtitle(text(R.string.settings_retention_info_body))
        row.setTrailing(
            StatusPill(context, text(R.string.settings_retention_info_value), TvTone.NEUTRAL, TvGlyph.INFO),
        )
        return row
    }

    /**
     * User-adjustable UI scale: cycle through compact / normal / large. The value is persisted,
     * applied to [TvTheme.userScale] and the current screen is rebuilt immediately; the rail is
     * owned by the shell and picks the new scale up after the next app start (stated in the hint).
     */
    private fun buildUiScaleRow(): FocusableRow {
        val current = currentUiScale()
        val row = FocusableRow(context, interactive = true)
        row.setCard(true)
        row.setLeading(TvGlyph.INFO, TvTheme.accent)
        row.setTitle(text(R.string.settings_ui_scale_label))
        row.setSubtitle(text(R.string.settings_ui_scale_desc) + " " + text(R.string.settings_ui_scale_hint))
        val pill = StatusPill(context, text(uiScaleLabelRes(current)), TvTone.NEUTRAL, TvGlyph.INFO)
        row.setTrailing(pill)
        row.contentDescription = "${text(R.string.settings_ui_scale_label)}: ${text(uiScaleLabelRes(current))}"
        row.setOnClickListener {
            val actual = currentUiScale()
            val nearestIndex = UI_SCALE_STAGES.indices.minByOrNull {
                kotlin.math.abs(UI_SCALE_STAGES[it] - actual)
            } ?: 1
            val next = UI_SCALE_STAGES[(nearestIndex + 1) % UI_SCALE_STAGES.size]
            readService { services.settings.setUiScale(next) }
            TvTheme.userScale = next
            pill.set(TvGlyph.INFO, text(uiScaleLabelRes(next)), TvTone.NEUTRAL)
            row.contentDescription = "${text(R.string.settings_ui_scale_label)}: ${text(uiScaleLabelRes(next))}"
            notify(text(R.string.settings_ui_scale_changed, text(uiScaleLabelRes(next))))
            host.refreshCurrent()
        }
        return row
    }

    private fun currentUiScale(): Float {
        val stored = readService { services.settings.uiScale() } ?: TvTheme.userScale
        return stored.coerceIn(UI_SCALE_MIN, UI_SCALE_MAX)
    }

    private fun uiScaleLabelRes(scale: Float): Int = when {
        scale < 0.925f -> R.string.settings_ui_scale_compact
        scale > 1.075f -> R.string.settings_ui_scale_large
        else -> R.string.settings_ui_scale_normal
    }

    private companion object {
        const val UI_SCALE_MIN = 0.85f
        const val UI_SCALE_MAX = 1.15f
        val UI_SCALE_STAGES = listOf(0.85f, 1.00f, 1.15f)
    }
}
