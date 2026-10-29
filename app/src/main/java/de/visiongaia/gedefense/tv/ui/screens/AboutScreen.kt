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
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.horizontalRow
import de.visiongaia.gedefense.tv.ui.components.patchStatusGlyph
import de.visiongaia.gedefense.tv.ui.components.patchStatusLabelRes
import de.visiongaia.gedefense.tv.ui.components.patchStatusTone
import de.visiongaia.gedefense.tv.ui.components.visibilityGlyph
import de.visiongaia.gedefense.tv.ui.components.visibilityLabelRes
import de.visiongaia.gedefense.tv.ui.components.visibilityTone

/**
 * About screen (2026 redesign): original GeDefense brand block, version/source identity and the
 * honest capability limits of a non-privileged TV app.
 */
internal class AboutScreen(services: TvServices) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.ABOUT

    override fun build(scaffold: ScreenScaffold) {
        val result = lastResult()

        scaffold.setEyebrow(text(R.string.about_eyebrow))
        scaffold.setTitle(text(R.string.about_title))
        scaffold.setSubtitle(text(R.string.about_subtitle))

        scaffold.content.addView(buildBrandBlock(), matchParams())

        scaffold.addSection(text(R.string.about_section_version))
        scaffold.content.addView(
            parameterPanel(
                infoRow(
                    text(R.string.settings_version),
                    text(R.string.about_version, services.appVersionName, services.appVersionCode),
                ),
                infoRow(text(R.string.about_publisher_label), text(R.string.about_publisher_value)),
                infoRow(text(R.string.about_source_label), context.packageName),
            ),
            matchParams(),
        )

        scaffold.addSection(text(R.string.about_section_limits))
        for (limitRes in listOf(
            R.string.about_limit_inventory,
            R.string.about_limit_network,
            R.string.about_limit_privileged,
            R.string.about_limit_firmware,
            R.string.about_limit_telemetry,
        )) {
            val row = FocusableRow(context, interactive = false)
            row.setLeading(TvGlyph.INFO, TvTheme.electricBlue)
            row.setTitle(text(limitRes))
            scaffold.content.addView(row, matchParams())
        }

        scaffold.addSection(text(R.string.about_section_collectors))
        scaffold.content.addView(bodyText(context, text(R.string.about_collectors_body)), matchParams())

        scaffold.addSection(text(R.string.about_section_device))
        if (result == null) {
            scaffold.content.addView(bodyText(context, text(R.string.about_device_none), TvTheme.textSecondary), matchParams())
        } else {
            val platform = result.platform
            scaffold.content.addView(
                parameterPanel(
                    infoRow(text(R.string.about_device_model), platform.displayModel),
                    infoRow(
                        text(R.string.about_device_android),
                        text(R.string.home_android_value, platform.androidRelease, platform.sdkInt),
                    ),
                    infoRowPill(
                        text(R.string.about_device_patch),
                        pill(
                            patchStatusGlyph(result.patch.status),
                            patchStatusLabelRes(result.patch.status),
                            patchStatusTone(result.patch.status),
                        ),
                    ),
                    infoRowPill(
                        text(R.string.home_label_coverage),
                        pill(visibilityGlyph(result.coverage), visibilityLabelRes(result.coverage), visibilityTone(result.coverage)),
                    ),
                ),
                matchParams(),
            )
        }

        scaffold.addSection(text(R.string.about_section_legal))
        scaffold.content.addView(bodyText(context, text(R.string.about_legal), TvTheme.textSecondary), matchParams())

        scaffold.addAction(
            primaryAction(R.string.action_back, TvGlyph.CHEVRON) { host.goBack() },
            primary = true,
        )
        scaffold.addAction(
            secondaryAction(R.string.action_open_settings, TvGlyph.SHIELD) { host.navigate(TvRoute.SETTINGS) },
        )
    }

    /** Original GeDefense logo lockup (VGT-owned asset) with product wordmark. */
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
            LinearLayout.LayoutParams(TvTheme.scaledDp(context, 120), TvTheme.scaledDp(context, 120)).apply {
                rightMargin = TvTheme.scaledDp(context, 24)
            },
        )
        val column = column()
        column.addView(TvTheme.textView(context, text(R.string.app_name), TvTheme.TEXT_TITLE_SP, TvTheme.textPrimary, bold = true))
        column.addView(
            TvTheme.textView(context, text(R.string.brand_rail_caption), TvTheme.TEXT_BODY_SP, TvTheme.accent),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 6)
            },
        )
        column.addView(
            bodyText(context, text(R.string.about_developer), TvTheme.textSecondary),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 8)
            },
        )
        row.addView(column, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        panel.addView(row)
        return panel
    }
}
