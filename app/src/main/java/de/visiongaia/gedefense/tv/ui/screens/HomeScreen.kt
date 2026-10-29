package de.visiongaia.gedefense.tv.ui.screens

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.contract.ScanSummary
import de.visiongaia.gedefense.tv.contract.VpnStateListener
import de.visiongaia.gedefense.tv.core.model.CapabilityState
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.PostureBand
import de.visiongaia.gedefense.tv.core.model.ScanResult
import de.visiongaia.gedefense.tv.core.model.VpnState
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FindingRow
import de.visiongaia.gedefense.tv.ui.components.FocusableAction
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.GlassPanel
import de.visiongaia.gedefense.tv.ui.components.MetricTile
import de.visiongaia.gedefense.tv.ui.components.RingGaugeView
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.SectionHeader
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.captionText
import de.visiongaia.gedefense.tv.ui.components.horizontalRow
import de.visiongaia.gedefense.tv.ui.components.patchStatusGlyph
import de.visiongaia.gedefense.tv.ui.components.patchStatusLabelRes
import de.visiongaia.gedefense.tv.ui.components.patchStatusTone
import de.visiongaia.gedefense.tv.ui.components.postureBandGlyph
import de.visiongaia.gedefense.tv.ui.components.postureBandLabelRes
import de.visiongaia.gedefense.tv.ui.components.postureBandTone
import de.visiongaia.gedefense.tv.ui.components.readService
import de.visiongaia.gedefense.tv.ui.components.scanStateLabelRes
import de.visiongaia.gedefense.tv.ui.components.visibilityGlyph
import de.visiongaia.gedefense.tv.ui.components.visibilityLabelRes
import de.visiongaia.gedefense.tv.ui.components.visibilityTone
import de.visiongaia.gedefense.tv.ui.components.vpnStateGlyph
import de.visiongaia.gedefense.tv.ui.components.vpnStateLabelRes
import de.visiongaia.gedefense.tv.ui.components.vpnStateTone

/**
 * TV Home dashboard:
 * - Hero row with circular posture gauge, status pill, last scan info and inline action button
 * - Streamlined 4-tile KPI row (Android release, detected apps, threat feeds, scan status)
 * - 2-Column bottom section: Left = Top-Befunde (with link to full findings), Right = Gerät & Prüfumfang
 * - Designed to fit completely within 1080p, 2K and 4K viewports without clipping or hidden scrolls
 */
internal class HomeScreen(services: TvServices) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.HOME

    override fun build(scaffold: ScreenScaffold) {
        scaffold.hideHeader()

        val result = lastResult()
        val summary = if (result == null) lastSummary() else null
        val uiState = scanUiState()
        val running = uiState?.running == true
        val threat = readService { services.threatIntel.status() }

        val uiScale = TvTheme.userScale.coerceAtLeast(0.1f)
        val heroHeightDp = (124f / uiScale).toInt()
        val ringDp = (82f / uiScale).toInt()
        val heroHeightPx = TvTheme.dp(context, heroHeightDp)

        // 1. Hero Card
        scaffold.content.addView(
            buildHero(scaffold, result, summary, running, heroHeightPx, ringDp),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, heroHeightPx),
        )

        // 2. Metric KPI row
        scaffold.content.addView(
            buildMetricGrid(result, summary, threat),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 8)
            },
        )

        // 3. V2 protection widget + XDR entry (compact, one focus stop each)
        scaffold.content.addView(
            buildProtectionWidget(),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 8)
            },
        )
        scaffold.content.addView(
            buildXdrRow(),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 6)
            },
        )

        // 4. Two-Column Dashboard Section: Left = Top-Befunde, Right = Gerät & Prüfumfang
        val twoColRow = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = TvTheme.scaledDp(context, 10)
            }
        }

        val leftCol = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.54f).apply {
                rightMargin = TvTheme.scaledDp(context, 14)
            }
        }
        buildFindingsColumn(leftCol, result, summary)

        val rightCol = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.46f)
        }
        buildDeviceColumn(rightCol, result, summary)

        twoColRow.addView(leftCol)
        twoColRow.addView(rightCol)
        scaffold.content.addView(twoColRow)
    }

    // -------------------------------------------------------------------- hero

    private fun buildHero(
        scaffold: ScreenScaffold,
        result: ScanResult?,
        summary: ScanSummary?,
        running: Boolean,
        heroHeightPx: Int,
        ringDp: Int,
    ): View {
        val hero = FrameLayout(context).apply {
            clipChildren = false
            background = TvTheme.heroBackground(context)
        }
        val watermarkWidthPx = (heroHeightPx * 1.3f).toInt()
        val watermark = ImageView(context).apply {
            val bitmap = decodeWatermark(context, watermarkWidthPx)
            if (bitmap != null) setImageBitmap(bitmap) else setImageResource(R.drawable.brand_watermark)
            scaleType = ImageView.ScaleType.FIT_CENTER
            alpha = 0.16f
            contentDescription = null
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        }
        hero.addView(
            watermark,
            FrameLayout.LayoutParams(
                watermarkWidthPx,
                heroHeightPx,
                Gravity.END or Gravity.CENTER_VERTICAL,
            ),
        )

        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(
                TvTheme.scaledDp(context, 14),
                TvTheme.scaledDp(context, 8),
                TvTheme.scaledDp(context, 16),
                TvTheme.scaledDp(context, 8),
            )
        }

        val band = result?.score?.band ?: summary?.band
        val scoreValue = result?.score?.value ?: summary?.scoreValue
        val coverage = result?.coverage ?: summary?.coverage
        val ring = RingGaugeView(context, ringDp)
        val (tone, highlight) = ringColors(band)
        ring.setScore(scoreValue, tone, highlight)
        row.addView(
            ring,
            LinearLayout.LayoutParams(TvTheme.dp(context, ringDp), TvTheme.dp(context, ringDp)).apply {
                rightMargin = TvTheme.scaledDp(context, 14)
            },
        )

        val column = column()
        column.addView(
            TvTheme.textView(context, text(R.string.home_hero_eyebrow), TvTheme.TEXT_MICRO_SP, TvTheme.accent, bold = true).apply {
                letterSpacing = 0.18f
                isAllCaps = true
            },
        )
        column.addView(
            TvTheme.textView(context, text(R.string.home_hero_title), TvTheme.TEXT_HEADING_SP, TvTheme.textPrimary, bold = true),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 2)
            },
        )

        val lastCheckLine = when {
            result != null -> text(
                R.string.home_hero_last_check,
                TvFormat.dateTime(context, result.completedAtMillis),
                text(scanStateLabelRes(result.state)),
            )

            summary != null -> text(
                R.string.home_hero_last_check,
                TvFormat.dateTime(context, summary.completedAtMillis),
                text(scanStateLabelRes(summary.state)),
            )

            else -> text(R.string.home_hero_never_checked)
        }
        column.addView(
            TvTheme.textView(context, lastCheckLine, TvTheme.TEXT_MICRO_SP, TvTheme.textSecondary),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 2)
            },
        )

        val chips = horizontalRow(context)
        if (band != null) {
            chips.addView(
                StatusPill(context, text(postureBandLabelRes(band)), postureBandTone(band), postureBandGlyph(band)),
            )
        }
        if (coverage != null) {
            chips.addView(
                StatusPill(context, text(visibilityLabelRes(coverage)), visibilityTone(coverage), visibilityGlyph(coverage)),
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    leftMargin = TvTheme.scaledDp(context, 6)
                },
            )
        }
        column.addView(
            chips,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 5)
            },
        )

        row.addView(column, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))

        // Hero CTA button placed on the right side of the card
        val ctaLabel = when {
            running -> R.string.action_show_progress
            result == null && summary == null -> R.string.action_start_check
            else -> R.string.action_rerun_check
        }
        val cta = FocusableAction.primary(context, ctaLabel, TvGlyph.SHIELD).apply {
            setOnClickListener { host.navigate(TvRoute.CHECK) }
        }
        scaffold.setPrimaryFocus(cta)
        row.addView(
            cta,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                leftMargin = TvTheme.scaledDp(context, 12)
            },
        )

        hero.addView(
            row,
            FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT),
        )
        return hero
    }

    private fun ringColors(band: PostureBand?): Pair<Int, Int> = when (band) {
        PostureBand.STRONG -> TvTheme.success to TvTheme.goldBright
        PostureBand.MODERATE -> TvTheme.accent to TvTheme.goldBright
        PostureBand.WEAK -> TvTheme.warning to TvTheme.goldBright
        else -> TvTheme.textSecondary to TvTheme.electricBlue
    }

    // ------------------------------------------------------------- KPI tiles

    private fun buildMetricGrid(
        result: ScanResult?,
        summary: ScanSummary?,
        threat: de.visiongaia.gedefense.tv.core.model.ThreatIntelStatus?,
    ): View {
        val androidValue = result?.platform?.androidRelease ?: text(R.string.home_metric_no_data)
        val appsValue = result?.inventory?.apps?.size?.toString() ?: text(R.string.home_metric_no_data)
        val feedsValue = if (threat != null && threat.availableCount > 0) {
            "${threat.freshCount}/${threat.availableCount}"
        } else {
            text(R.string.home_metric_no_data)
        }
        val supported = result?.collectorResults?.count { it.capability == CapabilityState.SUPPORTED }
        val total = result?.collectorResults?.size
        val collectorsValue = when {
            supported != null && total != null && total > 0 -> "$supported/$total"
            summary != null -> summary.collectorCount.toString()
            else -> text(R.string.home_metric_no_data)
        }
        val coverage = result?.coverage ?: summary?.coverage
        val hasData = result != null || summary != null
        val valueColor = if (hasData) TvTheme.textPrimary else TvTheme.textSecondary

        val row = horizontalRow(context)
        row.gravity = Gravity.CENTER_VERTICAL
        row.addView(
            metricTile(
                TvGlyph.SHIELD,
                TvTheme.accent,
                androidValue,
                text(R.string.home_metric_android),
                valueColor,
            ),
            tileParams(rightMargin = true),
        )
        row.addView(
            metricTile(
                TvGlyph.EYE,
                TvTheme.electricBlue,
                appsValue,
                text(R.string.home_metric_apps),
                valueColor,
            ),
            tileParams(rightMargin = true),
        )
        row.addView(
            metricTile(
                TvGlyph.REFRESH,
                TvTheme.electricBlue,
                feedsValue,
                text(R.string.home_metric_feeds),
                valueColor,
            ),
            tileParams(rightMargin = true),
        )
        row.addView(
            metricTile(
                TvGlyph.CHECK,
                if (coverage == DataVisibility.FULL) TvTheme.success else TvTheme.accent,
                collectorsValue,
                text(R.string.home_metric_collectors),
                valueColor,
            ),
            tileParams(rightMargin = false),
        )
        return row
    }

    private fun metricTile(
        glyph: TvGlyph,
        glyphColor: Int,
        value: CharSequence,
        label: CharSequence,
        valueColor: Int,
    ): MetricTile = MetricTile(context).apply {
        bind(glyph, glyphColor, value, label, valueColor)
    }

    private fun tileParams(rightMargin: Boolean): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            if (rightMargin) this.rightMargin = TvTheme.scaledDp(context, 8)
        }

    // ---------------------------------------------------------------- findings column

    private fun buildFindingsColumn(container: LinearLayout, result: ScanResult?, summary: ScanSummary?) {
        val findings = result?.findings.orEmpty()
        val meta = when {
            result != null && findings.isNotEmpty() -> TvFormat.findingsCount(context, findings.size)
            summary != null -> TvFormat.findingsCount(context, summary.findingsCount)
            else -> null
        }
        container.addView(SectionHeader(context, text(R.string.home_top_findings), meta))

        when {
            findings.isNotEmpty() -> {
                for (finding in findings.take(2)) {
                    val row = FindingRow(context)
                    row.bind(finding, services.catalog)
                    row.setOnClickListener { host.navigate(TvRoute.FINDING_DETAIL, finding.id) }
                    container.addView(
                        row,
                        LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                            bottomMargin = TvTheme.scaledDp(context, 6)
                        },
                    )
                }
                val viewAllAction = FocusableAction.secondary(context, R.string.action_open_findings, TvGlyph.ALERT).apply {
                    setOnClickListener { host.navigate(TvRoute.FINDINGS) }
                }
                container.addView(
                    viewAllAction,
                    LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                        topMargin = TvTheme.scaledDp(context, 4)
                    },
                )
            }

            result != null -> {
                container.addView(
                    bodyText(context, text(R.string.home_no_findings_note)),
                    matchParams(),
                )
            }

            summary != null -> {
                val panel = GlassPanel(context, soft = true).apply {
                    compact()
                    addView(bodyText(context, text(R.string.home_summary_findings_note), TvTheme.textSecondary))
                    val viewAllAction = FocusableAction.secondary(context, R.string.action_open_findings, TvGlyph.ALERT).apply {
                        setOnClickListener { host.navigate(TvRoute.FINDINGS) }
                    }
                    addView(
                        viewAllAction,
                        LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                            topMargin = TvTheme.scaledDp(context, 6)
                        },
                    )
                }
                container.addView(panel, matchParams())
            }

            else -> {
                container.addView(
                    bodyText(context, text(R.string.empty_no_check_message)),
                    matchParams(),
                )
            }
        }
    }

    // ------------------------------------------------------------------ device column

    private fun buildDeviceColumn(container: LinearLayout, result: ScanResult?, summary: ScanSummary?) {
        container.addView(SectionHeader(context, text(R.string.home_section_device)))
        container.addView(buildDevicePanel(result, summary), matchParams())

        val viewEvidenceAction = FocusableAction.secondary(context, R.string.action_open_evidence, TvGlyph.EXPORT).apply {
            setOnClickListener { host.navigate(TvRoute.EVIDENCE) }
        }
        container.addView(
            viewEvidenceAction,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 6)
            },
        )
    }

    private fun buildDevicePanel(result: ScanResult?, summary: ScanSummary?): View {
        if (result == null) {
            val message = if (summary != null) {
                text(R.string.home_device_details_note)
            } else {
                text(R.string.about_device_none)
            }
            return noticePanel(TvGlyph.INFO, TvTone.NEUTRAL, null, message)
        }
        val supported = result.collectorResults.count { it.capability == CapabilityState.SUPPORTED }
        val total = result.collectorResults.size
        val rows = mutableListOf<View>()
        rows += infoRow(text(R.string.home_label_device), result.platform.displayModel)
        rows += infoRow(
            text(R.string.home_label_android),
            text(R.string.home_android_value, result.platform.androidRelease, result.platform.sdkInt),
        )
        rows += infoRowPill(
            text(R.string.home_label_patch),
            pill(
                patchStatusGlyph(result.patch.status),
                patchStatusLabelRes(result.patch.status),
                patchStatusTone(result.patch.status),
            ),
        )
        rows += infoRow(text(R.string.home_label_collectors), text(R.string.count_of_total, supported, total))
        rows += infoRowPill(
            text(R.string.home_label_coverage),
            pill(visibilityGlyph(result.coverage), visibilityLabelRes(result.coverage), visibilityTone(result.coverage)),
        )
        return parameterPanel(*rows.toTypedArray())
    }

    // ------------------------------------------------------- V2 protection entry

    private val vpnStateListener = VpnStateListener {
        val view = scaffold
        view.post { if (view.isAttachedToWindow) host.refreshCurrent() }
    }

    private var vpnStateListenerRegistered = false

    override fun onShown() {
        if (!vpnStateListenerRegistered) {
            readService { services.vpn.addStateListener(vpnStateListener) }
            vpnStateListenerRegistered = true
        }
    }

    override fun onHidden() {
        if (vpnStateListenerRegistered) {
            readService { services.vpn.removeStateListener(vpnStateListener) }
            vpnStateListenerRegistered = false
        }
    }

    /**
     * Compact local-protection widget: Sir Quacksec accent, honest VPN state and one click into the
     * protection dashboard. Never claims protection while the tunnel is inactive.
     */
    private fun buildProtectionWidget(): View {
        val status = readService { services.vpn.status() }
        val state = status?.state ?: VpnState.OFF
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            isFocusable = true
            isFocusableInTouchMode = false
            isClickable = true
            setBackgroundResource(R.drawable.sel_row_card)
            setPadding(
                TvTheme.scaledDp(context, 12),
                TvTheme.scaledDp(context, 8),
                TvTheme.scaledDp(context, 14),
                TvTheme.scaledDp(context, 8),
            )
            minimumHeight = TvTheme.scaledDp(context, 62)
        }
        val mascot = ImageView(context).apply {
            setImageResource(R.drawable.sir_quacksec)
            scaleType = ImageView.ScaleType.FIT_CENTER
            contentDescription = text(R.string.welcome_mascot_description)
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        }
        row.addView(
            mascot,
            LinearLayout.LayoutParams(TvTheme.scaledDp(context, 42), TvTheme.scaledDp(context, 48)).apply {
                rightMargin = TvTheme.scaledDp(context, 12)
            },
        )
        val column = column()
        column.addView(
            TvTheme.textView(context, text(R.string.home_prot_title), TvTheme.TEXT_HEADING_SP, TvTheme.textPrimary, bold = true),
        )
        val subtitle = when (state) {
            VpnState.ACTIVE -> R.string.home_prot_active
            VpnState.DEGRADED -> R.string.home_prot_degraded
            VpnState.PREPARING -> R.string.home_prot_preparing
            else -> R.string.home_prot_off
        }
        column.addView(captionText(context, text(subtitle), TvTheme.textSecondary))
        row.addView(column, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(
            StatusPill(
                context,
                text(vpnStateLabelRes(state)),
                vpnStateTone(state),
                vpnStateGlyph(state),
            ),
        )
        row.contentDescription = "${text(R.string.home_prot_title)}: ${text(vpnStateLabelRes(state))}"
        row.setOnClickListener { host.navigate(TvRoute.PROTECTION) }
        return row
    }

    private fun buildXdrRow(): FocusableRow {
        val row = FocusableRow(context, interactive = true)
        row.setCard(true)
        row.setLeading(TvGlyph.ALERT, TvTheme.accent)
        row.setTitle(text(R.string.home_prot_xdr_title))
        row.setSubtitle(text(R.string.home_prot_xdr_desc))
        row.setChevronVisible(true)
        row.setOnClickListener { host.navigate(TvRoute.XDR) }
        return row
    }

    private companion object {
        @Volatile
        private var cachedWatermark: Bitmap? = null

        @Volatile
        private var cachedWatermarkWidthPx: Int = 0

        fun decodeWatermark(context: android.content.Context, targetWidthPx: Int): Bitmap? {
            if (cachedWatermark != null && cachedWatermarkWidthPx == targetWidthPx) {
                return cachedWatermark
            }
            return try {
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeResource(context.resources, R.drawable.brand_watermark, bounds)
                val targetWidth = targetWidthPx.coerceAtLeast(1)
                var sample = 1
                while (bounds.outWidth > 0 && bounds.outWidth / (sample * 2) >= targetWidth) {
                    sample *= 2
                }
                val options = BitmapFactory.Options().apply { inSampleSize = sample }
                val bitmap = BitmapFactory.decodeResource(context.resources, R.drawable.brand_watermark, options)
                cachedWatermark = bitmap
                cachedWatermarkWidthPx = targetWidthPx
                bitmap
            } catch (t: Throwable) {
                null
            }
        }
    }
}
