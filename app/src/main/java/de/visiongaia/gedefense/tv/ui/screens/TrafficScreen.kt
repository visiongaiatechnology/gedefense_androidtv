package de.visiongaia.gedefense.tv.ui.screens

import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.core.model.AppTraffic
import de.visiongaia.gedefense.tv.core.model.CountryTraffic
import de.visiongaia.gedefense.tv.core.model.OriginInfo
import de.visiongaia.gedefense.tv.core.model.TrafficSnapshot
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.GlassPanel
import de.visiongaia.gedefense.tv.ui.components.GlyphView
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.TrafficWorldMapView
import de.visiongaia.gedefense.tv.ui.components.formatBytes
import de.visiongaia.gedefense.tv.ui.components.horizontalRow
import de.visiongaia.gedefense.tv.ui.components.readService
import de.visiongaia.gedefense.tv.ui.components.routeColorFor
import de.visiongaia.gedefense.tv.ui.components.verticalColumn

/**
 * Network & destinations screen (V2, VGT GLASS 2100 composition).
 *
 * The hero is one functional glass surface that pairs the world map with a calm numeric column; the
 * destination cards and the per-app grid sit on their own layers with an explicit section rhythm, so
 * the former vertical stacking of hero/tiles/map/list no longer feels compressed. All values are
 * real local telemetry; unknown countries stay unknown instead of being drawn as a guessed route.
 */
internal class TrafficScreen(services: TvServices) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.TRAFFIC

    private var mapView: TrafficWorldMapView? = null
    private var totalValue: TextView? = null
    private var flowsValue: TextView? = null
    private var blockedValue: TextView? = null
    private var updatedLabel: TextView? = null
    private var geoHint: TextView? = null
    private var firstFocusRow: View? = null
    private var lastFocusRow: View? = null

    private val handler = Handler(Looper.getMainLooper())
    private var liveUpdate: Runnable? = null
    private var lastRevision: Long = -1L

    override fun build(scaffold: ScreenScaffold) {
        val snapshot = currentSnapshot()
        val origin = currentOrigin()

        scaffold.setEyebrow(text(R.string.traffic_eyebrow))
        scaffold.setTitle(text(R.string.traffic_title))
        scaffold.setSubtitle(text(R.string.traffic_subtitle))

        val stateKey = snapshot.state.uppercase()
        val stateLabelRes = when (stateKey) {
            "ACTIVE" -> R.string.traffic_state_live
            "STOPPED" -> R.string.traffic_state_stopped
            "LAST" -> R.string.traffic_state_last
            else -> R.string.traffic_state_idle
        }
        val stateTone = when (stateKey) {
            "ACTIVE" -> TvTone.SUCCESS
            "STOPPED", "LAST" -> TvTone.WARNING
            else -> TvTone.NEUTRAL
        }
        val stateGlyph = when (stateKey) {
            "ACTIVE" -> TvGlyph.EYE
            "STOPPED" -> TvGlyph.EYE_OFF
            "LAST" -> TvGlyph.CLOCK
            else -> TvGlyph.EYE_OFF
        }
        scaffold.addStatus(StatusPill(context, text(stateLabelRes), stateTone, stateGlyph))
        scaffold.addStatus(
            StatusPill(
                context,
                TvFormat.appsCount(context, snapshot.apps.size),
                TvTone.NEUTRAL,
                TvGlyph.INFO,
            ),
        )

        scaffold.addFullWidth(buildHeroPanel(origin, snapshot), topSpacingDp = 12)
        if (stateKey == "LAST") {
            scaffold.addFullWidth(
                caption(text(R.string.traffic_state_last_note), TvTheme.textSecondary),
                topSpacingDp = 8,
            )
        }

        val knownCountryCount = snapshot.countries.count { isKnownCountry(it.countryCode) }
        scaffold.addSection(
            text(R.string.traffic_section_targets),
            if (knownCountryCount == 1) {
                text(R.string.traffic_country_count_one)
            } else {
                text(R.string.traffic_countries_count, knownCountryCount)
            },
        )
        scaffold.addFullWidth(buildDestinationRow(snapshot), topSpacingDp = 2)

        scaffold.addSection(text(R.string.traffic_section_apps), TvFormat.appsCount(context, snapshot.apps.size))
        if (snapshot.apps.isEmpty()) {
            scaffold.addFullWidth(buildEmptyApps(), topSpacingDp = 2)
        } else {
            buildAppGrid(snapshot.apps, scaffold)
        }
        scaffold.addSection(text(R.string.kinetic_section_title), text(R.string.kinetic_section_observe))
        buildKineticSection(scaffold)

        scaffold.addCaption(text(R.string.traffic_live_note), topSpacingDp = 14)

        scaffold.addAction(
            primaryAction(R.string.traffic_action_protection, TvGlyph.SHIELD) { host.navigate(TvRoute.PROTECTION) },
            primary = true,
        )
        scaffold.addAction(
            secondaryAction(R.string.traffic_action_xdr, TvGlyph.ALERT) { host.navigate(TvRoute.XDR) },
        )
        scaffold.linkFocusChain(firstFocusRow, lastFocusRow)

        scaffold.post { startLiveUpdates() }
        scaffold.addOnAttachStateChangeListener(object : View.OnAttachStateChangeListener {
            override fun onViewAttachedToWindow(v: View) {}

            override fun onViewDetachedFromWindow(v: View) {
                stopLiveUpdates()
            }
        })
    }

    override fun onHidden() {
        stopLiveUpdates()
    }

    // ------------------------------------------------------------------- hero

    private fun buildHeroPanel(origin: OriginInfo, snapshot: TrafficSnapshot): View {
        val panel = GlassPanel(context)
        val row = horizontalRow(context)
        row.gravity = Gravity.TOP

        val mapColumn = verticalColumn(context)
        val map = TrafficWorldMapView(context)
        map.setData(origin, routesFrom(snapshot.countries))
        this.mapView = map
        val screenHeightDp = context.resources.configuration.screenHeightDp.takeIf { it > 0 } ?: 540
        val mapHeightDp = (screenHeightDp * 0.33f).toInt().coerceIn(200, 280)
        mapColumn.addView(
            map,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, TvTheme.dp(context, mapHeightDp)),
        )

        val mapFooter = horizontalRow(context)
        mapFooter.gravity = Gravity.CENTER_VERTICAL
        mapFooter.setPadding(0, TvTheme.dp(context, 12), 0, 0)
        mapFooter.addView(
            StatusPill(
                context,
                text(R.string.traffic_map_origin, origin.countryCode ?: text(R.string.traffic_country_unknown)),
                TvTone.NEUTRAL,
                TvGlyph.INFO,
            ),
        )
        val updated = caption(text(R.string.traffic_updated, TvFormat.relative(context, snapshot.updatedAtMillis)))
        updatedLabel = updated
        mapFooter.addView(
            updated,
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                leftMargin = TvTheme.dp(context, 14)
                gravity = Gravity.CENTER_VERTICAL
            },
        )
        mapColumn.addView(mapFooter)
        row.addView(mapColumn, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.62f))

        val stats = verticalColumn(context)
        stats.setPadding(TvTheme.dp(context, 26), TvTheme.dp(context, 4), 0, 0)

        val total = TvTheme.textView(
            context,
            formatBytes(snapshot.txBytes + snapshot.rxBytes),
            TvTheme.TEXT_DISPLAY_SP,
            TvTheme.textPrimary,
            bold = true,
        )
        totalValue = total
        stats.addView(total)
        stats.addView(caption(text(R.string.traffic_hud_total)), topMargin(2))
        stats.addView(divider(), topMargin(16))

        flowsValue = statRow(stats, text(R.string.traffic_hud_flows), snapshot.activeFlows.toString(), TvGlyph.EYE, TvTheme.electricBlue)
        blockedValue = statRow(
            stats,
            text(R.string.traffic_hud_blocked),
            snapshot.blockedFlows.toString(),
            TvGlyph.SHIELD,
            if (snapshot.blockedFlows > 0L) TvTheme.critical else TvTheme.accent,
        )

        val geo = caption(text(R.string.traffic_geo_pending), TvTheme.textSecondary).apply { maxLines = 3 }
        geoHint = geo
        geo.visibility = if (snapshot.countries.any { isKnownCountry(it.countryCode) }) View.GONE else View.VISIBLE
        stats.addView(geo, topMargin(16))
        stats.addView(caption(text(R.string.traffic_origin_note), TvTheme.textSecondary), topMargin(8))

        row.addView(stats, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        panel.addView(row)
        return panel
    }

    private fun statRow(
        parent: LinearLayout,
        label: String,
        value: String,
        glyph: TvGlyph,
        accent: Int,
    ): TextView {
        val row = horizontalRow(context)
        row.gravity = Gravity.CENTER_VERTICAL
        row.setPadding(0, TvTheme.dp(context, 10), 0, 0)
        row.addView(
            GlyphView(context, glyph, accent, 16),
            LinearLayout.LayoutParams(TvTheme.dp(context, 16), TvTheme.dp(context, 16)).apply {
                rightMargin = TvTheme.dp(context, 10)
            },
        )
        row.addView(
            TvTheme.textView(context, label, TvTheme.TEXT_LABEL_SP, TvTheme.textSecondary),
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
        )
        val valueView = TvTheme.textView(context, value, TvTheme.TEXT_HEADING_SP, TvTheme.textPrimary, bold = true)
        row.addView(valueView)
        parent.addView(row)
        return valueView
    }

    private fun divider(): View = View(context).apply {
        setBackgroundColor(TvTheme.glassStroke)
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, TvTheme.dp(context, 1))
    }

    private fun topMargin(dp: Int): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = TvTheme.dp(context, dp)
        }

    // ------------------------------------------------------------ destinations

    private fun buildDestinationRow(snapshot: TrafficSnapshot): View {
        val countries = snapshot.countries
            .filter { isKnownCountry(it.countryCode) }
            .sortedWith(compareByDescending<CountryTraffic> { it.bytes }.thenBy { it.countryCode })
            .take(4)
        if (countries.isEmpty()) {
            val panel = GlassPanel(context, soft = true)
            panel.compact()
            panel.addView(caption(text(R.string.traffic_targets_empty), TvTheme.textSecondary))
            return panel
        }
        val row = horizontalRow(context)
        countries.forEachIndexed { index, country ->
            val card = GlassPanel(context, soft = true)
            card.compact()
            val header = horizontalRow(context)
            header.gravity = Gravity.CENTER_VERTICAL
            val dot = View(context).apply { setBackgroundColor(routeColorFor(country.countryCode)) }
            header.addView(
                dot,
                LinearLayout.LayoutParams(TvTheme.dp(context, 8), TvTheme.dp(context, 8)).apply {
                    rightMargin = TvTheme.dp(context, 8)
                },
            )
            header.addView(
                TvTheme.textView(context, country.countryCode, TvTheme.TEXT_LABEL_SP, TvTheme.textPrimary, bold = true),
            )
            card.addView(header)
            card.addView(
                TvTheme.textView(context, formatBytes(country.bytes), TvTheme.TEXT_LABEL_SP, TvTheme.textPrimary, bold = true),
                topMargin(8),
            )
            val meta = if (country.blockedFlows > 0) {
                text(R.string.traffic_target_meta, country.flows, country.blockedFlows)
            } else {
                text(R.string.traffic_target_meta_ok, country.flows)
            }
            card.addView(caption(meta), topMargin(4))
            row.addView(
                card,
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                    if (index < countries.lastIndex) rightMargin = TvTheme.dp(context, 10)
                },
            )
        }
        // Keep predictable card widths: unused slots stay as flexible spacers instead of
        // stretching a single destination card across the entire row.
        for (slot in countries.size until 4) {
            row.addView(
                View(context),
                LinearLayout.LayoutParams(0, 1, 1f).apply {
                    if (slot < 3) rightMargin = TvTheme.dp(context, 10)
                },
            )
        }

        return row
    }

    // ------------------------------------------------------- kinetic-lite

    private fun buildKineticSection(scaffold: ScreenScaffold) {
        val anomalies = readService { services.anomaly.anomalies() }.orEmpty()
        val active = readService { services.containment.active() }.orEmpty()
        if (anomalies.isEmpty() && active.isEmpty()) {
            scaffold.addFullWidth(buildKineticEmpty(), topSpacingDp = 2)
            return
        }
        for (record in active.take(4)) {
            val row = buildContainmentRow(record)
            scaffold.addFullWidth(row, topSpacingDp = 2)
            if (firstFocusRow == null) firstFocusRow = row
            lastFocusRow = row
        }
        for (anomaly in anomalies.take(4)) {
            val row = buildAnomalyRow(anomaly)
            scaffold.addFullWidth(row, topSpacingDp = 2)
            if (firstFocusRow == null) firstFocusRow = row
            lastFocusRow = row
        }
    }

    private fun buildKineticEmpty(): View {
        val panel = GlassPanel(context, soft = true)
        panel.compact()
        panel.addView(caption(text(R.string.kinetic_no_anomalies), TvTheme.textSecondary))
        panel.addView(caption(text(R.string.kinetic_observe_note), TvTheme.textSecondary), topMargin(6))
        return panel
    }

    private fun buildContainmentRow(record: de.visiongaia.gedefense.tv.core.model.ContainmentRecord): FocusableRow {
        val row = FocusableRow(context, interactive = true)
        row.setCard(true)
        row.setLeading(TvGlyph.SHIELD, TvTheme.critical)
        row.setTitle(text(R.string.kinetic_containment_active))
        val owner = record.appLabel?.takeIf { it.isNotBlank() } ?: record.packageName ?: text(R.string.kinetic_app_unattributed)
        val remaining = ((record.expiresAtMillis - System.currentTimeMillis()).coerceAtLeast(0L) / 60_000L) + 1L
        row.setSubtitle(
            text(R.string.containment_body, owner) + "\n" +
                text(R.string.kinetic_containment_remaining, remaining) + " · " + record.target.value,
        )
        row.setTrailing(StatusPill(context, text(R.string.kinetic_containment_release), TvTone.WARNING, TvGlyph.REFRESH))
        row.setOnClickListener {
            if (readService { services.containment.release(record.id) } == true) {
                notify(text(R.string.containment_released))
            } else {
                notify(text(R.string.containment_release_failed))
            }
            refreshIfVisible()
        }
        return row
    }

    private fun buildAnomalyRow(anomaly: de.visiongaia.gedefense.tv.core.model.OutboundAnomaly): FocusableRow {
        val row = FocusableRow(context, interactive = false)
        row.setCard(true)
        val seed = if (anomaly.severity.rank >= 3) TvTheme.critical else TvTheme.accent
        row.setLeading(TvGlyph.ALERT, seed)
        val owner = anomalyOwner(anomaly)
        row.setTitle(owner)
        val countries = anomaly.countryCode?.takeIf { it != "ZZ" && it != "UNKNOWN" } ?: text(R.string.traffic_country_unknown)
        val signalText = anomaly.signals.take(3).joinToString(" · ") { it.detail }
        row.setSubtitle(
            text(R.string.kinetic_anomaly_score, anomaly.score) + " · " + countries + "\n" +
                text(R.string.kinetic_anomaly_signals, signalText),
        )
        row.setTrailing(StatusPill(context, text(R.string.kinetic_section_observe), TvTone.WARNING, TvGlyph.INFO))
        return row
    }

    // ---------------------------------------------------------------- app grid

    private fun buildAppGrid(apps: List<AppTraffic>, scaffold: ScreenScaffold) {
        val shown = apps.take(MAX_APP_CARDS)
        var index = 0
        while (index < shown.size) {
            val row = horizontalRow(context)
            var column = 0
            while (column < 2 && index < shown.size) {
                val card = buildAppCard(shown[index])
                row.addView(
                    card,
                    LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                        if (column == 0) rightMargin = TvTheme.dp(context, 10)
                    },
                )
                if (firstFocusRow == null) firstFocusRow = card
                lastFocusRow = card
                index++
                column++
            }
            if (column < 2) {
                row.addView(View(context), LinearLayout.LayoutParams(0, 1, 1f))
            }
            scaffold.addFullWidth(row, topSpacingDp = if (index <= 2) 2 else 10)
        }
    }

    private fun buildAppCard(app: AppTraffic): FocusableRow {
        val row = FocusableRow(context, interactive = false)
        row.setCard(true)
        row.setLeading(TvGlyph.EYE, TvTheme.electricBlue)
        row.setTitle(displayLabel(app))
        val knownCountries = app.topCountries.map { it.countryCode }.filter { isKnownCountry(it) }.take(3)
        val countries = if (knownCountries.isNotEmpty()) {
            knownCountries.joinToString(", ")
        } else {
            text(R.string.traffic_country_unknown)
        }
        val subtitle = buildString {
            append(app.packageName)
            append("\n")
            append(text(R.string.traffic_app_card_meta, app.openedFlows, app.blockedFlows, countries))
        }
        row.setSubtitle(subtitle)
        row.setTrailing(
            StatusPill(context, formatBytes(app.totalBytes), TvTone.NEUTRAL, TvGlyph.REFRESH),
        )
        return row
    }

    private fun anomalyOwner(anomaly: de.visiongaia.gedefense.tv.core.model.OutboundAnomaly): String {
        val label = anomaly.appLabel?.takeIf { it.isNotBlank() }
        if (label != null) return label
        val pkg = anomaly.packageName
        if (pkg == null || pkg.startsWith("uid:") || pkg.startsWith("uid-")) return text(R.string.kinetic_app_unattributed)
        return pkg
    }

    private fun displayLabel(app: AppTraffic): String {
        val label = app.label.ifBlank { app.packageName }
        return if (label.startsWith("uid:") || label.startsWith("uid-")) {
            text(R.string.traffic_app_unattributed)
        } else {
            label
        }
    }

    private fun buildEmptyApps(): View {
        val panel = GlassPanel(context, soft = true)
        panel.compact()
        panel.addView(
            TvTheme.textView(context, text(R.string.traffic_empty_title), TvTheme.TEXT_LABEL_SP, TvTheme.textPrimary, bold = true),
        )
        panel.addView(caption(text(R.string.traffic_empty_message)), topMargin(6))
        return panel
    }

    // -------------------------------------------------------------- live data

    private fun currentSnapshot(): TrafficSnapshot =
        readService { services.traffic.snapshot() } ?: TrafficSnapshot.IDLE

    private fun currentOrigin(): OriginInfo =
        readService { services.traffic.origin() } ?: OriginInfo(null, null, "")

    private fun routesFrom(countries: List<CountryTraffic>): List<TrafficWorldMapView.TrafficMapRoute> =
        countries.filter { isKnownCountry(it.countryCode) }.map { country ->
            TrafficWorldMapView.TrafficMapRoute(
                ownerPackage = "",
                appLabel = country.countryCode,
                countryCode = country.countryCode,
                bytes = country.bytes,
                flows = country.flows,
                blockedFlows = country.blockedFlows,
                color = routeColorFor(country.countryCode),
            )
        }

    /** "ZZ" (UNKNOWN) until the offline geo generation is available; never draw it as a country. */
    private fun isKnownCountry(code: String?): Boolean =
        !code.isNullOrBlank() && code != "ZZ" && code != "UNKNOWN"

    private fun startLiveUpdates() {
        stopLiveUpdates()
        val runnable = object : Runnable {
            override fun run() {
                val revision = readService { services.traffic.revision() } ?: 0L
                if (revision != lastRevision) {
                    lastRevision = revision
                    val snapshot = currentSnapshot()
                    totalValue?.text = formatBytes(snapshot.txBytes + snapshot.rxBytes)
                    flowsValue?.text = snapshot.activeFlows.toString()
                    blockedValue?.text = snapshot.blockedFlows.toString()
                    blockedValue?.setTextColor(if (snapshot.blockedFlows > 0L) TvTheme.critical else TvTheme.accent)
                    mapView?.setData(currentOrigin(), routesFrom(snapshot.countries))
                    updatedLabel?.text = text(R.string.traffic_updated, TvFormat.relative(context, snapshot.updatedAtMillis))
                    geoHint?.visibility =
                        if (snapshot.countries.any { isKnownCountry(it.countryCode) }) View.GONE else View.VISIBLE
                }
                handler.postDelayed(this, LIVE_INTERVAL_MILLIS)
            }
        }
        liveUpdate = runnable
        handler.postDelayed(runnable, LIVE_INTERVAL_MILLIS)
    }

    private fun stopLiveUpdates() {
        liveUpdate?.let { handler.removeCallbacks(it) }
        liveUpdate = null
    }

    private companion object {
        const val LIVE_INTERVAL_MILLIS = 3_000L
        const val MAX_APP_CARDS = 8
    }
}
