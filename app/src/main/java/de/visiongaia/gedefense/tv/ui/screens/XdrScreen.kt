package de.visiongaia.gedefense.tv.ui.screens

import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.TrafficSnapshot
import de.visiongaia.gedefense.tv.core.xdr.XdrIncident
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.GlassPanel
import de.visiongaia.gedefense.tv.ui.components.GlyphView
import de.visiongaia.gedefense.tv.ui.components.MetricTile
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.confidenceLabelRes
import de.visiongaia.gedefense.tv.ui.components.horizontalRow
import de.visiongaia.gedefense.tv.ui.components.readService
import de.visiongaia.gedefense.tv.ui.components.severityGlyph
import de.visiongaia.gedefense.tv.ui.components.severityLabelRes
import de.visiongaia.gedefense.tv.ui.components.severityTone
import de.visiongaia.gedefense.tv.ui.components.toneColor
import de.visiongaia.gedefense.tv.ui.components.verticalColumn
import de.visiongaia.gedefense.tv.ui.components.visibilityLabelRes

/**
 * XDR-Light view (V2, VGT GLASS 2100 composition).
 *
 * Real incidents from the local [XdrApi] only: the UI never computes or invents its own score. The
 * layout separates a calm summary band, the explainable incident layer and a fixed context panel, so
 * density, severity and the limits of local XDR stay readable at TV distance.
 */
internal class XdrScreen(services: TvServices) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.XDR

    private var firstFocusRow: View? = null
    private var lastFocusRow: View? = null
    private var lastRevision: Long = -1L

    private val handler = Handler(Looper.getMainLooper())
    private var poll: Runnable? = null

    override fun build(scaffold: ScreenScaffold) {
        val incidents = incidents()
        lastRevision = readService { services.xdr.revision() } ?: 0L
        val traffic = readService { services.traffic.snapshot() } ?: TrafficSnapshot.IDLE

        scaffold.setEyebrow(text(R.string.xdr_eyebrow))
        scaffold.setTitle(text(R.string.xdr_title))
        scaffold.setSubtitle(text(R.string.xdr_subtitle))

        scaffold.addStatus(
            StatusPill(
                context,
                TvFormat.eventsCount(context, incidents.size),
                if (incidents.isEmpty()) TvTone.NEUTRAL else TvTone.WARNING,
                if (incidents.isEmpty()) TvGlyph.CHECK else TvGlyph.ALERT,
            ),
        )
        scaffold.addStatus(
            StatusPill(
                context,
                text(R.string.xdr_scope_short),
                TvTone.NEUTRAL,
                TvGlyph.INFO,
            ),
        )

        scaffold.addFullWidth(buildSummary(incidents, traffic), topSpacingDp = 12)

        if (incidents.isEmpty()) {
            scaffold.addFullWidth(buildEmptyPanel(), topSpacingDp = 16)
            scaffold.addSection(text(R.string.xdr_empty_scope_title))
            scaffold.addFullWidth(buildScopeCard(), topSpacingDp = 2)
            scaffold.addCaption(text(R.string.xdr_clear_hint), topSpacingDp = 12)
        } else {
            scaffold.addSection(text(R.string.xdr_section_incidents), TvFormat.eventsCount(context, incidents.size))
            scaffold.addFullWidth(buildIncidentWorkspace(incidents), topSpacingDp = 2)
            scaffold.addCaption(text(R.string.xdr_clear_hint), topSpacingDp = 14)
        }

        scaffold.addSection(text(R.string.kinetic_section_title), text(R.string.kinetic_section_observe))
        buildKineticSection(scaffold)
        scaffold.addCaption(text(R.string.xdr_clear_hint), topSpacingDp = 14)

        scaffold.addAction(
            primaryAction(R.string.xdr_action_protection, TvGlyph.SHIELD) { host.navigate(TvRoute.PROTECTION) },
            primary = true,
        )
        scaffold.addAction(
            secondaryAction(R.string.xdr_action_traffic, TvGlyph.EYE) { host.navigate(TvRoute.TRAFFIC) },
        )
        scaffold.linkFocusChain(firstFocusRow, lastFocusRow)

        scaffold.post { startPolling() }
        scaffold.addOnAttachStateChangeListener(object : View.OnAttachStateChangeListener {
            override fun onViewAttachedToWindow(v: View) {}

            override fun onViewDetachedFromWindow(v: View) {
                stopPolling()
            }
        })
    }

    override fun onHidden() {
        stopPolling()
    }

    // ---------------------------------------------------------------- summary

    private fun buildSummary(incidents: List<XdrIncident>, traffic: TrafficSnapshot): View {
        val row = horizontalRow(context)
        val highest = incidents.maxByOrNull { it.severity.rank }?.severity
        val highestLabel = highest?.let { text(severityLabelRes(it)) } ?: text(R.string.xdr_severity_none)
        val incidentTile = MetricTile(context).apply {
            bind(
                TvGlyph.ALERT,
                if (incidents.isEmpty()) TvTheme.success else TvTheme.critical,
                incidents.size.toString(),
                text(R.string.xdr_summary_incidents),
                TvTheme.textPrimary,
            )
        }
        val severityTile = MetricTile(context).apply {
            bind(
                TvGlyph.SHIELD,
                highest?.let { toneColor(context, severityTone(it)) } ?: TvTheme.textSecondary,
                highestLabel,
                text(R.string.xdr_summary_severity),
                TvTheme.textPrimary,
            )
        }
        val blockedTile = MetricTile(context).apply {
            bind(
                TvGlyph.EYE_OFF,
                if (traffic.blockedFlows > 0L) TvTheme.critical else TvTheme.accent,
                traffic.blockedFlows.toString(),
                text(R.string.xdr_summary_blocked),
                TvTheme.textPrimary,
            )
        }
        row.addView(incidentTile, weightParams(true))
        row.addView(severityTile, weightParams(true))
        row.addView(blockedTile, weightParams(false))
        return row
    }

    private fun weightParams(rightMargin: Boolean): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            if (rightMargin) this.rightMargin = TvTheme.dp(context, 10)
        }

    // ------------------------------------------------------------------ empty

    private fun buildEmptyPanel(): View {
        val panel = GlassPanel(context)
        val row = horizontalRow(context)
        row.gravity = Gravity.CENTER_VERTICAL
        row.addView(
            GlyphView(context, TvGlyph.SHIELD, TvTheme.success, 46),
            LinearLayout.LayoutParams(TvTheme.dp(context, 46), TvTheme.dp(context, 46)).apply {
                rightMargin = TvTheme.dp(context, 20)
            },
        )
        val column = verticalColumn(context)
        column.addView(
            TvTheme.textView(
                context,
                text(R.string.xdr_empty_title),
                TvTheme.TEXT_HEADING_SP,
                TvTheme.textPrimary,
                bold = true,
            ),
        )
        column.addView(
            caption(text(R.string.xdr_empty_message), TvTheme.textSecondary),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.dp(context, 6)
            },
        )
        row.addView(column, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        panel.addView(row)
        return panel
    }

    private fun buildScopeCard(): View {
        val panel = GlassPanel(context, soft = true)
        panel.compact()
        scopeLine(panel, TvGlyph.EYE, text(R.string.xdr_empty_scope_traffic))
        scopeLine(panel, TvGlyph.SHIELD, text(R.string.xdr_empty_scope_ti))
        scopeLine(panel, TvGlyph.CHECK, text(R.string.xdr_empty_scope_scan))
        panel.addView(
            caption(text(R.string.xdr_scope_note), TvTheme.textSecondary),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.dp(context, 10)
            },
        )
        return panel
    }

    private fun scopeLine(parent: LinearLayout, glyph: TvGlyph, label: String) {
        val row = horizontalRow(context)
        row.gravity = Gravity.CENTER_VERTICAL
        row.setPadding(0, TvTheme.dp(context, 5), 0, TvTheme.dp(context, 5))
        row.addView(
            GlyphView(context, glyph, TvTheme.accent, 14),
            LinearLayout.LayoutParams(TvTheme.dp(context, 14), TvTheme.dp(context, 14)).apply {
                rightMargin = TvTheme.dp(context, 10)
            },
        )
        row.addView(
            TvTheme.textView(context, label, TvTheme.TEXT_LABEL_SP, TvTheme.textPrimary),
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
        )
        parent.addView(row)
    }

    // ---------------------------------------------------------------- workspace

    private fun buildIncidentWorkspace(incidents: List<XdrIncident>): View {
        val row = horizontalRow(context)
        row.gravity = Gravity.TOP

        val listColumn = verticalColumn(context)
        incidents.take(MAX_INCIDENTS).forEachIndexed { index, incident ->
            val card = buildIncidentCard(incident)
            listColumn.addView(
                card,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    if (index < incidents.lastIndex) bottomMargin = TvTheme.dp(context, 10)
                },
            )
            if (firstFocusRow == null) firstFocusRow = card
            lastFocusRow = card
        }
        row.addView(listColumn, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.72f))

        val contextPanel = buildContextPanel()
        row.addView(
            contextPanel,
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                leftMargin = TvTheme.dp(context, 20)
            },
        )
        return row
    }

    private fun buildIncidentCard(incident: XdrIncident): FocusableRow {
        val row = FocusableRow(context, interactive = false)
        row.setCard(true)
        row.setLeading(severityGlyph(incident.severity), toneColor(context, severityTone(incident.severity)))
        row.setTitle(sanitizeOwnerText(resolve(incident.title) ?: text(R.string.xdr_incident_fallback_title)))
        row.setSubtitle(buildSubtitle(incident))
        row.setSubtitleMaxLines(3)
        return row
    }

    /** Incident titles from the catalog embed the raw owner; present it readably on TV. */
    private fun sanitizeOwnerText(value: String): String {
        var result = value.replace("uid-unresolved", text(R.string.traffic_app_unattributed))
        val match = Regex("uid:(\\d+)").find(result)
        if (match != null) {
            result = result.replace(match.value, text(R.string.xdr_owner_system_uid, match.groupValues[1]))
        }
        return result
    }

    private fun buildSubtitle(incident: XdrIncident): String {
        // Short, non-truncated two-line subtitle: rule/app/score first, the explainable why second.
        // Severity and confidence live in the trailing score pill and the summary band.
        val app = incident.packageName?.let { sanitizeOwner(it) }
        return buildString {
            append(text(R.string.xdr_label_rule))
            append(": ")
            append(incident.ruleId)
            if (!app.isNullOrBlank()) {
                append(" · ")
                append(text(R.string.xdr_label_app))
                append(": ")
                append(app)
            }
            append(" · ")
            append(text(R.string.xdr_score_label, incident.score))
            append("\n")
            append(resolve(incident.why) ?: text(R.string.xdr_text_unavailable))
        }
    }

    /** Technical, unresolved socket owners must not be presented as readable app names. */
    private fun sanitizeOwner(owner: String): String = when {
        owner.startsWith("uid-unresolved") -> text(R.string.traffic_app_unattributed)
        owner.startsWith("uid:") -> text(R.string.xdr_owner_system_uid, owner.removePrefix("uid:"))
        else -> owner
    }

    // ------------------------------------------------------- kinetic-lite

    private fun buildKineticSection(scaffold: ScreenScaffold) {
        val anomalies = readService { services.anomaly.anomalies() }.orEmpty()
        val active = readService { services.containment.active() }.orEmpty()
        if (anomalies.isEmpty() && active.isEmpty()) {
            scaffold.addCaption(text(R.string.kinetic_no_anomalies), topSpacingDp = 2)
            scaffold.addCaption(text(R.string.kinetic_observe_note), topSpacingDp = 4)
            return
        }
        for (record in active.take(4)) {
            val row = FocusableRow(context, interactive = true)
            row.setCard(true)
            row.setLeading(TvGlyph.SHIELD, TvTheme.critical)
            row.setTitle(text(R.string.kinetic_containment_active))
            val owner = record.appLabel?.takeIf { it.isNotBlank() } ?: record.packageName ?: text(R.string.kinetic_app_unattributed)
            val remaining = ((record.expiresAtMillis - System.currentTimeMillis()).coerceAtLeast(0L) / 60_000L) + 1L
            row.setSubtitle(text(R.string.containment_body, owner) + "\n" + record.target.value)
            row.setTrailing(StatusPill(context, text(R.string.kinetic_containment_release), TvTone.WARNING, TvGlyph.REFRESH))
            row.setOnClickListener {
                if (readService { services.containment.release(record.id) } == true) {
                    notify(text(R.string.containment_released))
                }
                refreshIfVisible()
            }
            scaffold.addFullWidth(row, topSpacingDp = 2)
            if (firstFocusRow == null) firstFocusRow = row
            lastFocusRow = row
        }
        for (anomaly in anomalies.take(6)) {
            val row = FocusableRow(context, interactive = false)
            row.setCard(true)
            row.setLeading(TvGlyph.ALERT, if (anomaly.severity.rank >= 3) TvTheme.critical else TvTheme.accent)
            val owner = anomalyOwner(anomaly)
            row.setTitle(owner)
            val countries = anomaly.countryCode?.takeIf { it != "ZZ" && it != "UNKNOWN" } ?: text(R.string.traffic_country_unknown)
            val signalText = anomaly.signals.take(3).joinToString(" · ") { it.detail }
            row.setSubtitle(
                text(R.string.kinetic_anomaly_score, anomaly.score) + " · " + countries + "\n" +
                    text(R.string.kinetic_anomaly_signals, signalText),
            )
            row.setTrailing(StatusPill(context, text(R.string.kinetic_section_observe), TvTone.WARNING, TvGlyph.INFO))
            scaffold.addFullWidth(row, topSpacingDp = 2)
            if (firstFocusRow == null) firstFocusRow = row
            lastFocusRow = row
        }
    }

    private fun anomalyOwner(anomaly: de.visiongaia.gedefense.tv.core.model.OutboundAnomaly): String {
        val label = anomaly.appLabel?.takeIf { it.isNotBlank() }
        if (label != null) return label
        val pkg = anomaly.packageName
        if (pkg == null || pkg.startsWith("uid:") || pkg.startsWith("uid-")) return text(R.string.kinetic_app_unattributed)
        return pkg
    }

    private fun buildContextPanel(): View {
        val panel = GlassPanel(context, soft = true)
        panel.addView(
            TvTheme.textView(
                context,
                text(R.string.xdr_context_title),
                TvTheme.TEXT_LABEL_SP,
                TvTheme.accent,
                bold = true,
            ),
        )
        panel.addView(
            caption(text(R.string.xdr_context_body), TvTheme.textPrimary),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.dp(context, 10)
            },
        )
        panel.addView(
            caption(text(R.string.xdr_context_limits), TvTheme.textSecondary),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.dp(context, 12)
            },
        )
        return panel
    }

    // -------------------------------------------------------------- live data

    private fun incidents(): List<XdrIncident> =
        readService { services.xdr.incidents() } ?: emptyList()

    private fun startPolling() {
        stopPolling()
        val runnable = object : Runnable {
            override fun run() {
                val revision = readService { services.xdr.revision() } ?: 0L
                if (revision != lastRevision) {
                    lastRevision = revision
                    if (scaffold.isAttachedToWindow) host.refreshCurrent()
                }
                handler.postDelayed(this, POLL_INTERVAL_MILLIS)
            }
        }
        poll = runnable
        handler.postDelayed(runnable, POLL_INTERVAL_MILLIS)
    }

    private fun stopPolling() {
        poll?.let { handler.removeCallbacks(it) }
        poll = null
    }

    private companion object {
        const val MAX_INCIDENTS = 12
        const val POLL_INTERVAL_MILLIS = 4_000L
    }
}
