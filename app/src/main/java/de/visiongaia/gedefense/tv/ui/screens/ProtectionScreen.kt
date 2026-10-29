package de.visiongaia.gedefense.tv.ui.screens

import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.contract.VpnStateListener
import de.visiongaia.gedefense.tv.core.model.AppTraffic
import de.visiongaia.gedefense.tv.core.model.TrafficSnapshot
import de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile
import de.visiongaia.gedefense.tv.core.model.VpnStatus
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.GlassPanel
import de.visiongaia.gedefense.tv.ui.components.GlyphBadge
import de.visiongaia.gedefense.tv.ui.components.MetricTile
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.captionText
import de.visiongaia.gedefense.tv.ui.components.formatBytes
import de.visiongaia.gedefense.tv.ui.components.horizontalRow
import de.visiongaia.gedefense.tv.ui.components.privacyProfileLabelRes
import de.visiongaia.gedefense.tv.ui.components.readService
import de.visiongaia.gedefense.tv.ui.components.toneColor
import de.visiongaia.gedefense.tv.ui.components.vpnStateClaimRes
import de.visiongaia.gedefense.tv.ui.components.vpnStateGlyph
import de.visiongaia.gedefense.tv.ui.components.vpnStateLabelRes
import de.visiongaia.gedefense.tv.ui.components.vpnReasonLabel
import de.visiongaia.gedefense.tv.ui.components.vpnStateTone

/**
 * Protection dashboard (V2): honest local loopback VPN state, consent-aware start/stop, filter
 * profile, auto-start, real counters and heuristic category chips from observed domains.
 *
 * The screen never claims protection while the tunnel is OFF/PREPARING/FAILED and never invents
 * traffic values when the VPN is inactive.
 */
internal class ProtectionScreen(services: TvServices) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.PROTECTION

    private val vpnListener = VpnStateListener { status ->
        val view = scaffold
        view.post { notify(text(vpnStateLabelRes(status.state))) }
    }

    /** Lifecycle subscription: no polling; the controller pushes state changes. */
    private val liveStateListener = VpnStateListener {
        val view = scaffold
        view.post { if (view.isAttachedToWindow) host.refreshCurrent() }
    }

    private var stateListenerRegistered = false

    override fun onShown() {
        if (!stateListenerRegistered) {
            readService { services.vpn.addStateListener(liveStateListener) }
            stateListenerRegistered = true
        }
    }

    override fun onHidden() {
        if (stateListenerRegistered) {
            readService { services.vpn.removeStateListener(liveStateListener) }
            stateListenerRegistered = false
        }
    }

    override fun build(scaffold: ScreenScaffold) {
        val status = readService { services.vpn.status() } ?: VpnStatus.OFF
        val snapshot = readService { services.traffic.snapshot() } ?: TrafficSnapshot.IDLE
        val profile = currentProfile(status)

        scaffold.setEyebrow(text(R.string.prot_eyebrow))
        scaffold.setTitle(text(R.string.prot_title))
        scaffold.setSubtitle(text(R.string.prot_subtitle))

        scaffold.addStatus(
            pill(vpnStateGlyph(status.state), vpnStateLabelRes(status.state), vpnStateTone(status.state)),
        )
        scaffold.addStatus(
            StatusPill(context, text(privacyProfileLabelRes(profile)), TvTone.NEUTRAL, TvGlyph.INFO),
        )

        scaffold.content.addView(buildStatusHero(status, snapshot), matchParams())
        scaffold.content.addView(buildCounterRow(status, snapshot), matchParams())

        scaffold.addSection(text(R.string.prot_profile_title))
        scaffold.content.addView(buildProfileRow(profile), matchParams())

        scaffold.addSection(text(R.string.prot_autostart_title))
        scaffold.content.addView(buildAutoStartRow(), matchParams())

        scaffold.addSection(text(R.string.kinetic_enable_title))
        scaffold.content.addView(buildContainmentRow(profile), matchParams())

        scaffold.addSection(text(R.string.prot_categories_title))
        buildCategorySection(scaffold, snapshot)

        scaffold.addSection(text(R.string.prot_section_links))
        scaffold.content.addView(buildTrafficLinkRow(), matchParams())
        scaffold.content.addView(buildXdrLinkRow(), matchParams())

        val primary = if (status.isProtecting) {
            dangerAction(R.string.prot_action_stop, TvGlyph.CROSS) { stopProtection() }
        } else {
            primaryAction(R.string.prot_action_start, TvGlyph.SHIELD) { startProtection() }
        }
        scaffold.addAction(primary, primary = true)
        scaffold.addAction(secondaryAction(R.string.prot_action_refresh, null) { host.refreshCurrent() })
    }

    // ------------------------------------------------------------------- hero

    private fun buildStatusHero(status: VpnStatus, snapshot: TrafficSnapshot): View {
        val panel = GlassPanel(context)
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val badge = GlyphBadge(
            context,
            vpnStateGlyph(status.state),
            toneColor(context, vpnStateTone(status.state)),
            52,
        )
        row.addView(
            badge,
            LinearLayout.LayoutParams(TvTheme.dp(context, 52), TvTheme.dp(context, 52)).apply {
                rightMargin = TvTheme.dp(context, 16)
            },
        )
        val column = column()
        column.addView(
            TvTheme.textView(
                context,
                text(vpnStateLabelRes(status.state)),
                TvTheme.TEXT_TITLE_SP,
                TvTheme.textPrimary,
                bold = true,
            ),
        )
        column.addView(
            bodyText(context, text(vpnStateClaimRes(status.state)), TvTheme.textSecondary),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.dp(context, 4)
            },
        )
        val detail = resolve(status.detail) ?: status.reasonKey?.let { vpnReasonLabel(context, it) }
        if (!detail.isNullOrBlank()) {
            column.addView(
                captionText(context, detail),
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = TvTheme.dp(context, 4)
                },
            )
        }
        column.addView(
            captionText(
                context,
                text(
                    R.string.prot_state_detail,
                    text(vpnStateLabelRes(status.state)),
                    text(privacyProfileLabelRes(currentProfile(status))),
                ),
            ),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.dp(context, 8)
            },
        )
        row.addView(column, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        panel.addView(row)
        panel.addView(
            captionText(context, text(R.string.prot_consent_note), TvTheme.textSecondary),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.dp(context, 10)
            },
        )
        return panel
    }

    // --------------------------------------------------------------- counters

    private fun buildCounterRow(status: VpnStatus, snapshot: TrafficSnapshot): View {
        val row = horizontalRow(context)
        val blocked = if (snapshot.blockedFlows > 0) snapshot.blockedFlows else status.blockedFlows
        val apps = if (snapshot.apps.isNotEmpty()) snapshot.apps.size else status.observedApps
        val activeFlows = snapshot.activeFlows
        row.addView(
            metricTile(TvGlyph.SHIELD, TvTheme.accent, blocked.toString(), text(R.string.prot_counter_blocked)),
            tileParams(rightMargin = true),
        )
        row.addView(
            metricTile(TvGlyph.EYE, TvTheme.electricBlue, apps.toString(), text(R.string.prot_counter_apps)),
            tileParams(rightMargin = true),
        )
        row.addView(
            metricTile(
                TvGlyph.REFRESH,
                TvTheme.electricBlue,
                activeFlows.toString(),
                text(R.string.prot_counter_flows),
            ),
            tileParams(rightMargin = false),
        )
        return row
    }

    private fun metricTile(glyph: TvGlyph, color: Int, value: String, label: String): MetricTile =
        MetricTile(context).apply { bind(glyph, color, value, label, TvTheme.textPrimary) }

    private fun tileParams(rightMargin: Boolean): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            if (rightMargin) this.rightMargin = TvTheme.dp(context, 10)
            topMargin = TvTheme.dp(context, 10)
        }

    // ---------------------------------------------------------------- profile

    private fun currentProfile(status: VpnStatus): TvPrivacyProfile {
        val stored = readService { services.settings.privacyProfile() }
        return stored ?: TvPrivacyProfile.fromStorage(status.privacyProfile)
    }

    private fun buildProfileRow(profile: TvPrivacyProfile): FocusableRow {
        val row = FocusableRow(context, interactive = true)
        row.setCard(true)
        row.setLeading(TvGlyph.INFO, TvTheme.accent)
        row.setTitle(text(R.string.prot_profile_title))
        row.setSubtitle(text(R.string.prot_profile_hint))
        val pill = StatusPill(context, text(privacyProfileLabelRes(profile)), TvTone.NEUTRAL, TvGlyph.INFO)
        row.setTrailing(pill)
        row.setOnClickListener {
            val actual = readService { services.settings.privacyProfile() } ?: nextProfile(profile)
            val next = nextProfile(actual)
            readService { services.settings.setPrivacyProfile(next) }
            readService { services.vpn.setPrivacyProfile(next) }
            notify(text(R.string.prot_profile_changed, text(privacyProfileLabelRes(next))))
            host.refreshCurrent()
        }
        return row
    }

    private fun nextProfile(profile: TvPrivacyProfile): TvPrivacyProfile {
        val stages = TvPrivacyProfile.entries
        val index = stages.indexOf(profile)
        return stages[(index + 1).mod(stages.size)]
    }

    // --------------------------------------------------------------- autostart

    private fun buildAutoStartRow(): FocusableRow {
        val enabled = readService { services.settings.vpnAutoStart() }
            ?: readService { services.vpn.autoStartEnabled() }
            ?: false
        val row = FocusableRow(context, interactive = true)
        row.setCard(true)
        row.setLeading(TvGlyph.CLOCK, TvTheme.accent)
        row.setTitle(text(R.string.prot_autostart_title))
        row.setSubtitle(text(R.string.prot_autostart_desc))
        val pill = StatusPill(
            context,
            text(if (enabled) R.string.settings_state_enabled else R.string.settings_state_disabled),
            if (enabled) TvTone.SUCCESS else TvTone.NEUTRAL,
            if (enabled) TvGlyph.CHECK else TvGlyph.CROSS,
        )
        row.setTrailing(pill)
        row.setOnClickListener {
            val next = !enabled
            readService { services.settings.setVpnAutoStart(next) }
            readService { services.vpn.setAutoStartEnabled(next) }
            notify(text(if (next) R.string.settings_state_enabled else R.string.settings_state_disabled))
            host.refreshCurrent()
        }
        return row
    }

    // ------------------------------------------------------------- containment

    private fun buildContainmentRow(profile: TvPrivacyProfile): FocusableRow {
        val enabled = readService { services.settings.containmentEnabled() } ?: false
        val active = readService { services.containment.active() }.orEmpty()
        val row = FocusableRow(context, interactive = true)
        row.setCard(true)
        row.setLeading(TvGlyph.SHIELD, if (enabled) TvTheme.accent else TvTheme.textSecondary)
        row.setTitle(text(R.string.kinetic_enable_title))
        val subtitle = buildString {
            append(text(R.string.kinetic_enable_body))
            if (profile != TvPrivacyProfile.STRICT) {
                append("\n")
                append(text(R.string.kinetic_requires_strict))
            }
            if (active.isNotEmpty()) {
                append("\n")
                append(text(R.string.kinetic_containment_active))
                append(": ")
                append(active.size)
            }
        }
        row.setSubtitle(subtitle)
        val pill = StatusPill(
            context,
            text(
                when {
                    enabled && profile == TvPrivacyProfile.STRICT -> R.string.kinetic_containment_enabled
                    enabled -> R.string.kinetic_containment_disabled
                    else -> R.string.kinetic_containment_disabled
                },
            ),
            if (enabled && profile == TvPrivacyProfile.STRICT) TvTone.SUCCESS else TvTone.NEUTRAL,
            if (enabled && profile == TvPrivacyProfile.STRICT) TvGlyph.CHECK else TvGlyph.INFO,
        )
        row.setTrailing(pill)
        row.setOnClickListener {
            val next = !enabled
            readService { services.containment.setEnabled(next) }
            if (next && profile != TvPrivacyProfile.STRICT) {
                readService { services.settings.setPrivacyProfile(TvPrivacyProfile.STRICT) }
                readService { services.vpn.setPrivacyProfile(TvPrivacyProfile.STRICT) }
            }
            notify(text(if (next) R.string.kinetic_containment_enabled else R.string.kinetic_containment_disabled))
            host.refreshCurrent()
        }
        return row
    }

    // -------------------------------------------------------------- categories

    private fun buildCategorySection(scaffold: ScreenScaffold, snapshot: TrafficSnapshot) {
        val categories = categorize(snapshot.apps)
        if (categories.isEmpty()) {
            scaffold.addFullWidth(captionText(context, text(R.string.prot_categories_empty), TvTheme.textSecondary))
        } else {
            val row = horizontalRow(context)
            for ((key, count) in categories) {
                val glyph = when (key) {
                    "c2" -> TvGlyph.ALERT
                    "ads", "acr" -> TvGlyph.INFO
                    else -> TvGlyph.CLOCK
                }
                val tone = when (key) {
                    "c2" -> TvTone.DANGER
                    "ads", "acr" -> TvTone.WARNING
                    else -> TvTone.INFO
                }
                row.addView(
                    StatusPill(
                        context,
                        trafficCategoryLabel(key) + " · $count",
                        tone,
                        glyph,
                    ),
                    LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                        rightMargin = TvTheme.dp(context, 8)
                    },
                )
            }
            scaffold.addFullWidth(row)
            scaffold.addFullWidth(captionText(context, text(R.string.prot_categories_note), TvTheme.textSecondary))
        }
    }

    private fun trafficCategoryLabel(key: String): String = when (key) {
        "telemetry" -> text(R.string.prot_cat_telemetry)
        "acr" -> text(R.string.prot_cat_acr)
        "ads" -> text(R.string.prot_cat_ads)
        else -> text(R.string.prot_cat_c2)
    }

    /** Local heuristic over observed domains only; returns category -> observed domain count. */
    private fun categorize(apps: List<AppTraffic>): List<Pair<String, Int>> {
        val domainSet = LinkedHashSet<String>()
        for (app in apps) {
            for (domain in app.topDomains) domainSet += domain.domain.lowercase()
        }
        if (domainSet.isEmpty()) return emptyList()
        val keywords = mapOf(
            "telemetry" to listOf("telemetry", "metrics", "analytics", "stats", "logging"),
            "acr" to listOf("acr", "contentrecognition", "tvsquared", "samba", "screen"),
            "ads" to listOf("ads", "adserver", "doubleclick", "googlesyndication", "advert", "tracker"),
            "c2" to listOf("c2", "command", "botnet", "malware"),
        )
        return keywords.mapNotNull { (category, keys) ->
            val count = domainSet.count { domain -> keys.any { domain.contains(it) } }
            if (count > 0) category to count else null
        }.sortedByDescending { it.second }
    }

    // ------------------------------------------------------------------ links

    private fun buildTrafficLinkRow(): FocusableRow {
        val row = FocusableRow(context, interactive = true)
        row.setCard(true)
        row.setLeading(TvGlyph.EYE, TvTheme.electricBlue)
        row.setTitle(text(R.string.prot_link_traffic))
        row.setSubtitle(text(R.string.prot_link_traffic_desc))
        row.setChevronVisible(true)
        row.setOnClickListener { host.navigate(TvRoute.TRAFFIC) }
        return row
    }

    private fun buildXdrLinkRow(): FocusableRow {
        val row = FocusableRow(context, interactive = true)
        row.setCard(true)
        row.setLeading(TvGlyph.ALERT, TvTheme.accent)
        row.setTitle(text(R.string.prot_link_xdr))
        row.setSubtitle(text(R.string.prot_link_xdr_desc))
        row.setChevronVisible(true)
        row.setOnClickListener { host.navigate(TvRoute.XDR) }
        return row
    }

    // ---------------------------------------------------------------- actions

    private fun startProtection() {
        val result = readService { services.vpn.start(host.activity(), vpnListener) }
        if (result == null) {
            notify(text(R.string.prot_start_failed))
        } else if (result.consentRequired) {
            notify(text(R.string.prot_start_consent))
        } else if (result.started) {
            notify(text(R.string.prot_start_started))
        } else {
            notify(text(R.string.prot_start_failed))
        }
        host.refreshCurrent()
    }

    private fun stopProtection() {
        readService { services.vpn.stop() }
        notify(text(R.string.prot_stop_requested))
        host.refreshCurrent()
    }
}
