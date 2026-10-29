package de.visiongaia.gedefense.tv.ui

import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.ui.screens.AboutScreen
import de.visiongaia.gedefense.tv.ui.screens.AppsScreen
import de.visiongaia.gedefense.tv.ui.screens.CheckScreen
import de.visiongaia.gedefense.tv.ui.screens.EvidenceScreen
import de.visiongaia.gedefense.tv.ui.screens.FindingDetailScreen
import de.visiongaia.gedefense.tv.ui.screens.FindingsScreen
import de.visiongaia.gedefense.tv.ui.screens.HardeningScreen
import de.visiongaia.gedefense.tv.ui.screens.HomeScreen
import de.visiongaia.gedefense.tv.ui.screens.OnboardingScreen
import de.visiongaia.gedefense.tv.ui.screens.ProtectionScreen
import de.visiongaia.gedefense.tv.ui.screens.SettingsScreen
import de.visiongaia.gedefense.tv.ui.screens.ThreatIntelScreen
import de.visiongaia.gedefense.tv.ui.screens.TrafficScreen
import de.visiongaia.gedefense.tv.ui.screens.XdrScreen

/**
 * Builds the TV navigation rail and creates the screen instance for a route.
 *
 * The Lead-owned shell (`TvMainActivity`) owns the back stack, focus routing, onboarding gating and
 * window concerns; this registry only maps routes to screens and provides the localised rail model.
 * Rail: PROTECTION, TRAFFIC, HOME, CHECK, FINDINGS, APPS, HARDENING, THREAT_INTEL, EVIDENCE,
 * SETTINGS. ONBOARDING is a full-screen shell flow (no rail), XDR is pushed from Protection/Home and
 * FINDING_DETAIL/ABOUT are pushed detail screens.
 */
class ScreenRegistry(private val services: TvServices) {

    /** Rail entries in display order. Labels and descriptions are German string resources. */
    fun routesForRail(): List<NavItem> = RAIL

    /**
     * Maps any route (including pushed detail screens) to the rail entry that should be highlighted.
     * XDR belongs to the protection context; finding details belong to the findings entry.
     */
    fun railSelectionFor(route: TvRoute): TvRoute = when (route) {
        TvRoute.XDR -> TvRoute.PROTECTION
        TvRoute.FINDING_DETAIL -> TvRoute.FINDINGS
        TvRoute.ABOUT -> TvRoute.SETTINGS
        else -> route
    }

    /**
     * Creates the screen for [route]. [argument] carries the pushed identity (for example the finding
     * id for [TvRoute.FINDING_DETAIL]) and is ignored by screens that do not need one.
     */
    fun create(route: TvRoute, argument: String? = null): TvScreen = when (route) {
        TvRoute.ONBOARDING -> OnboardingScreen(services)
        TvRoute.PROTECTION -> ProtectionScreen(services)
        TvRoute.TRAFFIC -> TrafficScreen(services)
        TvRoute.XDR -> XdrScreen(services)
        TvRoute.HOME -> HomeScreen(services)
        TvRoute.CHECK -> CheckScreen(services)
        TvRoute.FINDINGS -> FindingsScreen(services)
        TvRoute.FINDING_DETAIL -> FindingDetailScreen(services, argument)
        TvRoute.APPS -> AppsScreen(services)
        TvRoute.HARDENING -> HardeningScreen(services)
        TvRoute.THREAT_INTEL -> ThreatIntelScreen(services)
        TvRoute.EVIDENCE -> EvidenceScreen(services)
        TvRoute.SETTINGS -> SettingsScreen(services)
        TvRoute.ABOUT -> AboutScreen(services)
    }

    companion object {
        private val RAIL: List<NavItem> = listOf(
            NavItem(TvRoute.PROTECTION, R.string.nav_protection, R.string.nav_protection_desc),
            NavItem(TvRoute.TRAFFIC, R.string.nav_traffic, R.string.nav_traffic_desc),
            NavItem(TvRoute.HOME, R.string.nav_home, R.string.nav_home_desc),
            NavItem(TvRoute.CHECK, R.string.nav_check, R.string.nav_check_desc),
            NavItem(TvRoute.FINDINGS, R.string.nav_findings, R.string.nav_findings_desc),
            NavItem(TvRoute.APPS, R.string.nav_apps, R.string.nav_apps_desc),
            NavItem(TvRoute.HARDENING, R.string.nav_hardening, R.string.nav_hardening_desc),
            NavItem(TvRoute.THREAT_INTEL, R.string.nav_threat_intel, R.string.nav_threat_intel_desc),
            NavItem(TvRoute.EVIDENCE, R.string.nav_evidence, R.string.nav_evidence_desc),
            NavItem(TvRoute.SETTINGS, R.string.nav_settings, R.string.nav_settings_desc),
        )
    }
}
