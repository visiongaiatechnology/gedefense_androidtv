package de.visiongaia.gedefense.tv.ui

import android.view.KeyEvent
import android.view.View

/**
 * Screen identifiers of the TV app. The D-pad navigation rail exposes the first block; detail
 * screens are pushed by their parent screen.
 */
enum class TvRoute {
    ONBOARDING,
    PROTECTION,
    TRAFFIC,
    XDR,
    HOME,
    CHECK,
    FINDINGS,
    FINDING_DETAIL,
    APPS,
    HARDENING,
    THREAT_INTEL,
    EVIDENCE,
    SETTINGS,
    ABOUT,
}

/** One entry of the left navigation rail, localised through string resources. */
data class NavItem(
    val route: TvRoute,
    val labelRes: Int,
    val descriptionRes: Int,
)

/**
 * Navigation and notification surface provided by [de.visiongaia.gedefense.tv.TvMainActivity] to
 * every screen. Screens must not start activities or manipulate the back stack directly.
 */
interface ScreenHost {
    fun navigate(route: TvRoute, argument: String? = null)

    /** Pops the current screen. Returns false when the stack is already at home. */
    fun goBack(): Boolean

    /** Shows a short, unobtrusive overlay message (never a blocking dialog for telemetry). */
    fun notifyUser(message: String)

    /** Rebuilds the current screen from its current data source. */
    fun refreshCurrent()

    /** The owning activity, required for platform consent dialogs (VpnService.prepare). */
    fun activity(): android.app.Activity

    /** Hides the navigation rail during immersive flows such as the first-run onboarding. */
    fun setRailVisible(visible: Boolean)

    /** Sir Quacksec welcome animation (shown once per app start; skippable). */
    fun showWelcomeOverlay()

    /** Blocking-looking but D-pad-safe Threat-Intelligence sync overlay with brand logo. */
    fun showSyncOverlay(title: String)

    fun updateSyncOverlay(completed: Int, total: Int)

    fun hideSyncOverlay()
}

/**
 * A single TV screen. Screens own their view tree and focus behaviour.
 *
 * Contract:
 *  - every interactive control must be reachable and activatable with the D-pad;
 *  - the initial D-pad focus must land on a sensible control ([initialFocus]);
 *  - [handleBack] returns true when the screen consumed BACK (for example closing a detail pane);
 *  - no screen may assume touch input, hover or a mouse pointer.
 */
interface TvScreen {
    val route: TvRoute

    fun createView(host: ScreenHost): View

    fun onShown() {}

    fun onHidden() {}

    fun handleBack(): Boolean = false

    fun initialFocus(): View? = null

    /** Optional screen-specific key handling; return true when consumed. */
    fun onKeyEvent(event: KeyEvent): Boolean = false
}
