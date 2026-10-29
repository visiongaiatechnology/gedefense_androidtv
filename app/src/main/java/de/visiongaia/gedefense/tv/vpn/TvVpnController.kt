package de.visiongaia.gedefense.tv.vpn

import android.app.Activity
import android.app.Fragment
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import de.visiongaia.gedefense.tv.contract.VpnControlApi
import de.visiongaia.gedefense.tv.contract.VpnStartResult
import de.visiongaia.gedefense.tv.contract.VpnStateListener
import de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile
import de.visiongaia.gedefense.tv.core.model.VpnState
import de.visiongaia.gedefense.tv.core.model.VpnStatus
import de.visiongaia.gedefense.tv.data.TvSettingsStore

/**
 * VpnControlApi implementation for the TV.
 *
 * Consent flow: [VpnService.prepare] returns an Intent when user approval is required. The controller
 * launches it through a headless [Fragment] (same pattern as the SAF report export), so no Lead-owned
 * Activity callback is needed; the result starts the foreground [TvVpnService]. `startIfPermitted` is
 * the consent-free path used by auto-start/onboarding.
 *
 * Status is a process-wide snapshot from [TvVpnProcessState]; [addStateListener]/[removeStateListener]
 * provide live updates for Protection/Onboarding/Home. [setThreatIndex] hands the latest validated
 * threat index to the data plane and refreshes a running policy.
 */
class TvVpnController(
    context: Context,
    private val settings: TvSettingsStore,
    private val traffic: de.visiongaia.gedefense.tv.traffic.TvTrafficStore? = null,
) : VpnControlApi {
    private val appContext = context.applicationContext

    override fun status(): VpnStatus {
        val base = TvVpnProcessState.status()
        if (!base.isProtecting) return base
        // O(1) cached snapshot: enrich the truthful state with locally counted traffic totals.
        return try {
            val snapshot = traffic?.snapshot()
            if (snapshot == null) base else base.copy(
                blockedFlows = snapshot.blockedFlows,
                observedApps = snapshot.apps.size,
            )
        } catch (_: Throwable) {
            base
        }
    }

    override fun start(activity: Activity, listener: VpnStateListener): VpnStartResult {
        addStateListener(listener)
        if (!NativeGaiaNet.available) {
            publishUnsupported()
            return VpnStartResult(started = false, consentRequired = false, message = null)
        }
        val prepareIntent = try {
            VpnService.prepare(activity)
        } catch (error: RuntimeException) {
            Log.w(TAG, "VPN prepare failed type=${error::class.java.simpleName}")
            return VpnStartResult(started = false, consentRequired = false, message = null)
        }
        if (prepareIntent == null) {
            return VpnStartResult(started = startServiceInternal(), consentRequired = false, message = null)
        }
        return if (requestConsent(activity, prepareIntent, listener)) {
            VpnStartResult(started = false, consentRequired = true, message = null)
        } else {
            VpnStartResult(started = false, consentRequired = true, message = null)
        }
    }

    override fun startIfPermitted(listener: VpnStateListener): VpnStartResult {
        addStateListener(listener)
        if (!NativeGaiaNet.available) {
            publishUnsupported()
            return VpnStartResult(started = false, consentRequired = false, message = null)
        }
        val prepareIntent = try {
            VpnService.prepare(appContext)
        } catch (error: RuntimeException) {
            Log.w(TAG, "VPN prepare failed type=${error::class.java.simpleName}")
            return VpnStartResult(started = false, consentRequired = false, message = null)
        }
        return if (prepareIntent != null) {
            VpnStartResult(started = false, consentRequired = true, message = null)
        } else {
            VpnStartResult(started = startServiceInternal(), consentRequired = false, message = null)
        }
    }

    override fun stop(): Boolean {
        if (status().state == VpnState.OFF) return false
        return sendServiceIntent(TvVpnService.stopIntent(appContext), foreground = false)
    }

    override fun autoStartEnabled(): Boolean = try {
        settings.vpnAutoStart()
    } catch (_: Throwable) {
        false
    }

    override fun setAutoStartEnabled(enabled: Boolean) {
        try {
            settings.setVpnAutoStart(enabled)
        } catch (_: Throwable) {
            // Preferences failures must never crash the protection screen.
        }
    }

    override fun privacyProfile(): TvPrivacyProfile = try {
        settings.privacyProfile()
    } catch (_: Throwable) {
        TvPrivacyProfile.BALANCED
    }

    override fun setPrivacyProfile(profile: TvPrivacyProfile): Boolean {
        return try {
            settings.setPrivacyProfile(profile)
            // A profile change only needs a data-plane refresh while protection is running.
            if (status().isProtecting) {
                sendServiceIntent(TvVpnService.refreshIntent(appContext), foreground = false)
            }
            true
        } catch (_: Throwable) {
            false
        }
    }

    override fun addStateListener(listener: VpnStateListener) {
        TvVpnProcessState.addListener(listener)
    }

    override fun removeStateListener(listener: VpnStateListener) {
        TvVpnProcessState.removeListener(listener)
    }

    override fun setThreatIndex(index: de.visiongaia.gedefense.mobile.core.ThreatIndex): Boolean {
        TvVpnProcessState.threatIndex = index
        // Apply the updated policy as soon as possible while protection is running; the service
        // rebuilds the helper policy with a fail-closed tunnel handover.
        return if (status().isProtecting) {
            sendServiceIntent(TvVpnService.refreshIntent(appContext), foreground = false)
        } else {
            true
        }


    }
    private fun requestConsent(activity: Activity, prepareIntent: Intent, listener: VpnStateListener): Boolean {
        return try {
            val fragmentManager = activity.fragmentManager
            if (fragmentManager.findFragmentByTag(TvVpnConsentFragment.TAG) != null) return false
            val fragment = TvVpnConsentFragment()
            fragment.prepareIntent = prepareIntent
            fragment.onResult = { granted ->
                if (granted) {
                    if (!startServiceInternal()) {
                        TvVpnProcessState.publish(
                            VpnStatus(state = VpnState.FAILED, startedAtMillis = 0L, reasonKey = "vpn_start_failed"),
                        )
                    }
                } else {
                    TvVpnProcessState.publish(
                        VpnStatus(state = VpnState.OFF, startedAtMillis = 0L, reasonKey = "vpn_consent_denied"),
                    )
                }
            }
            fragmentManager.beginTransaction().add(fragment, TvVpnConsentFragment.TAG).commitAllowingStateLoss()
            true
        } catch (error: Throwable) {
            Log.w(TAG, "VPN consent launch failed type=${error::class.java.simpleName}")
            false
        }
    }

    private fun publishUnsupported() {
        TvVpnProcessState.publish(
            VpnStatus(state = VpnState.UNSUPPORTED, startedAtMillis = 0L, reasonKey = "vpn_helper_unavailable"),
        )
    }

    private fun startServiceInternal(): Boolean =
        sendServiceIntent(TvVpnService.startIntent(appContext), foreground = true)

    private fun sendServiceIntent(intent: Intent, foreground: Boolean): Boolean = try {
        if (foreground) {
            appContext.startForegroundService(intent)
        } else {
            @Suppress("DEPRECATION")
            appContext.startService(intent)
        }
        true
    } catch (_: IllegalStateException) {
        // Background-start restrictions: fall back to a plain start; the service still foregrounds
        // itself immediately in onStartCommand.
        try {
            @Suppress("DEPRECATION")
            appContext.startService(intent)
            true
        } catch (_: RuntimeException) {
            false
        }
    } catch (_: SecurityException) {
        false
    } catch (_: RuntimeException) {
        false
    }

    companion object {
        private const val TAG = "GeDefenseTvVpnController"
    }
}

/**
 * Headless VpnService.prepare() consent host. Receives its own onActivityResult from the Activity
 * (plain Activity dispatches results to attached fragments), so no Lead-owned callback is required.
 */
@Suppress("DEPRECATION")
class TvVpnConsentFragment : Fragment() {
    var prepareIntent: Intent? = null
    var onResult: ((Boolean) -> Unit)? = null
    private var started = false
    private val finished = java.util.concurrent.atomic.AtomicBoolean(false)

    init {
        retainInstance = true
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null && prepareIntent == null) {
            // After process death the consent intent is gone; fail closed instead of hanging.
            complete(false)
        }
    }

    override fun onStart() {
        super.onStart()
        if (started || finished.get()) return
        started = true
        val intent = prepareIntent
        val host = activity
        if (intent == null || host == null) {
            complete(false)
            return
        }
        try {
            startActivityForResult(intent, REQUEST_CODE)
        } catch (_: Throwable) {
            complete(false)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_CODE) complete(resultCode == Activity.RESULT_OK)
    }

    private fun complete(granted: Boolean) {
        if (!finished.compareAndSet(false, true)) return
        val callback = onResult
        onResult = null
        activity?.fragmentManager?.let { manager ->
            try {
                manager.beginTransaction().remove(this).commitAllowingStateLoss()
            } catch (_: Throwable) {
                // Fragment removal is cosmetic; the result is delivered below regardless.
            }
        }
        try {
            callback?.invoke(granted)
        } catch (_: Throwable) {
            // A UI callback must never crash the consent host.
        }
    }

    companion object {
        const val TAG = "gedefense-tv-vpn-consent"
        private const val REQUEST_CODE = 7303
    }
}
