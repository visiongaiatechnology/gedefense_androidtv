package de.visiongaia.gedefense.tv.contract

import android.app.Activity
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.OriginInfo
import de.visiongaia.gedefense.tv.core.model.TrafficFlow
import de.visiongaia.gedefense.tv.core.model.TrafficSnapshot
import de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile
import de.visiongaia.gedefense.tv.core.model.VpnStatus

/**
 * V2 contracts: on-device loopback VPN control and local traffic telemetry.
 *
 * These interfaces connect the TV UI with the VpnService/data plane. All values are local; no
 * traffic content ever leaves the device.
 */

/** Result of a user-triggered VPN start (consent can require an Activity round trip). */
data class VpnStartResult(
    val started: Boolean,
    val consentRequired: Boolean,
    val message: MessageRef?,
)

/** Listener for asynchronous VPN start/stop transitions; callbacks may arrive on a worker thread. */
fun interface VpnStateListener {
    fun onStateChanged(status: VpnStatus)
}

interface VpnControlApi {
    fun status(): VpnStatus

    /** Live status updates for Protection/Onboarding/Home without polling. */
    fun addStateListener(listener: VpnStateListener)

    fun removeStateListener(listener: VpnStateListener)

    /**
     * Hands the latest validated Threat-Intelligence index to the VPN policy. The app calls this on
     * startup and after every successful TI sync; the service rebuilds its policy on next start or
     * applies it live when the helper supports a policy refresh.
     */
    fun setThreatIndex(index: de.visiongaia.gedefense.mobile.core.ThreatIndex): Boolean

    /**
     * Requests user consent through [activity] when required and starts the local loopback VPN.
     * Returns immediately; the final state is delivered through the listener or [status].
     */
    fun start(activity: Activity, listener: VpnStateListener): VpnStartResult

    /** Starts without consent UI when consent was granted previously (e.g. onboarding finished). */
    fun startIfPermitted(listener: VpnStateListener): VpnStartResult

    fun stop(): Boolean

    fun autoStartEnabled(): Boolean

    fun setAutoStartEnabled(enabled: Boolean)

    /** Current local privacy/filter profile (drives the DNS/tracker filtering rules). */
    fun privacyProfile(): TvPrivacyProfile

    fun setPrivacyProfile(profile: TvPrivacyProfile): Boolean
}

interface TrafficApi {
    /** Live, bounded snapshot of locally observed traffic. */
    fun snapshot(): TrafficSnapshot

    /** Monotonic revision; changes whenever the snapshot changed. Cheap polling primitive. */
    fun revision(): Long

    /** Bounded history, newest first. */
    fun flows(limit: Int = 200): List<TrafficFlow>

    /** Approximate map origin (country of the TV setup, never GPS). */
    fun origin(): OriginInfo

    /** Clears the current session counters (does not stop the VPN). */
    fun clearSession()
}

/** TV XDR-light incidents derived from real local traffic/finding signals. */
interface XdrApi {
    fun incidents(): List<de.visiongaia.gedefense.tv.core.xdr.XdrIncident>

    /** Monotonic revision; changes whenever incidents changed. */
    fun revision(): Long

    fun clear()
}
