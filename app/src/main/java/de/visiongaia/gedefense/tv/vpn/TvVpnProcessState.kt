package de.visiongaia.gedefense.tv.vpn

import android.os.Handler
import android.os.Looper
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.tv.contract.VpnStateListener
import de.visiongaia.gedefense.tv.core.model.VpnStatus
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Process-wide VPN status bridge between the `VpnService`, the controller and the TV UI.
 *
 * The service and the controller live in the same app process; this object keeps the single truthful
 * status snapshot, the latest validated threat index for the policy, and fans state changes out to
 * registered listeners on the main thread. Listeners are isolated: a throwing UI callback can never
 * disturb the data plane.
 */
object TvVpnProcessState {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val listeners = CopyOnWriteArrayList<VpnStateListener>()

    @Volatile
    private var current: VpnStatus = VpnStatus.OFF

    /** Latest validated threat index handed over by the app; empty means "privacy policy only". */
    @Volatile
    var threatIndex: ThreatIndex = ThreatIndex.empty()

    fun status(): VpnStatus = current

    fun publish(next: VpnStatus) {
        current = next
        if (listeners.isEmpty()) return
        for (listener in listeners) {
            mainHandler.post {
                try {
                    listener.onStateChanged(next)
                } catch (_: Throwable) {
                    // A UI observer has no authority over the VPN data plane.
                }
            }
        }
    }

    fun addListener(listener: VpnStateListener): Boolean = listeners.add(listener)

    fun removeListener(listener: VpnStateListener): Boolean = listeners.remove(listener)

    fun clearListeners() {
        listeners.clear()
    }
}
