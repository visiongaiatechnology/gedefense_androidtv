package de.visiongaia.gedefense.tv.ui

import de.visiongaia.gedefense.tv.core.model.ContainmentRecord
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Process-wide bridge between the containment data path (VPN/traffic store) and the TV shell.
 *
 * The shell subscribes to show the reversible "kill" popup; the notifier never blocks the caller and
 * never invents a record: only real, user-visible containment changes are published.
 */
object ContainmentNotifier {
    fun interface Listener {
        fun onContainmentChanged(record: ContainmentRecord)
    }

    private val listeners = CopyOnWriteArrayList<Listener>()

    fun addListener(listener: Listener) {
        listeners.addIfAbsent(listener)
    }

    fun removeListener(listener: Listener) {
        listeners.remove(listener)
    }

    fun publish(record: ContainmentRecord) {
        for (listener in listeners) {
            try {
                listener.onContainmentChanged(record)
            } catch (_: Throwable) {
                // A UI listener must never disturb the data path.
            }
        }
    }
}
