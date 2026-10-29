package de.visiongaia.gedefense.tv.contract

import de.visiongaia.gedefense.tv.core.model.ContainmentRecord
import de.visiongaia.gedefense.tv.core.model.OutboundAnomaly

/** Local outbound anomaly feed (V2.1 "Outbound Kinetic-Lite", observe-only by default). */
interface AnomalyApi {
    fun anomalies(): List<OutboundAnomaly>

    /** Monotonic revision; changes when the anomaly set changes. */
    fun revision(): Long
}

/** Listener for apply/release/expiry of local temporary containments (UI popup + lists). */
fun interface ContainmentListener {
    fun onContainmentChanged(record: ContainmentRecord)
}

/**
 * Local temporary containment of outbound destination prefixes.
 *
 * Containment is opt-in (strict profile) and always reversible: every record has an explicit expiry
 * and can be released by the user from the TV popup or the protection/network screens.
 */
interface ContainmentApi {
    fun active(): List<ContainmentRecord>

    fun history(limit: Int = 50): List<ContainmentRecord>

    fun release(id: String): Boolean

    fun revision(): Long

    fun addListener(listener: ContainmentListener)

    fun removeListener(listener: ContainmentListener)

    /** Policy switch (Settings → Protection). Default is false (observe-only). */
    fun setEnabled(enabled: Boolean)

    fun enabled(): Boolean
}
