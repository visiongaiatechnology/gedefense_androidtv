package de.visiongaia.gedefense.tv.platform

import de.visiongaia.gedefense.tv.core.model.CancelSignal
import de.visiongaia.gedefense.tv.core.model.CollectorCategory
import de.visiongaia.gedefense.tv.core.model.CollectorCoverage
import de.visiongaia.gedefense.tv.core.model.CollectorDescriptor
import de.visiongaia.gedefense.tv.core.model.CollectorEnvironment
import de.visiongaia.gedefense.tv.core.model.CollectorResult
import de.visiongaia.gedefense.tv.core.model.DataQuality
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.ThreatIntelStatus
import de.visiongaia.gedefense.tv.core.model.TvEvent

/**
 * Reports the local threat-intelligence feed status as observed on this device.
 *
 * V1 has no system-wide flow visibility (datasheet section 7), therefore TV_TI_MATCH events and
 * matches can only exist for indicators the app actually observed. The TV app observes no such
 * indicators today, so this collector emits an honest empty match set and never invents hits from
 * unavailable telemetry. Its job is the visible status: which feeds are cached, which are fresh and
 * which are stale/offline.
 */
class ThreatIntelCollector(
    private val statusProvider: () -> ThreatIntelStatus,
) : TvCollector {
    override val descriptor: CollectorDescriptor = CollectorSupport.descriptor(
        id = "threat-intel",
        category = CollectorCategory.THREAT_INTEL,
        titleKey = "collector.threatintel.title",
        descriptionKey = "collector.threatintel.description",
        restrictedOnSomeDevices = false,
    )

    @Volatile
    override var lastEvents: List<TvEvent> = emptyList()
        private set

    @Volatile
    var lastStatus: ThreatIntelStatus? = null
        private set

    override fun collect(environment: CollectorEnvironment, cancel: CancelSignal): CollectorResult {
        val startedAt = System.currentTimeMillis()
        return try {
            if (cancel.isCancelled()) throw InterruptedException("threat-intel collector cancelled")
            val status = statusProvider()
            lastStatus = status
            val total = status.feeds.size
            val available = status.availableCount
            val fresh = status.freshCount
            val stale = status.staleCount
            val visibility = when {
                total == 0 -> DataVisibility.NONE
                // No cached feed is an *observed* state of the TI subsystem, but it must never look
                // clean: PARTIAL keeps the overall posture capped instead of hiding the gap.
                available == 0 -> DataVisibility.PARTIAL
                stale > 0 -> DataVisibility.STALE
                else -> DataVisibility.FULL
            }
            val dataQuality = when {
                available == 0 -> DataQuality.UNKNOWN
                stale > 0 -> DataQuality.STALE
                fresh > 0 -> DataQuality.FRESH
                else -> DataQuality.UNKNOWN
            }
            val completedAt = System.currentTimeMillis()
            CollectorSupport.supported(
                descriptor = descriptor,
                startedAtMillis = startedAt,
                completedAtMillis = completedAt,
                visibility = visibility,
                dataQuality = dataQuality,
                // No findings by design: no feed match was observed by this app in V1.
                findings = emptyList(),
                coverage = CollectorCoverage(
                    observed = available,
                    total = total,
                    note = when {
                        available == 0 -> MessageRef(CollectorSupport.KEY_COLLECTOR_STALE)
                        stale > 0 -> MessageRef(CollectorSupport.KEY_COLLECTOR_STALE)
                        else -> null
                    },
                ),
                errorKey = if (available == 0) MessageRef(CollectorSupport.KEY_COLLECTOR_STALE) else null,
            )
        } catch (interrupted: InterruptedException) {
            throw interrupted
        } catch (_: Throwable) {
            CollectorSupport.failed(
                descriptor = descriptor,
                startedAtMillis = startedAt,
                completedAtMillis = System.currentTimeMillis(),
            )
        }
    }
}
