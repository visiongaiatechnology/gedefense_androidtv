package de.visiongaia.gedefense.tv.platform

import de.visiongaia.gedefense.tv.core.model.Collector
import de.visiongaia.gedefense.tv.core.model.TvEvent

/**
 * TV collector that additionally exposes the real XDR-lite events observed during its last run.
 *
 * The read-only tv-core contract has no event sink on [de.visiongaia.gedefense.tv.core.model.CollectorResult];
 * events are therefore kept on the collector instance and persisted by the scan controller. Events
 * are never invented: a collector that observed nothing returns an empty list.
 */
interface TvCollector : Collector {
    val lastEvents: List<TvEvent>
}
