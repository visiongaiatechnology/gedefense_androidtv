package de.visiongaia.gedefense.tv.core.scan

import de.visiongaia.gedefense.tv.core.model.CancelSignal
import de.visiongaia.gedefense.tv.core.model.Collector
import de.visiongaia.gedefense.tv.core.model.CollectorEnvironment
import de.visiongaia.gedefense.tv.core.model.ScanOutcome
import de.visiongaia.gedefense.tv.core.model.ScanProgress

/**
 * Executes all collectors in a bounded, cancellable, fault-isolated run.
 *
 * Contract:
 *  - a throwing collector becomes a `FAILED` [de.visiongaia.gedefense.tv.core.model.CollectorResult]
 *    and never aborts the remaining collectors;
 *  - each collector has a hard time budget; exceeding it is a failed result with `collector.timeout`;
 *  - cancellation is checked between collectors and propagated to progress observers once;
 *  - no collector may be executed twice in one run.
 */
interface ScanEngine {
    @Throws(InterruptedException::class)
    fun run(
        collectors: List<Collector>,
        environment: CollectorEnvironment,
        cancel: CancelSignal,
        onProgress: (ScanProgress) -> Unit,
    ): ScanOutcome
}

/** Hard bounds for a TV scan. Low overhead is a datasheet design principle. */
data class ScanEngineConfig(
    val collectorTimeoutMillis: Long = 12_000L,
    val maxCollectors: Int = 32,
) {
    init {
        require(collectorTimeoutMillis in 1_000L..60_000L) { "invalid collector timeout" }
        require(maxCollectors in 1..64) { "invalid collector bound" }
    }
}
