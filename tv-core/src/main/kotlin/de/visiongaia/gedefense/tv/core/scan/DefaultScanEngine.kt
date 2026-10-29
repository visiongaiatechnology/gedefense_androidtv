package de.visiongaia.gedefense.tv.core.scan

import de.visiongaia.gedefense.tv.core.model.CancelSignal
import de.visiongaia.gedefense.tv.core.model.CapabilityState
import de.visiongaia.gedefense.tv.core.model.Collector
import de.visiongaia.gedefense.tv.core.model.CollectorDescriptor
import de.visiongaia.gedefense.tv.core.model.CollectorEnvironment
import de.visiongaia.gedefense.tv.core.model.CollectorResult
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.ScanOutcome
import de.visiongaia.gedefense.tv.core.model.ScanProgress
import de.visiongaia.gedefense.tv.core.model.ScanState
import de.visiongaia.gedefense.tv.core.score.DefaultCoverageAggregator
import de.visiongaia.gedefense.tv.core.score.RuleBasedScoringEngine
import de.visiongaia.gedefense.tv.core.score.ScoringEngine
import java.util.UUID
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Default bounded, cancellable, fault-isolated scan runner.
 *
 * Semantics:
 *  - collectors run sequentially on one dedicated daemon thread (low overhead, deterministic order);
 *  - a collector that throws, returns an unattributable result or exceeds [ScanEngineConfig.collectorTimeoutMillis]
 *    becomes a `FAILED` [CollectorResult] and never aborts the remaining collectors;
 *  - a cancel signal observed between collectors stops the run with [ScanState.CANCELLED] and the
 *    results collected so far; a thread interruption is rethrown as [InterruptedException];
 *  - progress is emitted once per started collector plus exactly one final update;
 *  - the outcome carries [DefaultCoverageAggregator] coverage and [RuleBasedScoringEngine] score.
 */
class DefaultScanEngine(
    private val scoring: ScoringEngine = RuleBasedScoringEngine,
    private val config: ScanEngineConfig = ScanEngineConfig(),
    private val clock: () -> Long = { System.currentTimeMillis() },
) : ScanEngine {

    override fun run(
        collectors: List<Collector>,
        environment: CollectorEnvironment,
        cancel: CancelSignal,
        onProgress: (ScanProgress) -> Unit,
    ): ScanOutcome {
        require(collectors.size <= config.maxCollectors) {
            "too many collectors: ${collectors.size} > ${config.maxCollectors}"
        }
        val collectorIds = collectors.map { it.descriptor.id }
        require(collectorIds.size == collectorIds.toSet().size) { "duplicate collector id in scan input" }

        val scanId = UUID.randomUUID().toString()
        val startedAt = clock()
        val results = mutableListOf<CollectorResult>()
        var cancelled = false

        val executor = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "tv-scan-collector").apply { isDaemon = true }
        }
        try {
            for (collector in collectors) {
                if (cancel.isCancelled()) {
                    cancelled = true
                    break
                }
                val descriptor = collector.descriptor
                emitProgress(onProgress, results, collectors.size, descriptor.id, descriptor.title)
                val collectorStartedAt = clock()
                val future = executor.submit<CollectorResult> { collector.collect(environment, cancel) }
                try {
                    val result = future.get(config.collectorTimeoutMillis, TimeUnit.MILLISECONDS)
                    results += normalize(result, descriptor)
                } catch (_: TimeoutException) {
                    future.cancel(true)
                    results += failedResult(descriptor, collectorStartedAt, "collector.timeout")
                } catch (execution: ExecutionException) {
                    val cause = execution.cause
                    if (cancel.isCancelled() && cause is InterruptedException) {
                        cancelled = true
                    } else {
                        results += failedResult(descriptor, collectorStartedAt, "collector.failed")
                    }
                } catch (interrupted: InterruptedException) {
                    future.cancel(true)
                    Thread.currentThread().interrupt()
                    throw interrupted
                }
                if (!cancelled && cancel.isCancelled()) {
                    cancelled = true
                }
                if (cancelled) break
            }
        } finally {
            executor.shutdownNow()
        }

        val completedAt = clockAtLeast(startedAt)
        val coverage = DefaultCoverageAggregator.aggregate(results)
        val score = scoring.score(results, environment.patch)
        emitProgress(onProgress, results, collectors.size, null, null)

        val state = when {
            cancelled -> ScanState.CANCELLED
            results.isEmpty() -> ScanState.FAILED
            results.none { it.capability == CapabilityState.SUPPORTED } -> ScanState.FAILED
            results.all { it.capability == CapabilityState.SUPPORTED && it.visibility == DataVisibility.FULL } ->
                ScanState.COMPLETED
            else -> ScanState.PARTIAL
        }
        return ScanOutcome(
            scanId = scanId,
            startedAtMillis = startedAt,
            completedAtMillis = completedAt,
            state = state,
            collectorResults = results.toList(),
            score = score,
            coverage = coverage,
        )
    }

    private fun normalize(result: CollectorResult, descriptor: CollectorDescriptor): CollectorResult {
        if (result.collectorId != descriptor.id || result.category != descriptor.category) {
            return failedResult(descriptor, result.startedAtMillis, "collector.invalidresult")
        }
        return result
    }

    private fun failedResult(
        descriptor: CollectorDescriptor,
        startedAtMillis: Long,
        errorKey: String,
    ): CollectorResult = CollectorResult.failed(
        collectorId = descriptor.id,
        category = descriptor.category,
        startedAtMillis = startedAtMillis,
        completedAtMillis = clockAtLeast(startedAtMillis),
        errorKey = MessageRef(errorKey),
    )

    private fun emitProgress(
        onProgress: (ScanProgress) -> Unit,
        results: List<CollectorResult>,
        totalCollectors: Int,
        currentCollectorId: String?,
        currentTitle: MessageRef?,
    ) {
        val progress = ScanProgress(
            completedCollectors = results.size,
            totalCollectors = totalCollectors,
            currentCollectorId = currentCollectorId,
            currentTitle = currentTitle,
            findingsSoFar = results.sumOf { it.findings.size },
        )
        try {
            onProgress(progress)
        } catch (_: RuntimeException) {
            // A broken UI observer must never abort the scan; progress is advisory only.
        }
    }

    private fun clockAtLeast(lowerBound: Long): Long = clock().coerceAtLeast(lowerBound)
}
