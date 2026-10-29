package de.visiongaia.gedefense.tv.data

import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.tv.contract.AnomalyApi
import de.visiongaia.gedefense.tv.core.anomaly.AnomalyConfig
import de.visiongaia.gedefense.tv.core.anomaly.OutboundAnomalyEngine
import de.visiongaia.gedefense.tv.core.model.OutboundAnomaly
import de.visiongaia.gedefense.tv.traffic.TvTrafficStore
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * TV V2.1 outbound anomaly adapter (AnomalyApi).
 *
 * Runs the tv-core `OutboundAnomalyEngine` over the bounded traffic snapshot/flow history on a
 * dedicated low-priority thread, at most once per [EVAL_THROTTLE_MILLIS]. The engine is observe-only
 * and bounded; this store never invents anomalies and simply exposes the deterministic engine output
 * plus a monotonic revision for cheap UI polling.
 *
 * The engine is recreated when a new validated threat index arrives (policy context change); that
 * deliberately resets its window/dedupe state so new correlation is evaluated from scratch.
 */
class TvAnomalyStore(
    initialThreatIndex: ThreatIndex = ThreatIndex.empty(),
) : AnomalyApi {
    private val lock = Any()
    private var engine = OutboundAnomalyEngine(threatIndex = initialThreatIndex)
    private var cachedAnomalies: List<OutboundAnomaly> = emptyList()
    private val revisionCounter = AtomicLong(0L)
    private val evaluating = AtomicBoolean(false)
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "gedefense-tv-anomaly").apply {
            isDaemon = true
            priority = Thread.MIN_PRIORITY
        }
    }

    @Volatile
    private var traffic: TvTrafficStore? = null

    @Volatile
    private var lastEvaluationMillis = 0L

    /** Called on the anomaly executor whenever a new anomaly set was computed (used by containment). */
    @Volatile
    var anomalyListener: ((List<OutboundAnomaly>) -> Unit)? = null

    fun attach(trafficStore: TvTrafficStore) {
        traffic = trafficStore
        trafficStore.addSnapshotListener { _, _ -> requestEvaluation() }
    }

    /** Replaces the policy context after a successful threat-intel sync. */
    fun setThreatIndex(index: ThreatIndex) {
        synchronized(lock) {
            engine = OutboundAnomalyEngine(threatIndex = index, config = AnomalyConfig())
            cachedAnomalies = emptyList()
        }
        revisionCounter.incrementAndGet()
        requestEvaluation()
    }

    override fun anomalies(): List<OutboundAnomaly> = cachedAnomalies

    override fun revision(): Long = revisionCounter.get()

    private fun requestEvaluation() {
        val now = System.currentTimeMillis()
        if (now - lastEvaluationMillis < EVAL_THROTTLE_MILLIS) return
        if (!evaluating.compareAndSet(false, true)) return
        lastEvaluationMillis = now
        try {
            executor.execute {
                try {
                    val store = traffic
                    if (store == null) return@execute
                    val snapshot = store.snapshot()
                    val flows = store.flows(FLOW_LIMIT)
                    val result = synchronized(lock) {
                        engine.evaluate(snapshot, flows, System.currentTimeMillis()).take(MAX_ANOMALIES)
                    }
                    val changed = synchronized(lock) {
                        val differs = result != cachedAnomalies
                        if (differs) cachedAnomalies = result
                        differs
                    }
                    if (changed) {
                        revisionCounter.incrementAndGet()
                        anomalyListener?.let { listener ->
                            try {
                                listener(result)
                            } catch (_: Throwable) {
                                // Containment must never be able to break anomaly evaluation.
                            }
                        }
                    }
                } catch (_: Throwable) {
                    // Anomaly enrichment is secondary telemetry: the data plane stays unaffected.
                } finally {
                    evaluating.set(false)
                }
            }
        } catch (_: RuntimeException) {
            evaluating.set(false)
        }
    }

    companion object {
        private const val MAX_ANOMALIES = 32
        private const val FLOW_LIMIT = 500
        private const val EVAL_THROTTLE_MILLIS = 2_000L
    }
}
