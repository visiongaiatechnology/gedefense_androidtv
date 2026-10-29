package de.visiongaia.gedefense.tv.data

import de.visiongaia.gedefense.tv.contract.XdrApi
import de.visiongaia.gedefense.tv.core.model.TrafficAction
import de.visiongaia.gedefense.tv.core.model.TrafficFlow
import de.visiongaia.gedefense.tv.core.xdr.TvXdrEngine
import de.visiongaia.gedefense.tv.core.xdr.XdrConfig
import de.visiongaia.gedefense.tv.core.xdr.XdrIncident
import de.visiongaia.gedefense.tv.traffic.TvTrafficEventSink
import de.visiongaia.gedefense.tv.traffic.TvTrafficStore
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * TV XDR-light store: adapts real local traffic snapshots into the tv-core [TvXdrEngine].
 *
 * Wiring: the store is registered as the traffic event sink and as the traffic snapshot listener. A
 * bounded single-thread evaluator runs at most once per [EVAL_THROTTLE_MILLIS] over the current
 * snapshot/flow history and caches at most [MAX_INCIDENTS] explainable incidents. No incident is
 * invented: an empty list simply means the engine found no correlated pattern in observed data.
 *
 * The engine is recreated when a new validated threat index arrives (policy context change); that
 * deliberately resets its dedupe/known-app state so new correlation is evaluated from scratch.
 */
class TvXdrStore(
    initialThreatIndex: de.visiongaia.gedefense.mobile.core.ThreatIndex =
        de.visiongaia.gedefense.mobile.core.ThreatIndex.empty(),
) : XdrApi, TvTrafficEventSink {
    private val lock = Any()
    private var engine = TvXdrEngine(threatIndex = initialThreatIndex)
    private var cachedIncidents: List<XdrIncident> = emptyList()
    private val revisionCounter = AtomicLong(0L)
    private val evaluating = AtomicBoolean(false)
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "gedefense-tv-xdr").apply {
            isDaemon = true
            priority = Thread.MIN_PRIORITY
        }
    }

    @Volatile
    private var traffic: TvTrafficStore? = null

    @Volatile
    private var lastEvaluationMillis = 0L

    @Volatile
    private var lastSessionStart = 0L

    /** Attaches the evaluator to the live traffic store (idempotent). */
    fun attach(trafficStore: TvTrafficStore) {
        traffic = trafficStore
        trafficStore.eventSink = this
        trafficStore.addSnapshotListener { _, _ -> requestEvaluation() }
    }

    /** Replaces the policy context after a successful threat-intel sync. */
    fun setThreatIndex(index: de.visiongaia.gedefense.mobile.core.ThreatIndex) {
        synchronized(lock) {
            engine = TvXdrEngine(
                threatIndex = index,
                config = XdrConfig(maxIncidents = MAX_INCIDENTS),
            )
            cachedIncidents = emptyList()
        }
        revisionCounter.incrementAndGet()
        requestEvaluation()
    }

    override fun incidents(): List<XdrIncident> = cachedIncidents

    override fun revision(): Long = revisionCounter.get()

    override fun clear() {
        synchronized(lock) {
            engine.reset()
            cachedIncidents = emptyList()
        }
        revisionCounter.incrementAndGet()
    }

    // ------------------------------------------------------ TvTrafficEventSink

    override fun onBlockedFlow(ownerPackage: String, destination: String, protocol: String, ruleHint: String?) {
        // The blocked flow is already part of the next traffic snapshot; just schedule the evaluation.
        requestEvaluation()
    }

    override fun onPrivacyDecision(
        ownerPackage: String,
        domain: String,
        action: TrafficAction,
        category: String,
        ruleId: String?,
    ) {
        requestEvaluation()
    }

    // ------------------------------------------------------------------ evaluation

    /** Coalesced, throttled evaluation on the dedicated low-priority executor. */
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
                    // A new traffic session (VPN start) must also start a fresh XDR dedupe window:
                    // otherwise the first incidents of the session would be suppressed by the
                    // previous session's dedupe bucket and the UI would show an empty list.
                    if (snapshot.startedAtMillis != lastSessionStart) {
                        lastSessionStart = snapshot.startedAtMillis
                        synchronized(lock) { engine.reset() }
                    }
                    val flows = store.flows(FLOW_LIMIT)
                    val incidents = synchronized(lock) {
                        engine.evaluate(snapshot, flows, System.currentTimeMillis()).take(MAX_INCIDENTS)
                    }
                    synchronized(lock) {
                        if (incidents.isNotEmpty()) {
                            // Dedupe means a later evaluation may return an empty delta; never let that
                            // erase already shown incidents. Merge newest-first and cap the list.
                            val merged = (incidents + cachedIncidents)
                                .distinctBy { it.id }
                                .sortedWith(
                                    compareByDescending<de.visiongaia.gedefense.tv.core.xdr.XdrIncident> { it.lastSeenMillis }
                                        .thenByDescending { it.score },
                                )
                                .take(MAX_INCIDENTS)
                            if (merged != cachedIncidents) {
                                cachedIncidents = merged
                                revisionCounter.incrementAndGet()
                            }
                        }
                    }
                } catch (_: Throwable) {
                    // XDR enrichment is secondary telemetry: never disturb the data plane.
                } finally {
                    evaluating.set(false)
                }
            }
        } catch (_: RuntimeException) {
            evaluating.set(false)
        }
    }

    companion object {
        const val MAX_INCIDENTS = 32
        private const val FLOW_LIMIT = 500
        private const val EVAL_THROTTLE_MILLIS = 2_000L
    }
}
