package de.visiongaia.gedefense.tv.data

import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.tv.contract.ContainmentApi
import de.visiongaia.gedefense.tv.contract.ContainmentListener
import de.visiongaia.gedefense.tv.contract.VpnControlApi
import de.visiongaia.gedefense.tv.core.anomaly.ContainmentRegistry
import de.visiongaia.gedefense.tv.core.anomaly.OutboundContainmentPolicy
import de.visiongaia.gedefense.tv.core.anomaly.composeThreatIndex
import de.visiongaia.gedefense.tv.core.model.ContainmentPolicy
import de.visiongaia.gedefense.tv.core.model.ContainmentRecord
import de.visiongaia.gedefense.tv.core.model.ContainmentState
import de.visiongaia.gedefense.tv.core.model.OutboundAnomaly
import de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile
import de.visiongaia.gedefense.tv.ui.ContainmentNotifier
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * V2.1 "Outbound Kinetic-Lite" containment adapter.
 *
 * Consumes the deterministic anomaly feed (OBSERVE-only) from [TvAnomalyStore] and applies temporary
 * destination containments only when the user explicitly opted in *and* the strict profile is active.
 * Every record has a TTL, is reversible, and is enforced by refreshing the VPN policy with a composed
 * ThreatIndex. No app package, system service, launcher/Play traffic or allowlisted CDN prefix is
 * ever targeted.
 */
class TvContainmentStore(
    private val settings: TvSettingsStore,
    private val vpn: VpnControlApi,
    private val anomaliesProvider: () -> List<OutboundAnomaly>,
    private val baseIndexProvider: () -> ThreatIndex,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val evidenceSink: ((String, String, String, String) -> Boolean)? = null,
) : ContainmentApi {

    private val lock = Any()
    private val executor = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "gedefense-tv-kinetic").apply {
            isDaemon = true
            priority = Thread.MIN_PRIORITY
        }
    }
    private val listeners = CopyOnWriteArrayList<ContainmentListener>()
    private val revisionCounter = AtomicLong(0L)

    private var registry = ContainmentRegistry(policyFor(settings), clock)
    private var policyEnabled: Boolean = registry.policy().enabled
    private var lastTickMillis = 0L

    /**
     * Last validated base threat index handed over by the bootstrap / TI sync.
     *
     * The provider is only an initial fallback: calling `policyIndexSnapshot()` (full feed hash/parse)
     * on every containment change would cost seconds of CPU on the TV. The base policy is immutable
     * between syncs and must stay bit-identical inside [composeThreatIndex].
     */
    @Volatile
    private var cachedBaseIndex: ThreatIndex = ThreatIndex.empty()

    @Volatile
    private var baseIndexResolved = false

    /** Starts the bounded 5 s evaluator; safe to call once from the bootstrap background thread. */
    fun start() {
        executor.scheduleWithFixedDelay({ tick() }, 4_000L, 5_000L, TimeUnit.MILLISECONDS)
    }

    /**
     * Updates the validated base policy context (initial startup and after every successful TI sync)
     * and immediately re-publishes the composed policy (base + ACTIVE containment overlay).
     *
     * Must be called from a background thread (bootstrap / TI sync); it composes synchronously so an
     * active containment overlay can never be dropped by a base-index refresh.
     */
    fun updateBaseThreatIndex(index: ThreatIndex) {
        cachedBaseIndex = index
        baseIndexResolved = true
        synchronized(lock) {
            applyEnforcementLocked()
        }
    }

    // ------------------------------------------------------------- ContainmentApi

    override fun active(): List<ContainmentRecord> = synchronized(lock) {
        registry.active(clock())
    }

    override fun history(limit: Int): List<ContainmentRecord> = synchronized(lock) {
        registry.all(limit)
    }

    override fun release(id: String): Boolean {
        val released: ContainmentRecord? = synchronized(lock) {
            val record = registry.all(64).firstOrNull { it.id == id }
            if (record == null) {
                null
            } else if (registry.release(id, clock())) {
                applyEnforcementLocked()
                record
            } else {
                null
            }
        }
        val record = released ?: return false
        revisionCounter.incrementAndGet()
        publish(record.copy(state = ContainmentState.RELEASED, releasedAtMillis = clock()))
        return true
    }

    override fun revision(): Long = revisionCounter.get()

    override fun addListener(listener: ContainmentListener) {
        listeners.addIfAbsent(listener)
    }

    override fun removeListener(listener: ContainmentListener) {
        listeners.remove(listener)
    }

    override fun setEnabled(enabled: Boolean) {
        settings.setContainmentEnabled(enabled)
        synchronized(lock) {
            val desired = policyFor(settings)
            if (!desired.enabled) {
                releaseAllLocked()
                applyEnforcementLocked()
            }
            registry = ContainmentRegistry(desired, clock)
            policyEnabled = desired.enabled
        }
        revisionCounter.incrementAndGet()
    }

    override fun enabled(): Boolean = settings.containmentEnabled() &&
        settings.privacyProfile() == TvPrivacyProfile.STRICT

    // ----------------------------------------------------------------- evaluation

    /**
     * QA-only instrumentation hook (debug builds only): applies a harmless TEST-NET containment so
     * the reversible popup/enforcement path can be verified on the emulator without fabricating user
     * traffic. Release builds never call this.
     */
    fun applyDebugTestContainment(): ContainmentRecord? {
        val now = clock()
        val target = de.visiongaia.gedefense.tv.core.model.ContainmentTarget(
            de.visiongaia.gedefense.tv.core.model.ContainmentTargetType.DESTINATION_PREFIX,
            "45.33.32.0/24",
        )
        val signals = listOf(
            de.visiongaia.gedefense.tv.core.model.AnomalySignal(
                de.visiongaia.gedefense.tv.core.model.AnomalyKind.C2_MATCH,
                45,
                "debug_test_signal",
                2,
            ),
            de.visiongaia.gedefense.tv.core.model.AnomalySignal(
                de.visiongaia.gedefense.tv.core.model.AnomalyKind.REPEATED_BLOCK,
                25,
                "debug_test_signal",
                2,
            ),
        )
        val proposal = de.visiongaia.gedefense.tv.core.model.ContainmentProposal(
            id = "debug-${now}",
            target = target,
            reasonCode = "debug_test",
            anomalyKind = de.visiongaia.gedefense.tv.core.model.AnomalyKind.C2_MATCH,
            anomalyScore = 70,
            confidence = de.visiongaia.gedefense.tv.core.model.Confidence.HIGH,
            packageName = "com.example.streamtest",
            appLabel = "Streaming Test",
            countryCode = "US",
            signals = signals,
            proposedTtlMillis = 5L * 60L * 1_000L,
        )
        // QA simulates the explicit strict-profile opt-in (production default is OBSERVE-only).
        settings.setContainmentEnabled(true)
        settings.setPrivacyProfile(de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile.STRICT)
        registry = de.visiongaia.gedefense.tv.core.anomaly.ContainmentRegistry(policyFor(settings), clock)
        policyEnabled = true
        val record = synchronized(lock) {
            registry.apply(proposal)?.also { applyEnforcementLocked() }
        } ?: return null
        revisionCounter.incrementAndGet()
        publish(record)
        return record
    }

    private fun tick() {
        try {
            val now = clock()
            if (now - lastTickMillis < 3_000L) return
            lastTickMillis = now
            refreshPolicyIfNeeded()
            synchronized(lock) {
                val expired = registry.expire(now)
                if (expired.isNotEmpty()) {
                    applyEnforcementLocked()
                    for (record in expired) publish(record)
                    revisionCounter.incrementAndGet()
                }
                if (!registry.policy().enabled) return
                val anomalies = anomaliesProvider()
                if (anomalies.isEmpty()) return
                var changed = false
                val proposals = OutboundContainmentPolicy.propose(anomalies, registry.policy()) { false }
                for (proposal in proposals) {
                    val record = registry.apply(proposal) ?: continue
                    changed = true
                    publish(record)
                }
                if (changed) {
                    applyEnforcementLocked()
                    revisionCounter.incrementAndGet()
                }
            }
        } catch (_: Throwable) {
            // Kinetic enrichment must never disturb the VPN data path.
        }
    }

    private fun refreshPolicyIfNeeded() {
        val desired = policyFor(settings)
        synchronized(lock) {
            if (desired.enabled == policyEnabled) return
            if (!desired.enabled) {
                releaseAllLocked()
                applyEnforcementLocked()
            }
            registry = ContainmentRegistry(desired, clock)
            policyEnabled = desired.enabled
            revisionCounter.incrementAndGet()
        }
    }

    private fun releaseAllLocked() {
        val active = registry.active(clock())
        for (record in active) {
            if (registry.release(record.id, clock())) {
                publish(record.copy(state = ContainmentState.RELEASED, releasedAtMillis = clock()))
            }
        }
    }

    /** Refreshes the VPN threat policy with the current, immutable containment overlay. */
    private fun applyEnforcementLocked(): Boolean {
        val composed = composeThreatIndex(currentBaseIndex(), registry.active(clock()))
        return try {
            vpn.setThreatIndex(composed)
        } catch (_: Throwable) {
            false
        }

    }

    /** Cached base index, resolved exactly once through the provider as initial fallback. */
    private fun currentBaseIndex(): ThreatIndex {
        if (baseIndexResolved) return cachedBaseIndex
        val resolved = try {
            baseIndexProvider()
        } catch (_: Throwable) {
            ThreatIndex.empty()
        }
        cachedBaseIndex = resolved
        baseIndexResolved = true
        return resolved
    }

    private fun publish(record: ContainmentRecord) {
        val eventType = when (record.state) {
            ContainmentState.ACTIVE -> "containment.applied"
            ContainmentState.RELEASED -> "containment.released"
            ContainmentState.EXPIRED -> "containment.expired"
        }
        try {
            evidenceSink?.invoke(
                eventType,
                if (record.state == ContainmentState.ACTIVE) "warning" else "info",
                record.target.value,
                "reason=${record.reasonCode.take(48)} score=${record.anomalyScore} ttl=${record.expiresAtMillis - record.createdAtMillis}ms",
            )
        } catch (_: Throwable) {
            // Evidence enrichment must never block the containment path.
        }
        ContainmentNotifier.publish(record)
        for (listener in listeners) {
            try {
                listener.onContainmentChanged(record)
            } catch (_: Throwable) {
                // A UI listener must never disturb the data path.
            }
        }
    }

    private fun policyFor(settings: TvSettingsStore): ContainmentPolicy {
        val strict = settings.privacyProfile() == TvPrivacyProfile.STRICT
        return ContainmentPolicy(enabled = settings.containmentEnabled() && strict)
    }
}
