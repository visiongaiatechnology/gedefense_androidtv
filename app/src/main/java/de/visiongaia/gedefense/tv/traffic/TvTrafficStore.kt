package de.visiongaia.gedefense.tv.traffic

import android.content.Context
import android.content.SharedPreferences
import de.visiongaia.gedefense.tv.contract.TrafficApi
import de.visiongaia.gedefense.tv.core.geo.CountryCentroids
import de.visiongaia.gedefense.tv.core.geo.GeoLookup
import de.visiongaia.gedefense.tv.core.model.AppTraffic
import de.visiongaia.gedefense.tv.core.model.CountryTraffic
import de.visiongaia.gedefense.tv.core.model.DomainTraffic
import de.visiongaia.gedefense.tv.core.model.OriginInfo
import de.visiongaia.gedefense.tv.core.model.TrafficAction
import de.visiongaia.gedefense.tv.core.model.TrafficFlow
import de.visiongaia.gedefense.tv.core.model.TrafficSnapshot
import de.visiongaia.gedefense.tv.core.traffic.TrafficAggregator
import java.util.Locale

/**
 * XDR hand-off for locally observed traffic. The implementation is intentionally an interface: the
 * tv-core `TvXdrEngine` (task-5) will be attached here without changing the data plane. Until then the
 * store simply has no sink and the counters/flows stay in the bounded local snapshot.
 */
interface TvTrafficEventSink {
    fun onBlockedFlow(ownerPackage: String, destination: String, protocol: String, ruleHint: String?)

    fun onPrivacyDecision(ownerPackage: String, domain: String, action: TrafficAction, category: String, ruleId: String?)
}

/**
 * Bounded local traffic store for the V2 loopback VPN, implementing [TrafficApi].
 *
 * The counting/aggregation itself is delegated to the tv-core `TrafficAggregator` (frozen V2 API):
 * this class owns the Android-side plumbing — lazy snapshot caching for instant UI reads, optional
 * XDR sink hand-off, and a small last-known-good persistence so the traffic screen has data
 * immediately after a process restart (clearly marked as the last known state, never as live).
 *
 * Performance: aggregation runs on the telemetry reader thread; [snapshot] only returns the cached
 * value and never parses or aggregates on the UI thread.
 */
class TvTrafficStore(
    context: Context,
    geoLookup: GeoLookup = GeoLookup.NONE,
    clock: () -> Long = { System.currentTimeMillis() },
) : TrafficApi {
    private val appContext = context.applicationContext
    private val clock: () -> Long = clock
    private val aggregator = TrafficAggregator(geoLookup = geoLookup, clock = clock)
    private val prefs: SharedPreferences =
        appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val lock = Any()

    @Volatile
    private var cached: TrafficSnapshot = TrafficSnapshot.IDLE

    @Volatile
    private var restoredFlows: List<TrafficFlow> = emptyList()

    @Volatile
    private var live = false

    @Volatile
    private var lastRefreshMillis = 0L

    @Volatile
    private var lastPersistMillis = 0L

    @Volatile
    var eventSink: TvTrafficEventSink? = null

    private val snapshotListeners =
        java.util.concurrent.CopyOnWriteArrayList<(TrafficSnapshot, List<TrafficFlow>) -> Unit>()

    /**
     * Registers a snapshot observer (XDR, anomaly engine, ...). Observers run on the telemetry thread
     * after the cached snapshot changed and are isolated so one failing observer cannot break the data
     * plane.
     */
    fun addSnapshotListener(listener: (TrafficSnapshot, List<TrafficFlow>) -> Unit) {
        snapshotListeners.addIfAbsent(listener)
    }

    fun removeSnapshotListener(listener: (TrafficSnapshot, List<TrafficFlow>) -> Unit) {
        snapshotListeners.remove(listener)
    }

    private val revisionCounter = java.util.concurrent.atomic.AtomicLong(0L)

    /** Monotonic revision; changes whenever the cached snapshot changed. */
    override fun revision(): Long = revisionCounter.get()

    init {
        val restored = try {
            restore()
        } catch (_: Throwable) {
            null
        }
        if (restored != null) {
            cached = restored.snapshot
            restoredFlows = restored.flows
        }
    }

    // ------------------------------------------------------------------ TrafficApi

    override fun snapshot(): TrafficSnapshot = cached

    override fun flows(limit: Int): List<TrafficFlow> {
        val effective = limit.coerceIn(1, MAX_QUERY_FLOWS)
        return if (live) {
            try {
                aggregator.flows(effective)
            } catch (_: Throwable) {
                restoredFlows.take(effective)
            }
        } else {
            restoredFlows.take(effective)
        }
    }

    override fun origin(): OriginInfo {
        val country = try {
            Locale.getDefault().country.uppercase(Locale.US).takeIf { it.matches(COUNTRY_PATTERN) }
        } catch (_: Throwable) {
            null
        }
        val point = country?.let { runCatching { CountryCentroids.lookup(it) }.getOrNull() }
        // TV has no GPS; the origin is the locale/home country with an offline centroid only.
        return OriginInfo(
            countryCode = country,
            point = point,
            label = country ?: ORIGIN_UNKNOWN,
        )
    }

    override fun clearSession() {
        try {
            aggregator.clearSession()
        } catch (_: Throwable) {
            // Counter reset is best effort; the tunnel is not affected.
        }
        revisionCounter.incrementAndGet()
        refresh(force = true)
    }

    // ------------------------------------------------------ data-plane feed (service)

    /** Starts a new live session and resets the aggregator counters. */
    fun beginSession() {
        live = true
        try {
            aggregator.reset(STATE_ACTIVE)
        } catch (_: Throwable) {
            // Keep serving a bounded snapshot even if the aggregator rejects the reset.
        }
        revisionCounter.incrementAndGet()
        refresh(force = true)
    }

    /** Marks the session as stopped; the snapshot keeps its last observed values. */
    fun endSession() {
        live = false
        try {
            aggregator.stop()
        } catch (_: Throwable) {
            // Session teardown must never throw into the VpnService.
        }
        revisionCounter.incrementAndGet()
        refresh(force = true)
    }

    fun activeFlowCount(): Int = try {
        aggregator.activeFlowCount()
    } catch (_: Throwable) {
        0
    }

    fun openFlow(
        flowId: Long,
        owner: String,
        label: String,
        destinationAddress: String,
        destinationDomain: String?,
        action: TrafficAction,
        protocol: String,
        openedAtMillis: Long,
    ): Boolean {
        val accepted = try {
            aggregator.open(
                flowId = flowId,
                ownerPackage = owner,
                ownerLabel = label,
                destinationAddress = destinationAddress,
                destinationDomain = destinationDomain,
                action = action,
                protocol = protocol,
                openedAtMillis = openedAtMillis.coerceAtLeast(1L),
            )
        } catch (_: Throwable) {
            false
        }
        refresh()
        return accepted
    }

    fun updateFlow(flowId: Long, txTotal: Long, rxTotal: Long) {
        try {
            aggregator.update(flowId, txTotal, rxTotal, clock().coerceAtLeast(1L))
        } catch (_: Throwable) {
            // A late update for a closed flow is expected on session teardown.
        }
        refresh()
    }

    fun closeFlow(flowId: Long, txTotal: Long, rxTotal: Long) {
        try {
            aggregator.close(flowId, txTotal, rxTotal, clock().coerceAtLeast(1L))
        } catch (_: Throwable) {
            // A late close for an evicted flow is expected under bounded caps.
        }
        refresh()
    }

    /**
     * Records a packet the native policy dropped. There is no TUN flow state for blocked packets, so
     * this goes through the aggregator's dedicated blocked path (blocked counters + domain count).
     */
    fun recordBlocked(
        owner: String,
        label: String,
        destinationAddress: String,
        destinationDomain: String?,
        bytes: Long,
        protocol: String,
        ruleHint: String?,
    ) {
        val at = clock().coerceAtLeast(1L)
        try {
            aggregator.recordBlocked(
                ownerPackage = owner,
                ownerLabel = label,
                destinationAddress = destinationAddress,
                destinationDomain = destinationDomain,
                bytes = bytes.coerceIn(0L, MAX_BLOCKED_EVENT_BYTES),
                protocol = protocol,
                firstSeenMillis = at,
                lastSeenMillis = at,
            )
        } catch (_: Throwable) {
            // Blocked-event accounting is observability only; the packet is already dropped.
        }
        eventSink?.let { sink ->
            try {
                sink.onBlockedFlow(owner, destinationAddress, protocol, ruleHint)
            } catch (_: Throwable) {
                // The XDR sink must never be able to break the data plane.
            }
        }
        refresh()
    }

    fun dnsQuery(owner: String, label: String, domain: String) {
        try {
            aggregator.dnsQuery(owner, label, domain, clock().coerceAtLeast(1L))
        } catch (_: Throwable) {
            // Malformed/duplicate DNS observations are ignored, never propagated.
        }
        refresh()
    }

    fun privacyDecision(
        owner: String,
        label: String,
        destinationAddress: String?,
        domain: String,
        action: TrafficAction,
        category: String,
        ruleId: String?,
    ) {
        if (action == TrafficAction.BLOCK) {
            recordBlocked(
                owner = owner,
                label = label,
                destinationAddress = destinationAddress ?: "0.0.0.0",
                destinationDomain = domain,
                bytes = 0L,
                protocol = "udp",
                ruleHint = ruleId ?: category,
            )
        } else {
            dnsQuery(owner, label, domain)
        }
        eventSink?.let { sink ->
            try {
                sink.onPrivacyDecision(owner, domain, action, category, ruleId)
            } catch (_: Throwable) {
                // The XDR sink must never be able to break the data plane.
            }
        }
    }

    fun transportError() {
        try {
            aggregator.transportError()
        } catch (_: Throwable) {
            // Transport error accounting is advisory.
        }
        refresh()
    }

    fun forceRefresh() {
        refresh(force = true)
    }

    // -------------------------------------------------------------- snapshot cache

    private fun refresh(force: Boolean = false) {
        val now = clock()
        if (!force && now - lastRefreshMillis < REFRESH_THROTTLE_MILLIS) return
        lastRefreshMillis = now
        val next = try {
            aggregator.snapshot()
        } catch (_: Throwable) {
            cached
        }
        if (next != cached) {
            cached = next
            revisionCounter.incrementAndGet()
            val flows = safeFlowsForListener()
            for (listener in snapshotListeners) {
                try {
                    listener(next, flows)
                } catch (_: Throwable) {
                    // Enrichment consumers must never be able to break the data plane.
                }
            }
        }
        if (now - lastPersistMillis >= PERSIST_THROTTLE_MILLIS) {
            lastPersistMillis = now
            persist(cached)
        }
    }

    private fun safeFlowsForListener(): List<TrafficFlow> = try {
        if (live) aggregator.flows(MAX_QUERY_FLOWS) else restoredFlows
    } catch (_: Throwable) {
        emptyList()
    }

    private fun persist(snapshot: TrafficSnapshot) {
        // SECV2-08: traffic metadata (domains, destinations, per-app countries) is privacy-sensitive
        // and is intentionally no longer written to plaintext SharedPreferences. The live session
        // keeps it in memory only; after a restart the screen honestly reports no last snapshot.
        try {
            prefs.edit().remove(KEY_SNAPSHOT).apply()
        } catch (_: Throwable) {
            // Losing the persisted hint has no security impact.
        }
    }

    private fun encode(snapshot: TrafficSnapshot, flows: List<TrafficFlow>): String = buildString {
        append(VERSION).append('\n')
        append(escape(snapshot.state)).append('|')
        append(snapshot.startedAtMillis).append('|')
        append(snapshot.updatedAtMillis).append('|')
        append(snapshot.txBytes).append('|')
        append(snapshot.rxBytes).append('|')
        append(snapshot.activeFlows).append('|')
        append(snapshot.blockedFlows).append('|')
        append(snapshot.correlatedFlows).append('|')
        append(snapshot.annotatedFlows).append('|')
        append(snapshot.transportErrors).append('\n')
        for (app in snapshot.apps.take(MAX_PERSISTED_APPS)) {
            append("A|").append(escape(app.packageName)).append('|').append(escape(app.label)).append('|')
            append(app.txBytes).append('|').append(app.rxBytes).append('|').append(app.activeFlows).append('|')
            append(app.openedFlows).append('|').append(app.blockedFlows).append('|')
            append(app.correlatedFlows).append('|').append(app.annotatedFlows).append('\n')
        }
        for (country in snapshot.countries.take(MAX_PERSISTED_COUNTRIES)) {
            append("C|").append(country.countryCode).append('|').append(country.bytes).append('|')
            append(country.flows).append('|').append(country.blockedFlows).append('\n')
        }
        for (domain in snapshot.domains.take(MAX_PERSISTED_DOMAINS)) {
            append("D|").append(escape(domain.domain)).append('|').append(domain.queries).append('|')
            append(domain.blockedQueries).append('\n')
        }
        for (flow in flows.take(MAX_PERSISTED_FLOWS)) {
            append("F|").append(flow.id).append('|').append(escape(flow.ownerPackage)).append('|')
            append(escape(flow.ownerLabel)).append('|').append(escape(flow.destinationAddress)).append('|')
            append(flow.countryCode ?: "").append('|').append(escape(flow.destinationDomain ?: "")).append('|')
            append(flow.action.name).append('|').append(escape(flow.protocol)).append('|')
            append(flow.txBytes).append('|').append(flow.rxBytes).append('|')
            append(flow.openedAtMillis).append('|').append(flow.lastSeenMillis).append('\n')
        }
    }

    private data class Restored(val snapshot: TrafficSnapshot, val flows: List<TrafficFlow>)

    private fun restore(): Restored? {
        // SECV2-08: plaintext traffic metadata is never restored or kept across restarts.
        try {
            prefs.edit().remove(KEY_SNAPSHOT).apply()
        } catch (_: Throwable) {
            // Ignore preference failures; the traffic screen will simply start empty.
        }
        return null
    }

    private fun escape(value: String): String = value
        .replace("%", "%25")
        .replace("|", "%7C")
        .replace("\n", " ")
        .replace("\r", " ")
        .take(MAX_FIELD_CHARS)

    private fun unescape(value: String): String = value
        .replace("%7C", "|")
        .replace("%25", "%")

    companion object {
        private const val PREFS_NAME = "gedefense_tv_traffic"
        private const val KEY_SNAPSHOT = "last_snapshot.v1"
        private const val VERSION = "v1"
        private const val STATE_ACTIVE = "ACTIVE"
        private const val STATE_LAST_KNOWN = "LAST"
        private const val STATE_IDLE = "IDLE"
        private const val ORIGIN_UNKNOWN = "unknown"
        private val COUNTRY_PATTERN = Regex("[A-Z]{2}")
        private const val REFRESH_THROTTLE_MILLIS = 500L
        private const val PERSIST_THROTTLE_MILLIS = 2_000L
        private const val MAX_PERSISTED_APPS = 50
        private const val MAX_PERSISTED_COUNTRIES = 32
        private const val MAX_PERSISTED_DOMAINS = 50
        private const val MAX_PERSISTED_FLOWS = 100
        private const val MAX_QUERY_FLOWS = 500
        private const val MAX_PERSISTED_CHARS = 128 * 1024
        private const val MAX_FIELD_CHARS = 256
        private const val MAX_BLOCKED_EVENT_BYTES = 65_535L
    }
}
