package de.visiongaia.gedefense.tv.core.traffic

import de.visiongaia.gedefense.mobile.core.canonicalPrivacyDomain
import de.visiongaia.gedefense.tv.core.geo.GeoLookup
import de.visiongaia.gedefense.tv.core.model.AppTraffic
import de.visiongaia.gedefense.tv.core.model.CountryTraffic
import de.visiongaia.gedefense.tv.core.model.DomainTraffic
import de.visiongaia.gedefense.tv.core.model.TrafficAction
import de.visiongaia.gedefense.tv.core.model.TrafficFlow
import de.visiongaia.gedefense.tv.core.model.TrafficSnapshot
import java.util.Locale

/**
 * Hard memory/aggregation bounds for [TrafficAggregator].
 *
 * The values mirror the model bounds ([TrafficSnapshot] allows at most 200 apps, 64 countries and
 * 200 domains) and keep the ring buffer small enough for a TV process.
 */
data class TrafficCaps(
    val maxActiveFlows: Int = 2_000,
    val maxHistoryFlows: Int = 500,
    val maxApps: Int = 200,
    val maxCountries: Int = 64,
    val maxDomains: Int = 200,
    val maxPerAppCountries: Int = 32,
    val maxPerAppDomains: Int = 64,
    val topCountriesPerApp: Int = 12,
    val topDomainsPerApp: Int = 12,
    val maxLabelLength: Int = 120,
    val maxEventBytes: Long = 1L shl 40,
) {
    init {
        require(maxActiveFlows in 1..10_000) { "invalid active flow bound" }
        require(maxHistoryFlows in 1..5_000) { "invalid history bound" }
        require(maxApps in 1..200) { "invalid app bound" }
        require(maxCountries in 1..64) { "invalid country bound" }
        require(maxDomains in 1..200) { "invalid domain bound" }
        require(maxPerAppCountries in 1..64) { "invalid per-app country bound" }
        require(maxPerAppDomains in 1..200) { "invalid per-app domain bound" }
        require(topCountriesPerApp in 1..12) { "invalid per-app country top bound" }
        require(topDomainsPerApp in 1..12) { "invalid per-app domain top bound" }
        require(maxLabelLength in 1..120) { "invalid label bound" }
        require(maxEventBytes in 1L..(1L shl 44)) { "invalid event byte bound" }
    }

    companion object {
        val DEFAULT = TrafficCaps()
    }
}

/**
 * Thread-safe, bounded aggregation of the loopback VPN telemetry.
 *
 * The aggregator is the single source of truth for [TrafficSnapshot] and the flow history ring
 * buffer. It is deliberately fail-honest:
 *  - unknown geo stays unknown (`TrafficFlow.countryCode == null`) and is aggregated under `ZZ`;
 *  - events beyond a cap are rejected (`false`) or trimmed deterministically instead of growing
 *    without bound;
 *  - byte counters saturate instead of overflowing;
 *  - every mutation is serialised on one internal lock, so reader snapshots are consistent.
 */
class TrafficAggregator(
    private val geoLookup: GeoLookup = GeoLookup.NONE,
    private val caps: TrafficCaps = TrafficCaps.DEFAULT,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {

    private data class MutableCountry(var bytes: Long = 0L, var flows: Int = 0, var blockedFlows: Int = 0)

    private data class MutableDomain(var queries: Long = 0L, var blockedQueries: Long = 0L)

    private data class MutableApp(
        val packageName: String,
        var label: String,
        var txBytes: Long = 0L,
        var rxBytes: Long = 0L,
        var activeFlows: Int = 0,
        var openedFlows: Long = 0L,
        var blockedFlows: Long = 0L,
        var correlatedFlows: Long = 0L,
        var annotatedFlows: Long = 0L,
        val countries: LinkedHashMap<String, MutableCountry> = LinkedHashMap(),
        val domains: LinkedHashMap<String, MutableDomain> = LinkedHashMap(),
    )

    private data class MutableFlow(
        val id: Long,
        val ownerPackage: String,
        val ownerLabel: String,
        val destinationAddress: String,
        val destinationDomain: String?,
        val countryCode: String?,
        val action: TrafficAction,
        val protocol: String,
        var txBytes: Long,
        var rxBytes: Long,
        val openedAtMillis: Long,
        var lastSeenMillis: Long,
    )

    private val lock = Any()
    private val activeFlows = LinkedHashMap<Long, MutableFlow>()
    private val history = ArrayDeque<TrafficFlow>()
    private val apps = LinkedHashMap<String, MutableApp>()
    private val countries = LinkedHashMap<String, MutableCountry>()
    private val domains = LinkedHashMap<String, MutableDomain>()

    private var startedAtMillis = 0L
    private var updatedAtMillis = 0L
    private var txBytes = 0L
    private var rxBytes = 0L
    private var blockedFlows = 0L
    private var correlatedFlows = 0L
    private var annotatedFlows = 0L
    private var transportErrors = 0L
    private var state = "IDLE"
    private var syntheticFlowId = 1L shl 62

    /** Read-only view of the configured bounds. */
    val limits: TrafficCaps get() = caps

    fun reset(state: String = "ACTIVE") {
        synchronized(lock) {
            val safeState = state.trim().takeIf { it.isNotEmpty() && it.length <= 24 } ?: "IDLE"
            activeFlows.clear()
            history.clear()
            apps.clear()
            countries.clear()
            domains.clear()
            val now = clock().coerceAtLeast(1L)
            startedAtMillis = now
            updatedAtMillis = now
            txBytes = 0L
            rxBytes = 0L
            blockedFlows = 0L
            correlatedFlows = 0L
            annotatedFlows = 0L
            transportErrors = 0L
            this.state = safeState
        }
    }

    /** Clears counters and history but keeps the current tunnel state label. */
    fun clearSession() {
        synchronized(lock) {
            reset(state = if (state == "IDLE" || state == "STOPPED") state else "ACTIVE")
        }
    }

    fun stop() {
        synchronized(lock) {
            activeFlows.clear()
            apps.values.forEach { it.activeFlows = 0 }
            updatedAtMillis = clock().coerceAtLeast(updatedAtMillis)
            state = "STOPPED"
        }
    }

    fun open(
        flowId: Long,
        ownerPackage: String,
        ownerLabel: String,
        destinationAddress: String,
        destinationDomain: String? = null,
        action: TrafficAction = TrafficAction.ALLOW,
        protocol: String = "tcp",
        openedAtMillis: Long = clock(),
    ): Boolean = synchronized(lock) {
        if (flowId < 0L) return@synchronized false
        if (activeFlows.size >= caps.maxActiveFlows) return@synchronized false
        if (activeFlows.containsKey(flowId)) return@synchronized false
        val pkg = normalizePackage(ownerPackage) ?: return@synchronized false
        val label = normalizeLabel(ownerLabel, pkg)
        val address = normalizeAddress(destinationAddress) ?: return@synchronized false
        val proto = normalizeProtocol(protocol) ?: return@synchronized false
        val domain = normalizeDomain(destinationDomain)
        val app = ensureApp(pkg, label) ?: return@synchronized false
        val country = normalizeCountry(geoLookup.countryCode(address))
        val openedAt = normalizeTimestamp(openedAtMillis)
        val flow = MutableFlow(
            id = flowId,
            ownerPackage = pkg,
            ownerLabel = label,
            destinationAddress = address,
            destinationDomain = domain,
            countryCode = country,
            action = action,
            protocol = proto,
            txBytes = 0L,
            rxBytes = 0L,
            openedAtMillis = openedAt,
            lastSeenMillis = openedAt,
        )
        activeFlows[flowId] = flow
        app.activeFlows += 1
        app.openedFlows = saturatingAdd(app.openedFlows, 1L)
        when (action) {
            TrafficAction.BLOCK -> {
                app.blockedFlows = saturatingAdd(app.blockedFlows, 1L)
                blockedFlows = saturatingAdd(blockedFlows, 1L)
            }
            TrafficAction.CORRELATE -> {
                app.correlatedFlows = saturatingAdd(app.correlatedFlows, 1L)
                correlatedFlows = saturatingAdd(correlatedFlows, 1L)
            }
            TrafficAction.ANNOTATE -> {
                app.annotatedFlows = saturatingAdd(app.annotatedFlows, 1L)
                annotatedFlows = saturatingAdd(annotatedFlows, 1L)
            }
            TrafficAction.ALLOW -> Unit
        }
        countryBucket(country)?.let { it.flows += 1 }
        appCountry(app, country)?.let { it.flows += 1 }
        beginIfIdle(openedAt)
        touch(openedAt)
        true
    }

    fun update(
        flowId: Long,
        txTotal: Long,
        rxTotal: Long,
        lastSeenMillis: Long = clock(),
    ): Boolean = synchronized(lock) {
        val flow = activeFlows[flowId] ?: return@synchronized false
        val app = apps[flow.ownerPackage] ?: return@synchronized false
        val tx = txTotal.coerceAtLeast(0L)
        val rx = rxTotal.coerceAtLeast(0L)
        val deltaTx = (tx - flow.txBytes).coerceAtLeast(0L)
        val deltaRx = (rx - flow.rxBytes).coerceAtLeast(0L)
        flow.txBytes = maxOf(flow.txBytes, tx)
        flow.rxBytes = maxOf(flow.rxBytes, rx)
        val seen = normalizeTimestamp(lastSeenMillis).coerceAtLeast(flow.openedAtMillis)
        flow.lastSeenMillis = maxOf(flow.lastSeenMillis, seen)
        addTraffic(app, flow.countryCode, deltaTx, deltaRx)
        touch(flow.lastSeenMillis)
        true
    }

    fun close(
        flowId: Long,
        txTotal: Long,
        rxTotal: Long,
        lastSeenMillis: Long = clock(),
    ): Boolean = synchronized(lock) {
        val flow = activeFlows[flowId] ?: return@synchronized false
        val app = apps[flow.ownerPackage] ?: return@synchronized false
        val tx = maxOf(flow.txBytes, txTotal.coerceAtLeast(0L))
        val rx = maxOf(flow.rxBytes, rxTotal.coerceAtLeast(0L))
        addTraffic(app, flow.countryCode, tx - flow.txBytes, rx - flow.rxBytes)
        flow.txBytes = tx
        flow.rxBytes = rx
        val seen = normalizeTimestamp(lastSeenMillis).coerceAtLeast(flow.openedAtMillis)
        flow.lastSeenMillis = maxOf(flow.lastSeenMillis, seen)
        app.activeFlows = (app.activeFlows - 1).coerceAtLeast(0)
        activeFlows.remove(flowId)
        appendHistory(flow)
        touch(flow.lastSeenMillis)
        true
    }

    /**
     * Accounts a blocked destination that never produced an active flow (the data plane dropped it
     * before TUN flow accounting). Also increments the observed query counters for the domain.
     */
    fun recordBlocked(
        ownerPackage: String,
        ownerLabel: String,
        destinationAddress: String,
        destinationDomain: String?,
        bytes: Long,
        protocol: String = "udp",
        firstSeenMillis: Long = clock(),
        lastSeenMillis: Long = clock(),
    ): Boolean = synchronized(lock) {
        val pkg = normalizePackage(ownerPackage) ?: return@synchronized false
        val label = normalizeLabel(ownerLabel, pkg)
        val address = normalizeAddress(destinationAddress) ?: return@synchronized false
        val proto = normalizeProtocol(protocol) ?: return@synchronized false
        val domain = normalizeDomain(destinationDomain)
        val observedAt = normalizeTimestamp(firstSeenMillis)
        val seen = normalizeTimestamp(lastSeenMillis).coerceAtLeast(observedAt)
        val app = ensureApp(pkg, label) ?: return@synchronized false
        val safeBytes = bytes.coerceIn(0L, caps.maxEventBytes)
        app.blockedFlows = saturatingAdd(app.blockedFlows, 1L)
        blockedFlows = saturatingAdd(blockedFlows, 1L)
        val country = normalizeCountry(geoLookup.countryCode(address))
        addTraffic(app, country, safeBytes, 0L)
        countryBucket(country)?.let { bucket ->
            bucket.flows += 1
            bucket.blockedFlows += 1
        }
        appCountry(app, country)?.let { bucket ->
            bucket.flows += 1
            bucket.blockedFlows += 1
        }
        if (domain != null) {
            val domainCounter = domainBucket(domain)
            domainCounter.blockedQueries = saturatingAdd(domainCounter.blockedQueries, 1L)
            domainCounter.queries = saturatingAdd(domainCounter.queries, 1L)
            val appDomainCounter = appDomain(app, domain)
            appDomainCounter.blockedQueries = saturatingAdd(appDomainCounter.blockedQueries, 1L)
            appDomainCounter.queries = saturatingAdd(appDomainCounter.queries, 1L)
        }
        val historyId = syntheticFlowId
        syntheticFlowId = if (syntheticFlowId == Long.MAX_VALUE) 1L shl 62 else syntheticFlowId + 1L
        val flow = MutableFlow(
            id = historyId,
            ownerPackage = pkg,
            ownerLabel = label,
            destinationAddress = address,
            destinationDomain = domain,
            countryCode = country,
            action = TrafficAction.BLOCK,
            protocol = proto,
            txBytes = safeBytes,
            rxBytes = 0L,
            openedAtMillis = observedAt,
            lastSeenMillis = seen,
        )
        appendHistory(flow)
        beginIfIdle(observedAt)
        touch(seen)
        true
    }

    /** Records one observed DNS query (counts only; no domain content leaves the process). */
    fun dnsQuery(
        ownerPackage: String,
        ownerLabel: String,
        domain: String,
        observedAtMillis: Long = clock(),
    ): Boolean = synchronized(lock) {
        val pkg = normalizePackage(ownerPackage) ?: return@synchronized false
        val label = normalizeLabel(ownerLabel, pkg)
        val normalizedDomain = normalizeDomain(domain) ?: return@synchronized false
        val app = ensureApp(pkg, label) ?: return@synchronized false
        val bucket = domainBucket(normalizedDomain)
        bucket.queries = saturatingAdd(bucket.queries, 1L)
        val appDomain = appDomain(app, normalizedDomain)
        appDomain.queries = saturatingAdd(appDomain.queries, 1L)
        beginIfIdle(normalizeTimestamp(observedAtMillis))
        touch(normalizeTimestamp(observedAtMillis))
        true
    }

    fun transportError() {
        synchronized(lock) {
            transportErrors = saturatingAdd(transportErrors, 1L)
            updatedAtMillis = clock().coerceAtLeast(updatedAtMillis)
        }
    }

    fun activeFlowCount(): Int = synchronized(lock) { activeFlows.size }

    /** Bounded flow history, newest first. */
    fun flows(limit: Int = 200): List<TrafficFlow> = synchronized(lock) {
        val safeLimit = limit.coerceIn(0, caps.maxHistoryFlows)
        if (safeLimit == 0) emptyList() else history.take(safeLimit)
    }

    fun snapshot(): TrafficSnapshot = synchronized(lock) {
        val appRows = apps.values
            .map { app ->
                AppTraffic(
                    packageName = app.packageName,
                    label = app.label,
                    txBytes = app.txBytes,
                    rxBytes = app.rxBytes,
                    activeFlows = app.activeFlows,
                    openedFlows = app.openedFlows,
                    blockedFlows = app.blockedFlows,
                    correlatedFlows = app.correlatedFlows,
                    annotatedFlows = app.annotatedFlows,
                    topCountries = appTopCountries(app),
                    topDomains = appTopDomains(app),
                )
            }
            .sortedWith(compareByDescending<AppTraffic> { it.totalBytes }.thenBy { it.packageName })
            .take(caps.maxApps)
        val countryRows = countries.entries
            .map { (code, value) ->
                CountryTraffic(
                    countryCode = code,
                    bytes = value.bytes,
                    flows = value.flows,
                    blockedFlows = value.blockedFlows.coerceAtMost(value.flows),
                )
            }
            .sortedWith(compareByDescending<CountryTraffic> { it.bytes }.thenBy { it.countryCode })
            .take(caps.maxCountries)
        val domainRows = domains.entries
            .map { (name, value) ->
                DomainTraffic(
                    domain = name,
                    queries = value.queries,
                    blockedQueries = value.blockedQueries.coerceAtMost(value.queries),
                )
            }
            .sortedWith(compareByDescending<DomainTraffic> { it.queries }.thenBy { it.domain })
            .take(caps.maxDomains)
        TrafficSnapshot(
            state = state,
            startedAtMillis = startedAtMillis,
            updatedAtMillis = updatedAtMillis,
            txBytes = txBytes,
            rxBytes = rxBytes,
            activeFlows = activeFlows.size,
            blockedFlows = blockedFlows,
            correlatedFlows = correlatedFlows,
            annotatedFlows = annotatedFlows,
            apps = appRows,
            countries = countryRows,
            domains = domainRows,
            transportErrors = transportErrors,
        )
    }

    // --- internal bookkeeping ------------------------------------------------------------------

    private fun beginIfIdle(now: Long) {
        if (startedAtMillis == 0L) startedAtMillis = now
        if (state == "IDLE") state = "ACTIVE"
    }

    private fun touch(timestamp: Long) {
        updatedAtMillis = maxOf(updatedAtMillis, normalizeTimestamp(timestamp))
    }

    private fun ensureApp(packageName: String, label: String): MutableApp? {
        val existing = apps[packageName]
        if (existing != null) {
            if (label.isNotEmpty() && existing.label != label) existing.label = label
            return existing
        }
        if (apps.size >= caps.maxApps) return null
        val app = MutableApp(packageName = packageName, label = label)
        apps[packageName] = app
        return app
    }

    private fun addTraffic(app: MutableApp, countryCode: String?, deltaTx: Long, deltaRx: Long) {
        if (deltaTx <= 0L && deltaRx <= 0L) return
        app.txBytes = saturatingAdd(app.txBytes, deltaTx)
        app.rxBytes = saturatingAdd(app.rxBytes, deltaRx)
        txBytes = saturatingAdd(txBytes, deltaTx)
        rxBytes = saturatingAdd(rxBytes, deltaRx)
        val total = saturatingAdd(deltaTx, deltaRx)
        countryBucket(countryCode)?.let { it.bytes = saturatingAdd(it.bytes, total) }
        appCountry(app, countryCode)?.let { it.bytes = saturatingAdd(it.bytes, total) }
    }

    private fun countryBucket(countryCode: String?): MutableCountry? {
        val code = countryCode ?: GeoLookup.UNKNOWN_COUNTRY
        countries[code]?.let { return it }
        if (countries.size >= caps.maxCountries) return null
        val bucket = MutableCountry()
        countries[code] = bucket
        return bucket
    }

    private fun appCountry(app: MutableApp, countryCode: String?): MutableCountry? {
        val code = countryCode ?: GeoLookup.UNKNOWN_COUNTRY
        app.countries[code]?.let { return it }
        if (app.countries.size >= caps.maxPerAppCountries) {
            evictSmallestCountry(app.countries)
            if (app.countries.size >= caps.maxPerAppCountries) return null
        }
        val bucket = MutableCountry()
        app.countries[code] = bucket
        return bucket
    }

    private fun evictSmallestCountry(map: LinkedHashMap<String, MutableCountry>) {
        val victim = map.entries
            .sortedWith(compareBy<Map.Entry<String, MutableCountry>> { it.value.bytes }.thenBy { it.key })
            .firstOrNull()
            ?: return
        map.remove(victim.key)
    }

    private fun domainBucket(domain: String): MutableDomain {
        domains[domain]?.let { return it }
        while (domains.size >= caps.maxDomains) {
            val victim = domains.entries
                .sortedWith(compareBy<Map.Entry<String, MutableDomain>> { it.value.queries }.thenBy { it.key })
                .firstOrNull()
                ?: break
            domains.remove(victim.key)
        }
        val bucket = MutableDomain()
        domains[domain] = bucket
        return bucket
    }

    private fun appDomain(app: MutableApp, domain: String): MutableDomain {
        app.domains[domain]?.let { return it }
        while (app.domains.size >= caps.maxPerAppDomains) {
            val victim = app.domains.entries
                .sortedWith(compareBy<Map.Entry<String, MutableDomain>> { it.value.queries }.thenBy { it.key })
                .firstOrNull()
                ?: break
            app.domains.remove(victim.key)
        }
        val bucket = MutableDomain()
        app.domains[domain] = bucket
        return bucket
    }

    private fun appTopCountries(app: MutableApp): List<CountryTraffic> = app.countries.entries
        .map { (code, value) ->
            CountryTraffic(
                countryCode = code,
                bytes = value.bytes,
                flows = value.flows,
                blockedFlows = value.blockedFlows.coerceAtMost(value.flows),
            )
        }
        .sortedWith(compareByDescending<CountryTraffic> { it.bytes }.thenBy { it.countryCode })
        .take(caps.topCountriesPerApp)
        .toList()

    private fun appTopDomains(app: MutableApp): List<DomainTraffic> = app.domains.entries
        .map { (name, value) ->
            DomainTraffic(
                domain = name,
                queries = value.queries,
                blockedQueries = value.blockedQueries.coerceAtMost(value.queries),
            )
        }
        .sortedWith(compareByDescending<DomainTraffic> { it.queries }.thenBy { it.domain })
        .take(caps.topDomainsPerApp)
        .toList()

    private fun appendHistory(flow: MutableFlow) {
        val entry = TrafficFlow(
            id = flow.id,
            ownerPackage = flow.ownerPackage,
            ownerLabel = flow.ownerLabel,
            destinationAddress = flow.destinationAddress,
            countryCode = flow.countryCode,
            destinationDomain = flow.destinationDomain,
            action = flow.action,
            protocol = flow.protocol,
            txBytes = flow.txBytes,
            rxBytes = flow.rxBytes,
            openedAtMillis = flow.openedAtMillis,
            lastSeenMillis = maxOf(flow.lastSeenMillis, flow.openedAtMillis),
        )
        history.addFirst(entry)
        while (history.size > caps.maxHistoryFlows) history.removeLast()
    }

    private fun normalizePackage(raw: String): String? =
        raw.trim().takeIf { it.isNotEmpty() && it.length <= 255 }

    private fun normalizeLabel(raw: String, fallback: String): String =
        raw.trim().take(caps.maxLabelLength).ifEmpty { fallback.take(caps.maxLabelLength) }

    private fun normalizeAddress(raw: String): String? =
        raw.trim().takeIf { it.isNotEmpty() && it.length <= 64 }

    private fun normalizeProtocol(raw: String): String? {
        val value = raw.trim().lowercase(Locale.ROOT)
        if (value.length !in 1..8) return null
        if (value.any { !(it in 'a'..'z' || it in '0'..'9') }) return null
        return value
    }

    private fun normalizeDomain(raw: String?): String? {
        if (raw.isNullOrBlank()) return null
        return canonicalPrivacyDomain(raw)
    }

    private fun normalizeCountry(code: String?): String? {
        val value = code?.trim()?.uppercase(Locale.ROOT) ?: return null
        if (value.length != 2) return null
        if (value.any { it !in 'A'..'Z' }) return null
        return value
    }

    private fun normalizeTimestamp(value: Long): Long =
        if (value > 0L) value else clock().coerceAtLeast(1L)

    private fun saturatingAdd(left: Long, right: Long): Long {
        if (right <= 0L) return left
        return if (Long.MAX_VALUE - left < right) Long.MAX_VALUE else left + right
    }
}
