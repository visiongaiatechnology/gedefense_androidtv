package de.visiongaia.gedefense.tv.core.anomaly

import de.visiongaia.gedefense.mobile.core.FeedSemantics
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.tv.core.model.AnomalyKind
import de.visiongaia.gedefense.tv.core.model.AnomalySignal
import de.visiongaia.gedefense.tv.core.model.Confidence
import de.visiongaia.gedefense.tv.core.model.OutboundAnomaly
import de.visiongaia.gedefense.tv.core.model.Severity
import de.visiongaia.gedefense.tv.core.model.TrafficAction
import de.visiongaia.gedefense.tv.core.model.TrafficFlow
import de.visiongaia.gedefense.tv.core.model.TrafficSnapshot
import de.visiongaia.gedefense.tv.core.policy.TrackerCatalog
import de.visiongaia.gedefense.tv.core.policy.TrackerCategory
import java.util.Locale
import kotlin.math.sqrt

/**
 * Tunable windows, thresholds and bounds of the TV outbound anomaly engine.
 *
 * Defaults implement the datasheet V2.1 rules. Every threshold is bounded so the engine cannot be
 * configured into unbounded memory use or absurd windows.
 */
data class AnomalyConfig(
    val dnsBurstWindowMillis: Long = 60_000L,
    val dnsBurstThreshold: Int = 25,
    val fanoutWindowMillis: Long = 300_000L,
    val fanoutPrefixThreshold: Int = 20,
    val fanoutShortWindowMillis: Long = 60_000L,
    val fanoutShortDistinctPrefixThreshold: Int = 3,
    val beaconWindowMillis: Long = 1_800_000L,
    val beaconMinFlows: Int = 6,
    val beaconMinIntervalMillis: Long = 20_000L,
    val beaconMaxIntervalMillis: Long = 600_000L,
    val beaconMaxJitterFraction: Double = 0.20,
    val volumeWindowMillis: Long = 60_000L,
    val volumeAbsoluteBytes: Long = 8L * 1024L * 1024L,
    val volumeRatio: Double = 4.0,
    val previousWindowMaxApps: Int = 64,
    val repeatedBlockWindowMillis: Long = 300_000L,
    val repeatedBlockThreshold: Int = 3,
    val trackerWindowMillis: Long = 300_000L,
    val trackerThreshold: Int = 2,
    val c2WindowMillis: Long = 300_000L,
    val corridorWindowMillis: Long = 300_000L,
    val corridorThreshold: Int = 2,
    val highRiskCountries: Set<String> = setOf("RU", "CN", "IR", "KP", "SY"),
    val scanFlowLimit: Int = 500,
    val maxAnomalies: Int = 32,
    val maxKnownApps: Int = 512,
    val idWindowMillis: Long = 300_000L,
) {
    init {
        require(dnsBurstWindowMillis in 1_000L..3_600_000L) { "invalid DNS burst window" }
        require(dnsBurstThreshold in 1..1_000) { "invalid DNS burst threshold" }
        require(fanoutWindowMillis in 1_000L..3_600_000L) { "invalid fanout window" }
        require(fanoutPrefixThreshold in 1..1_000) { "invalid fanout threshold" }
        require(fanoutShortWindowMillis in 1_000L..3_600_000L) { "invalid short fanout window" }
        require(fanoutShortDistinctPrefixThreshold in 1..1_000) { "invalid short fanout threshold" }
        require(beaconWindowMillis in 60_000L..(24L * 3_600_000L)) { "invalid beacon window" }
        require(beaconMinFlows in 2..100) { "invalid beacon minimum flows" }
        require(beaconMinIntervalMillis in 1_000L..beaconMaxIntervalMillis) { "invalid beacon interval bounds" }
        require(beaconMaxIntervalMillis in beaconMinIntervalMillis..86_400_000L) { "invalid beacon interval bounds" }
        require(beaconMaxJitterFraction in 0.01..1.0) { "invalid beacon jitter fraction" }
        require(volumeWindowMillis in 1_000L..3_600_000L) { "invalid volume window" }
        require(volumeAbsoluteBytes in 1L..(64L shl 30)) { "invalid volume absolute bound" }
        require(volumeRatio in 1.1..100.0) { "invalid volume ratio" }
        require(previousWindowMaxApps in 1..512) { "invalid previous window app bound" }
        require(repeatedBlockWindowMillis in 1_000L..3_600_000L) { "invalid repeated block window" }
        require(repeatedBlockThreshold in 1..100) { "invalid repeated block threshold" }
        require(trackerWindowMillis in 1_000L..3_600_000L) { "invalid tracker window" }
        require(trackerThreshold in 1..100) { "invalid tracker threshold" }
        require(c2WindowMillis in 1_000L..3_600_000L) { "invalid C2 window" }
        require(corridorWindowMillis in 1_000L..3_600_000L) { "invalid corridor window" }
        require(corridorThreshold in 1..100) { "invalid corridor threshold" }
        require(highRiskCountries.all { it.matches(Regex("[A-Z]{2}")) }) { "invalid high risk country" }
        require(scanFlowLimit in 1..2_000) { "invalid flow scan bound" }
        require(maxAnomalies in 1..128) { "invalid anomaly bound" }
        require(maxKnownApps in 1..4_096) { "invalid known app bound" }
        require(idWindowMillis in 60_000L..3_600_000L) { "invalid id window" }
    }

    companion object {
        val DEFAULT = AnomalyConfig()
    }
}

/**
 * Deterministic, bounded outbound anomaly detection for the TV loopback VPN.
 *
 * The engine is a pure heuristic over locally observed flows: it never invents data, never blocks by
 * itself and never claims malware. Every anomaly carries its contributing [AnomalySignal] list so UI
 * and evidence can explain the score. Independent destination-specific signals encode up to two
 * destination addresses in their detail, enabling the containment policy's /24 (IPv4) or /64 (IPv6)
 * aggregation guardrail without touching the frozen anomaly model.
 *
 * Bounds: at most [AnomalyConfig.scanFlowLimit] flows, [AnomalyConfig.maxKnownApps] tracked packages,
 * [AnomalyConfig.previousWindowMaxApps] previous-window volume entries and
 * [AnomalyConfig.maxAnomalies] output anomalies.
 */
class OutboundAnomalyEngine(
    private val trackerCatalog: TrackerCatalog = TrackerCatalog.TV_DEFAULT,
    private val threatIndex: ThreatIndex = ThreatIndex.empty(),
    private val config: AnomalyConfig = AnomalyConfig(),
    private val clock: () -> Long = { System.currentTimeMillis() },
) {

    private data class WindowStat(val bytes: Long, val observedAtMillis: Long)

    private data class SignalEvidence(
        val kind: AnomalyKind,
        val score: Int,
        val detail: String,
        val count: Int,
        val destinationPrefix: String?,
        val destinationAddresses: List<String>,
        val countryCode: String?,
        val firstSeenMillis: Long,
        val lastSeenMillis: Long,
    )

    private data class BeaconCandidate(
        val address: String,
        val count: Int,
        val meanIntervalMillis: Long,
        val stddevMillis: Double,
    )

    private val lock = Any()
    private val previousWindowBytes = LinkedHashMap<String, WindowStat>()
    private val knownApps = LinkedHashSet<String>()
    private var revisionCounter = 0L

    /** Number of tracked packages; bounded by [AnomalyConfig.maxKnownApps]. */
    val knownAppCount: Int get() = synchronized(lock) { knownApps.size }

    /** Number of apps with previous-window volume state; bounded by [AnomalyConfig.previousWindowMaxApps]. */
    val previousWindowAppCount: Int get() = synchronized(lock) { previousWindowBytes.size }

    fun revision(): Long = synchronized(lock) { revisionCounter }

    /** Clears sliding-window state (e.g. on VPN session restart). */
    fun reset() {
        synchronized(lock) {
            previousWindowBytes.clear()
            knownApps.clear()
            revisionCounter += 1L
        }
    }

    fun evaluate(
        snapshot: TrafficSnapshot,
        flows: List<TrafficFlow>,
        nowMillis: Long = clock(),
    ): List<OutboundAnomaly> = synchronized(lock) {
        revisionCounter += 1L
        if (flows.isEmpty() && !snapshot.hasObservation) return emptyList()
        val now = nowMillis.coerceAtLeast(1L)
        val maxWindow = maxOf(
            config.dnsBurstWindowMillis,
            config.fanoutWindowMillis,
            config.beaconWindowMillis,
            config.volumeWindowMillis,
            config.repeatedBlockWindowMillis,
            config.trackerWindowMillis,
            config.c2WindowMillis,
            config.corridorWindowMillis,
        )
        val windowFloor = (now - maxWindow).coerceAtLeast(1L)
        val considered = flows.asSequence()
            .filter { flow -> flow.lastSeenMillis in windowFloor..now && flow.openedAtMillis <= now }
            .sortedWith(compareByDescending<TrafficFlow> { it.lastSeenMillis }.thenBy { it.id })
            .take(config.scanFlowLimit)
            .toList()
        if (considered.isEmpty()) {
            updatePreviousWindowState(emptyMap(), now)
            return emptyList()
        }

        considered.forEach { flow -> registerKnownApp(flow.ownerPackage) }
        val flowsByApp = LinkedHashMap<String, MutableList<TrafficFlow>>()
        considered.forEach { flow ->
            if (flowsByApp.size >= config.maxKnownApps && !flowsByApp.containsKey(flow.ownerPackage)) return@forEach
            flowsByApp.getOrPut(flow.ownerPackage) { ArrayList(8) }.add(flow)
        }

        val currentWindowBytes = LinkedHashMap<String, Long>()
        flowsByApp.forEach { (packageName, appFlows) ->
            val current = appFlows.filter { flow -> flow.lastSeenMillis >= now - config.volumeWindowMillis }
            val total = current.fold(0L) { sum, flow -> PrefixSupport.saturatingAdd(sum, PrefixSupport.bytesOf(flow)) }
            if (total > 0L) currentWindowBytes[packageName] = total
        }

        val anomalies = ArrayList<OutboundAnomaly>(flowsByApp.size)
        flowsByApp.forEach { (packageName, appFlows) ->
            val signals = detectSignals(packageName, appFlows, currentWindowBytes, now)
            if (signals.isNotEmpty()) anomalies += buildAnomaly(packageName, appFlows, signals, now)
        }
        updatePreviousWindowState(currentWindowBytes, now)
        anomalies
            .sortedWith(
                compareByDescending<OutboundAnomaly> { it.score }
                    .thenByDescending { it.lastSeenMillis }
                    .thenBy { it.id },
            )
            .take(config.maxAnomalies)
    }

    // --- rule detection ------------------------------------------------------------------------

    private fun detectSignals(
        packageName: String,
        appFlows: List<TrafficFlow>,
        currentWindowBytes: Map<String, Long>,
        now: Long,
    ): List<SignalEvidence> {
        val signals = ArrayList<SignalEvidence>(8)

        val dnsFlows = windowed(appFlows, now, config.dnsBurstWindowMillis)
            .filter { flow -> flow.destinationDomain != null }
        if (dnsFlows.size >= config.dnsBurstThreshold) {
            val bounds = boundsOf(dnsFlows) ?: return signals
            signals += SignalEvidence(
                kind = AnomalyKind.DNS_BURST,
                score = dnsScore(dnsFlows.size),
                detail = "dns_queries=${dnsFlows.size}",
                count = dnsFlows.size,
                destinationPrefix = null,
                destinationAddresses = emptyList(),
                countryCode = countryOf(dnsFlows),
                firstSeenMillis = bounds.first,
                lastSeenMillis = bounds.second,
            )
        }

        detectFanout(appFlows, now)?.let(signals::add)
        detectBeacon(appFlows, now)?.let(signals::add)
        detectVolume(appFlows, currentWindowBytes[packageName] ?: 0L, now)?.let(signals::add)
        detectRepeatedBlock(appFlows, now)?.let(signals::add)
        detectTrackerCategory(appFlows, now)?.let(signals::add)
        detectC2(appFlows, now)?.let(signals::add)
        detectCorridor(appFlows, now)?.let(signals::add)
        return signals
    }

    private fun detectFanout(appFlows: List<TrafficFlow>, now: Long): SignalEvidence? {
        val longFlows = windowed(appFlows, now, config.fanoutWindowMillis)
        val longPrefixes = longFlows.mapNotNull { flow -> PrefixSupport.aggregationPrefix(flow.destinationAddress) }.toSet()
        val shortFlows = windowed(appFlows, now, config.fanoutShortWindowMillis)
            .filter { flow -> PrefixSupport.parseAddress(flow.destinationAddress)?.family == 4 }
        val shortPrefixes = shortFlows.mapNotNull { flow -> PrefixSupport.aggregationPrefix(flow.destinationAddress) }.toSet()
        val (selectedFlows, count, score, extra) = when {
            longPrefixes.size >= config.fanoutPrefixThreshold ->
                FanoutSelection(longFlows, longPrefixes.size, fanoutLongScore(longPrefixes.size), "window=long")
            shortPrefixes.size >= config.fanoutShortDistinctPrefixThreshold ->
                FanoutSelection(shortFlows, shortPrefixes.size, fanoutShortScore(shortPrefixes.size), "window=short")
            else -> return null
        }
        val prefixAndAddresses = selectPrefixAndAddresses(selectedFlows) ?: return null
        return SignalEvidence(
            kind = AnomalyKind.DESTINATION_FANOUT,
            score = score,
            detail = AnomalyDetailCodec.encode(prefixAndAddresses.second, "prefixes=$count;$extra"),
            count = count,
            destinationPrefix = prefixAndAddresses.first,
            destinationAddresses = prefixAndAddresses.second,
            countryCode = countryOf(selectedFlows),
            firstSeenMillis = selectedFlows.minOf { it.openedAtMillis },
            lastSeenMillis = selectedFlows.maxOf { it.lastSeenMillis },
        )
    }

    private data class FanoutSelection(
        val flows: List<TrafficFlow>,
        val count: Int,
        val score: Int,
        val windowLabel: String,
    )

    private fun detectBeacon(appFlows: List<TrafficFlow>, now: Long): SignalEvidence? {
        val beaconFlows = windowed(appFlows, now, config.beaconWindowMillis)
        if (beaconFlows.size < config.beaconMinFlows) return null
        val byDestination = LinkedHashMap<String, MutableList<TrafficFlow>>()
        beaconFlows.forEach { flow ->
            val address = PrefixSupport.canonicalAddress(flow.destinationAddress) ?: return@forEach
            byDestination.getOrPut(address) { ArrayList(8) }.add(flow)
        }
        var best: BeaconCandidate? = null
        byDestination.forEach { (address, flows) ->
            if (flows.size < config.beaconMinFlows) return@forEach
            val times = flows.map { it.lastSeenMillis }.sorted()
            val intervals = times.zipWithNext { first, second -> second - first }
            if (intervals.size < config.beaconMinFlows - 1) return@forEach
            val mean = intervals.average()
            if (mean < config.beaconMinIntervalMillis || mean > config.beaconMaxIntervalMillis) return@forEach
            val variance = intervals.sumOf { interval -> val delta = interval - mean; delta * delta } / intervals.size
            val stddev = sqrt(variance)
            if (stddev > mean * config.beaconMaxJitterFraction) return@forEach
            val candidate = BeaconCandidate(address, flows.size, mean.toLong(), stddev)
            val currentBest = best
            if (currentBest == null ||
                candidate.count > currentBest.count ||
                (candidate.count == currentBest.count && candidate.address < currentBest.address)
            ) {
                best = candidate
            }
        }
        val candidate = best ?: return null
        val candidateFlows = byDestination[candidate.address].orEmpty()
        val prefixAndAddresses = selectPrefixAndAddresses(candidateFlows) ?: return null
        val jitterPercent = if (candidate.meanIntervalMillis > 0L) {
            (candidate.stddevMillis / candidate.meanIntervalMillis * 100.0).toInt()
        } else {
            0
        }
        return SignalEvidence(
            kind = AnomalyKind.BEACON_PATTERN,
            score = beaconScore(candidate.count),
            detail = AnomalyDetailCodec.encode(
                prefixAndAddresses.second,
                "interval_s=${candidate.meanIntervalMillis / 1000L};jitter_pct=$jitterPercent",
            ),
            count = candidate.count,
            destinationPrefix = prefixAndAddresses.first,
            destinationAddresses = prefixAndAddresses.second,
            countryCode = countryOf(candidateFlows),
            firstSeenMillis = candidateFlows.minOf { it.openedAtMillis },
            lastSeenMillis = candidateFlows.maxOf { it.lastSeenMillis },
        )
    }

    private fun detectVolume(appFlows: List<TrafficFlow>, currentBytes: Long, now: Long): SignalEvidence? {
        val previous = previousWindowBytes[appFlows.first().ownerPackage]
        val absolute = currentBytes >= config.volumeAbsoluteBytes
        val ratio = previous != null && previous.bytes > 0L &&
            currentBytes.toDouble() >= previous.bytes.toDouble() * config.volumeRatio
        if (!absolute && !ratio) return null
        val volumeFlows = windowed(appFlows, now, config.volumeWindowMillis)
        val bounds = boundsOf(volumeFlows) ?: return null
        val previousBytes = previous?.bytes ?: 0L
        val ratioX10 = if (previousBytes > 0L) currentBytes / (previousBytes / 10L).coerceAtLeast(1L) else 0L
        return SignalEvidence(
            kind = AnomalyKind.VOLUME_SPIKE,
            score = volumeScore(absolute, ratio),
            detail = "bytes=$currentBytes;prev=$previousBytes;ratio_x10=$ratioX10",
            count = volumeFlows.size.coerceAtLeast(1),
            destinationPrefix = null,
            destinationAddresses = emptyList(),
            countryCode = countryOf(volumeFlows),
            firstSeenMillis = bounds.first,
            lastSeenMillis = bounds.second,
        )
    }

    private fun detectRepeatedBlock(appFlows: List<TrafficFlow>, now: Long): SignalEvidence? {
        val blocked = windowed(appFlows, now, config.repeatedBlockWindowMillis)
            .filter { flow -> flow.action == TrafficAction.BLOCK }
        if (blocked.size < config.repeatedBlockThreshold) return null
        val bounds = boundsOf(blocked) ?: return null
        val prefixAndAddresses = selectPrefixAndAddresses(blocked)
        return SignalEvidence(
            kind = AnomalyKind.REPEATED_BLOCK,
            score = repeatedScore(blocked.size),
            detail = AnomalyDetailCodec.encode(prefixAndAddresses?.second.orEmpty(), "blocked=${blocked.size}"),
            count = blocked.size,
            destinationPrefix = prefixAndAddresses?.first,
            destinationAddresses = prefixAndAddresses?.second.orEmpty(),
            countryCode = countryOf(blocked),
            firstSeenMillis = bounds.first,
            lastSeenMillis = bounds.second,
        )
    }

    private fun detectTrackerCategory(appFlows: List<TrafficFlow>, now: Long): SignalEvidence? {
        val blockedTrackers = windowed(appFlows, now, config.trackerWindowMillis).filter { flow ->
            flow.action == TrafficAction.BLOCK && flow.destinationDomain?.let { domain ->
                when (trackerCatalog.match(domain)?.category) {
                    TrackerCategory.TELEMETRY, TrackerCategory.ACR, TrackerCategory.ADS -> true
                    else -> false
                }
            } == true
        }
        if (blockedTrackers.size < config.trackerThreshold) return null
        val bounds = boundsOf(blockedTrackers) ?: return null
        val categories = blockedTrackers.mapNotNull { flow ->
            flow.destinationDomain?.let { domain -> trackerCatalog.match(domain)?.category }
        }.distinct().sortedBy { it.name }
        val prefixAndAddresses = selectPrefixAndAddresses(blockedTrackers)
        return SignalEvidence(
            kind = AnomalyKind.TRACKER_CATEGORY,
            score = trackerScore(blockedTrackers.size),
            detail = AnomalyDetailCodec.encode(
                prefixAndAddresses?.second.orEmpty(),
                "categories=${categories.joinToString(",")};blocked=${blockedTrackers.size}",
            ),
            count = blockedTrackers.size,
            destinationPrefix = prefixAndAddresses?.first,
            destinationAddresses = prefixAndAddresses?.second.orEmpty(),
            countryCode = countryOf(blockedTrackers),
            firstSeenMillis = bounds.first,
            lastSeenMillis = bounds.second,
        )
    }

    private fun detectC2(appFlows: List<TrafficFlow>, now: Long): SignalEvidence? {
        val c2Flows = windowed(appFlows, now, config.c2WindowMillis).mapNotNull { flow ->
            val match = threatIndex.match(flow.destinationAddress) ?: return@mapNotNull null
            val feeds = match.feeds.filter { feed -> feed.semantics == FeedSemantics.MALICIOUS_C2 }
            if (feeds.isEmpty()) return@mapNotNull null
            flow to feeds.map { it.id }
        }
        if (c2Flows.isEmpty()) return null
        val flows = c2Flows.map { it.first }
        val feeds = c2Flows.flatMap { it.second }.distinct().sorted()
        val bounds = boundsOf(flows) ?: return null
        val prefixAndAddresses = selectPrefixAndAddresses(flows)
        return SignalEvidence(
            kind = AnomalyKind.C2_MATCH,
            score = c2Score(flows.size),
            detail = AnomalyDetailCodec.encode(prefixAndAddresses?.second.orEmpty(), "feeds=${feeds.joinToString(",")}"),
            count = flows.size,
            destinationPrefix = prefixAndAddresses?.first,
            destinationAddresses = prefixAndAddresses?.second.orEmpty(),
            countryCode = countryOf(flows),
            firstSeenMillis = bounds.first,
            lastSeenMillis = bounds.second,
        )
    }

    private fun detectCorridor(appFlows: List<TrafficFlow>, now: Long): SignalEvidence? {
        val corridorFlows = windowed(appFlows, now, config.corridorWindowMillis).filter { flow ->
            val country = normalizeCountry(flow.countryCode)
            country != null && country in config.highRiskCountries
        }
        val countries = corridorFlows.mapNotNull { flow -> normalizeCountry(flow.countryCode) }
            .filter { country -> country in config.highRiskCountries }
            .distinct()
            .sorted()
        if (corridorFlows.size < config.corridorThreshold || countries.isEmpty()) return null
        val bounds = boundsOf(corridorFlows) ?: return null
        return SignalEvidence(
            kind = AnomalyKind.HIGH_RISK_CORRIDOR,
            score = corridorScore(countries.size),
            detail = "countries=${countries.joinToString(",")};flows=${corridorFlows.size}",
            count = corridorFlows.size,
            destinationPrefix = null,
            destinationAddresses = emptyList(),
            countryCode = countries.first(),
            firstSeenMillis = bounds.first,
            lastSeenMillis = bounds.second,
        )
    }

    // --- anomaly assembly ----------------------------------------------------------------------

    private fun buildAnomaly(
        packageName: String,
        appFlows: List<TrafficFlow>,
        signals: List<SignalEvidence>,
        now: Long,
    ): OutboundAnomaly {
        val ordered = signals.sortedWith(
            compareByDescending<SignalEvidence> { it.score }
                .thenByDescending { kindPriority(it.kind) }
                .thenBy { it.detail },
        )
        val dominant = ordered.first()
        val totalScore = ordered.sumOf { it.score }.coerceIn(0, 100)
        val destinationSignal = ordered.firstOrNull { it.destinationPrefix != null && it.destinationAddresses.size >= 2 }
            ?: ordered.firstOrNull { it.destinationPrefix != null }
        val appLabel = appFlows.firstOrNull { it.ownerLabel.isNotBlank() }?.ownerLabel?.take(120)
        val country = destinationSignal?.countryCode ?: countryOf(appFlows)
        val firstSeen = appFlows.minOf { it.openedAtMillis }.coerceAtLeast(1L)
        val lastSeen = maxOf(appFlows.maxOf { it.lastSeenMillis }, firstSeen)
        val safePackageName = packageName.take(255)
        val bucket = now / config.idWindowMillis
        val id = "an-" + PrefixSupport.sha256Hex(
            "$safePackageName|${dominant.kind.name}|${destinationSignal?.destinationPrefix ?: "-"}|$bucket",
        ).take(20)
        val distinctKinds = ordered.map { it.kind }.distinct().size
        val anomalySignals = ordered.take(8).map { signal ->
            AnomalySignal(
                kind = signal.kind,
                score = signal.score.coerceIn(-100, 100),
                detail = signal.detail.take(160),
                count = signal.count.coerceAtLeast(0),
            )
        }
        return OutboundAnomaly(
            id = id,
            kind = dominant.kind,
            packageName = safePackageName,
            appLabel = appLabel,
            countryCode = country,
            destinationPrefix = destinationSignal?.destinationPrefix,
            score = totalScore,
            severity = severityFor(totalScore),
            confidence = confidenceFor(totalScore, distinctKinds, ordered.any { it.kind == AnomalyKind.C2_MATCH }),
            signals = anomalySignals,
            firstSeenMillis = firstSeen,
            lastSeenMillis = lastSeen,
            observationCount = appFlows.size.coerceAtLeast(1),
        )
    }

    // --- helpers -------------------------------------------------------------------------------

    private fun windowed(appFlows: List<TrafficFlow>, now: Long, windowMillis: Long): List<TrafficFlow> =
        appFlows.filter { flow -> flow.lastSeenMillis >= now - windowMillis }

    private fun boundsOf(flows: List<TrafficFlow>): Pair<Long, Long>? {
        if (flows.isEmpty()) return null
        return flows.minOf { it.openedAtMillis } to flows.maxOf { it.lastSeenMillis }
    }

    private fun selectPrefixAndAddresses(flows: List<TrafficFlow>): Pair<String, List<String>>? {
        if (flows.isEmpty()) return null
        val groups = LinkedHashMap<String, MutableList<TrafficFlow>>()
        flows.forEach { flow ->
            val prefix = PrefixSupport.aggregationPrefix(flow.destinationAddress) ?: return@forEach
            groups.getOrPut(prefix) { ArrayList(4) }.add(flow)
        }
        if (groups.isEmpty()) return null
        val best = groups.entries.sortedWith(
            compareByDescending<Map.Entry<String, MutableList<TrafficFlow>>> { it.value.size }.thenBy { it.key },
        ).first()
        val addresses = best.value
            .mapNotNull { flow -> PrefixSupport.canonicalAddress(flow.destinationAddress) }
            .distinct()
            .sorted()
            .take(2)
        return best.key to addresses
    }

    private fun countryOf(flows: List<TrafficFlow>): String? = flows
        .mapNotNull { flow -> normalizeCountry(flow.countryCode) }
        .firstOrNull { country -> country != "ZZ" && country != "UNKNOWN" }

    private fun normalizeCountry(raw: String?): String? {
        val value = raw?.trim()?.uppercase(Locale.ROOT) ?: return null
        if (value.length != 2 || value.any { it !in 'A'..'Z' }) return null
        return value
    }

    private fun registerKnownApp(packageName: String) {
        if (!knownApps.add(packageName)) return
        while (knownApps.size > config.maxKnownApps) {
            val iterator = knownApps.iterator()
            if (!iterator.hasNext()) break
            iterator.next()
            iterator.remove()
        }
    }

    private fun updatePreviousWindowState(currentBytes: Map<String, Long>, now: Long) {
        currentBytes.forEach { (packageName, bytes) -> previousWindowBytes[packageName] = WindowStat(bytes, now) }
        val expiry = (now - config.volumeWindowMillis * 2L).coerceAtLeast(1L)
        previousWindowBytes.keys
            .filter { packageName -> (previousWindowBytes[packageName]?.observedAtMillis ?: 0L) < expiry }
            .forEach(previousWindowBytes::remove)
        while (previousWindowBytes.size > config.previousWindowMaxApps) {
            val victim = previousWindowBytes.entries
                .sortedWith(compareBy<Map.Entry<String, WindowStat>> { it.value.observedAtMillis }.thenBy { it.key })
                .firstOrNull()
                ?: break
            previousWindowBytes.remove(victim.key)
        }
    }

    private fun dnsScore(count: Int): Int = (20 + (count - config.dnsBurstThreshold) * 20 / config.dnsBurstThreshold.coerceAtLeast(1)).coerceIn(20, 40)

    private fun fanoutLongScore(count: Int): Int = (25 + (count - config.fanoutPrefixThreshold)).coerceIn(25, 45)

    private fun fanoutShortScore(count: Int): Int = (12 + (count - config.fanoutShortDistinctPrefixThreshold) * 2).coerceIn(12, 20)

    private fun beaconScore(count: Int): Int = (30 + (count - config.beaconMinFlows) * 5).coerceIn(30, 50)

    private fun volumeScore(absolute: Boolean, ratio: Boolean): Int = when {
        absolute && ratio -> 45
        absolute -> 35
        else -> 25
    }

    private fun repeatedScore(count: Int): Int = (30 + (count - config.repeatedBlockThreshold) * 5).coerceIn(30, 50)

    private fun trackerScore(count: Int): Int = (25 + (count - config.trackerThreshold) * 2).coerceIn(25, 35)

    private fun c2Score(count: Int): Int = (60 + (count - 1) * 5).coerceIn(60, 80)

    private fun corridorScore(countryCount: Int): Int = (10 + 2 * minOf(countryCount, 4)).coerceIn(10, 18)

    private fun severityFor(score: Int): Severity = when {
        score >= 80 -> Severity.CRITICAL
        score >= 60 -> Severity.HIGH
        score >= 35 -> Severity.MEDIUM
        score >= 15 -> Severity.LOW
        else -> Severity.INFO
    }

    private fun confidenceFor(score: Int, distinctKinds: Int, hasC2: Boolean): Confidence = when {
        hasC2 || distinctKinds >= 3 || score >= 80 -> Confidence.HIGH
        distinctKinds >= 2 || score >= 40 -> Confidence.MEDIUM
        else -> Confidence.LOW
    }

    private fun kindPriority(kind: AnomalyKind): Int = when (kind) {
        AnomalyKind.C2_MATCH -> 8
        AnomalyKind.REPEATED_BLOCK -> 7
        AnomalyKind.BEACON_PATTERN -> 6
        AnomalyKind.DESTINATION_FANOUT -> 5
        AnomalyKind.TRACKER_CATEGORY -> 4
        AnomalyKind.DNS_BURST -> 3
        AnomalyKind.VOLUME_SPIKE -> 2
        AnomalyKind.HIGH_RISK_CORRIDOR -> 1
    }
}
