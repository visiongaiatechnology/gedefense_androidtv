package de.visiongaia.gedefense.tv.core

import de.visiongaia.gedefense.mobile.core.IpPrefix
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.mobile.core.ThreatRecord
import de.visiongaia.gedefense.tv.core.anomaly.AnomalyConfig
import de.visiongaia.gedefense.tv.core.anomaly.AnomalyDetailCodec
import de.visiongaia.gedefense.tv.core.anomaly.ContainmentRegistry
import de.visiongaia.gedefense.tv.core.anomaly.OutboundAnomalyEngine
import de.visiongaia.gedefense.tv.core.anomaly.OutboundContainmentPolicy
import de.visiongaia.gedefense.tv.core.anomaly.composeThreatIndex
import de.visiongaia.gedefense.tv.core.model.AnomalyKind
import de.visiongaia.gedefense.tv.core.model.AnomalySignal
import de.visiongaia.gedefense.tv.core.model.Confidence
import de.visiongaia.gedefense.tv.core.model.ContainmentOrigin
import de.visiongaia.gedefense.tv.core.model.ContainmentPolicy
import de.visiongaia.gedefense.tv.core.model.ContainmentProposal
import de.visiongaia.gedefense.tv.core.model.ContainmentRecord
import de.visiongaia.gedefense.tv.core.model.ContainmentState
import de.visiongaia.gedefense.tv.core.model.ContainmentTarget
import de.visiongaia.gedefense.tv.core.model.ContainmentTargetType
import de.visiongaia.gedefense.tv.core.model.OutboundAnomaly
import de.visiongaia.gedefense.tv.core.model.Severity
import de.visiongaia.gedefense.tv.core.model.TrafficAction
import de.visiongaia.gedefense.tv.core.model.TrafficFlow
import de.visiongaia.gedefense.tv.core.model.TrafficSnapshot
import java.io.File
import kotlin.system.exitProcess

// --- tiny assertion harness ---------------------------------------------------------------------

private var passedChecks = 0
private var failedChecks = 0
private val tests = mutableListOf<Pair<String, () -> Unit>>()

private fun test(name: String, body: () -> Unit) {
    tests += name to body
}

private fun check(condition: Boolean, message: String) {
    if (condition) {
        passedChecks += 1
    } else {
        failedChecks += 1
        throw AssertionError(message)
    }
}

private fun checkTrue(condition: Boolean, message: String) = check(condition, message)

private fun checkEquals(actual: Any?, expected: Any?, message: String) {
    check(actual == expected, "$message (expected=$expected actual=$actual)")
}

private inline fun <reified T : Throwable> checkThrows(message: String, block: () -> Unit) {
    try {
        block()
    } catch (throwable: Throwable) {
        if (throwable is T) {
            check(true, message)
            return
        }
        check(false, "$message (wrong exception: ${throwable::class.simpleName}: ${throwable.message})")
        return
    }
    check(false, "$message (no exception thrown)")
}

fun main() {
    registerTests()
    var failedTestCases = 0
    tests.forEach { (name, body) ->
        val failuresBefore = failedChecks
        try {
            body()
            if (failedChecks == failuresBefore) {
                println("ok   $name")
            } else {
                failedTestCases += 1
                println("FAIL $name")
            }
        } catch (throwable: Throwable) {
            if (failedChecks == failuresBefore) failedChecks += 1
            failedTestCases += 1
            println("FAIL $name -> ${throwable::class.simpleName}: ${throwable.message}")
            throwable.stackTrace.take(8).forEach { frame -> println("       at $frame") }
        }
    }
    println()
    println("PASS $passedChecks / FAIL $failedChecks")
    println("TESTS: ${tests.size - failedTestCases} passed, $failedTestCases failed")
    if (failedChecks > 0 || failedTestCases > 0) exitProcess(1)
}

private fun registerTests() {
    test("engine: DNS burst positive, scaled score, negative", ::testDnsBurst)
    test("engine: destination fanout long, short and negative", ::testFanout)
    test("engine: beacon math positive, jitter and interval negatives", ::testBeacon)
    test("engine: volume spike absolute and ratio", ::testVolumeSpike)
    test("engine: repeated blocked flows positive and negative", ::testRepeatedBlock)
    test("engine: tracker category blocks positive and negative", ::testTrackerCategory)
    test("engine: C2 threat-intel match positive and negative", ::testC2Match)
    test("engine: high-risk corridor is INFO and low score", ::testCorridor)
    test("engine: combined anomaly, dominance and end-to-end proposal", ::testCombinedAnomaly)
    test("engine: bounds, ids and deterministic ordering", ::testEngineBoundsAndOrdering)
    test("engine: determinism, reset and revision", ::testEngineDeterminismAndReset)
    test("engine: window filtering and configuration validation", ::testEngineWindowsAndConfig)
    test("policy: disabled by default and signal guardrails", ::testProposalGuardrails)
    test("policy: protected package and allowlist gates", ::testProposalAllowlistGates)
    test("policy: aggregation /24, /64 and single-IP guardrail", ::testProposalAggregation)
    test("policy: known country requirement and deterministic output", ::testProposalCountryAndDeterminism)
    test("registry: apply, ttl clamp, dedupe and max active", ::testRegistryApply)
    test("registry: release, expiry and isActive", ::testRegistryLifecycle)
    test("registry: ordering, revision, clear and record bound", ::testRegistryBoundsAndRevision)
    test("threat index: compose active containment onto empty base", ::testComposeEmptyBase)
    test("threat index: preserve base policy and ignore inactive records", ::testComposePreservesBase)
    test("threat index: IPv6 target, determinism and synthetic cap", ::testComposeV6AndDeterminism)
    test("source: no Android imports, valid configs and tasks", ::testSourceAndBuildChecks)
}

// --- fixtures ----------------------------------------------------------------------------------

private const val MINUTE = 60_000L
private const val KIN_NOW = 1_700_000_000_000L
private const val MIB = 1024L * 1024L

private class KineticClock(var now: Long = KIN_NOW) {
    fun read(): Long = now
}

private fun flow(
    id: Long,
    packageName: String = "com.example.app",
    action: TrafficAction = TrafficAction.ALLOW,
    domain: String? = null,
    country: String? = null,
    address: String = "45.33.32.20",
    openedAt: Long = KIN_NOW - 300_000L,
    lastSeen: Long = KIN_NOW - 1_000L,
    txBytes: Long = 10L,
    rxBytes: Long = 20L,
    label: String = "Example App",
): TrafficFlow = TrafficFlow(
    id = id,
    ownerPackage = packageName,
    ownerLabel = label,
    destinationAddress = address,
    countryCode = country,
    destinationDomain = domain,
    action = action,
    protocol = "tcp",
    txBytes = txBytes,
    rxBytes = rxBytes,
    openedAtMillis = openedAt,
    lastSeenMillis = lastSeen,
)

private fun c2Index(vararg prefixes: String): ThreatIndex = ThreatIndex.build(
    prefixes.map { prefix -> ThreatRecord("feodo", IpPrefix.parse(prefix)!!) },
)

private fun signal(
    kind: AnomalyKind,
    detail: String,
    score: Int = 30,
    count: Int = 1,
): AnomalySignal = AnomalySignal(kind = kind, score = score, detail = detail, count = count)

private fun defaultSignals(
    addresses: List<String> = listOf("45.33.32.7", "45.33.32.9"),
): List<AnomalySignal> = listOf(
    signal(AnomalyKind.C2_MATCH, AnomalyDetailCodec.encode(addresses, "feeds=feodo"), 60, addresses.size),
    signal(AnomalyKind.REPEATED_BLOCK, "blocked=3", 20, 3),
)

private fun anomaly(
    id: String = "an-test-0001",
    packageName: String? = "com.example.app",
    appLabel: String? = "Example App",
    countryCode: String? = "DE",
    destinationPrefix: String? = "45.33.32.0/24",
    score: Int = 75,
    kind: AnomalyKind = AnomalyKind.C2_MATCH,
    signals: List<AnomalySignal> = defaultSignals(),
): OutboundAnomaly = OutboundAnomaly(
    id = id,
    kind = kind,
    packageName = packageName,
    appLabel = appLabel,
    countryCode = countryCode,
    destinationPrefix = destinationPrefix,
    score = score,
    severity = Severity.HIGH,
    confidence = Confidence.HIGH,
    signals = signals,
    firstSeenMillis = KIN_NOW - MINUTE,
    lastSeenMillis = KIN_NOW,
    observationCount = 5,
)

private fun proposal(
    target: String = "45.33.32.0/24",
    ttl: Long = 10L * MINUTE,
    reasonCode: String = "anomaly_c2_match",
    kind: AnomalyKind = AnomalyKind.C2_MATCH,
    score: Int = 75,
    signals: List<AnomalySignal> = defaultSignals(),
): ContainmentProposal = ContainmentProposal(
    id = "prp-test-0001",
    target = ContainmentTarget(ContainmentTargetType.DESTINATION_PREFIX, target),
    reasonCode = reasonCode,
    anomalyKind = kind,
    anomalyScore = score,
    confidence = Confidence.HIGH,
    packageName = "com.example.app",
    appLabel = "Example App",
    countryCode = "DE",
    signals = signals,
    proposedTtlMillis = ttl,
)

private fun record(
    target: String = "45.33.32.0/24",
    state: ContainmentState = ContainmentState.ACTIVE,
    id: String = "cnt-test-" + target.hashCode().toString().replace('-', 'x'),
    created: Long = KIN_NOW,
): ContainmentRecord = ContainmentRecord(
    id = id,
    target = ContainmentTarget(ContainmentTargetType.DESTINATION_PREFIX, target),
    reasonCode = "anomaly_c2_match",
    anomalyKind = AnomalyKind.C2_MATCH,
    anomalyScore = 75,
    confidence = Confidence.HIGH,
    packageName = "com.example.app",
    appLabel = "Example App",
    countryCode = "DE",
    signals = defaultSignals(),
    origin = ContainmentOrigin.AUTO,
    state = state,
    createdAtMillis = created,
    expiresAtMillis = created + 10L * MINUTE,
    releasedAtMillis = if (state == ContainmentState.RELEASED) created + MINUTE else null,
)

private fun checkAnomalyInvariants(anomaly: OutboundAnomaly, messagePrefix: String) {
    checkTrue(anomaly.id.startsWith("an-"), "$messagePrefix id prefix")
    checkTrue(anomaly.id.length <= 128, "$messagePrefix id length")
    checkTrue(anomaly.score in 0..100, "$messagePrefix score bounds")
    checkTrue(anomaly.signals.isNotEmpty() && anomaly.signals.size <= 8, "$messagePrefix signal bounds")
    checkTrue(anomaly.signals.all { it.score in -100..100 }, "$messagePrefix signal score bounds")
    checkTrue(anomaly.signals.all { it.detail.length <= 160 }, "$messagePrefix signal detail bounds")
    checkTrue(anomaly.firstSeenMillis > 0L, "$messagePrefix first seen positive")
    checkTrue(anomaly.lastSeenMillis >= anomaly.firstSeenMillis, "$messagePrefix time order")
    checkTrue(anomaly.observationCount >= 1, "$messagePrefix observation count")
}

private fun checkSignalsSorted(anomaly: OutboundAnomaly, messagePrefix: String) {
    val scores = anomaly.signals.map { it.score }
    checkEquals(scores, scores.sortedDescending(), "$messagePrefix signals score desc")
}

// --- engine tests ------------------------------------------------------------------------------

private fun testDnsBurst() {
    val engine = OutboundAnomalyEngine()
    val flows = (1L..25L).map { id -> flow(id, domain = "telemetry.example", address = "45.33.32.20") }
    val anomalies = engine.evaluate(TrafficSnapshot.IDLE, flows, KIN_NOW)
    checkEquals(anomalies.size, 1, "DNS burst yields one anomaly")
    val anomaly = anomalies.single()
    checkAnomalyInvariants(anomaly, "dns")
    checkEquals(anomaly.kind, AnomalyKind.DNS_BURST, "DNS burst dominant kind")
    checkEquals(anomaly.signals.size, 1, "DNS burst single signal")
    checkEquals(anomaly.signals.single().kind, AnomalyKind.DNS_BURST, "DNS burst signal kind")
    checkEquals(anomaly.signals.single().score, 20, "DNS burst minimum score")
    checkEquals(anomaly.signals.single().count, 25, "DNS burst count")
    checkEquals(anomaly.score, 20, "DNS burst anomaly score")
    checkEquals(anomaly.severity, Severity.LOW, "DNS burst severity")

    val belowThreshold = OutboundAnomalyEngine()
        .evaluate(TrafficSnapshot.IDLE, (1L..24L).map { id -> flow(id, domain = "telemetry.example") }, KIN_NOW)
    checkEquals(belowThreshold.size, 0, "24 DNS queries stay quiet")

    val scaled = OutboundAnomalyEngine()
        .evaluate(TrafficSnapshot.IDLE, (1L..50L).map { id -> flow(id, domain = "telemetry.example") }, KIN_NOW)
    checkEquals(scaled.single().signals.single().score, 40, "DNS burst score capped at 40")

    val otherApp = OutboundAnomalyEngine()
    val split = (1L..20L).map { id -> flow(id, packageName = "com.a", domain = "a.example") } +
        (100L..120L).map { id -> flow(id, packageName = "com.b", domain = "b.example") }
    checkEquals(otherApp.evaluate(TrafficSnapshot.IDLE, split, KIN_NOW).size, 0, "20 queries per app stay below threshold")
}

private fun testFanout() {
    val longFlows = (1L..20L).map { index ->
        flow(
            id = index,
            address = "203.0.${index}.10",
            openedAt = KIN_NOW - (index * 10_000L),
            lastSeen = KIN_NOW - (index * 10_000L),
        )
    }
    val long = OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, longFlows, KIN_NOW)
    checkEquals(long.size, 1, "fanout long yields one anomaly")
    val anomaly = long.single()
    checkAnomalyInvariants(anomaly, "fanout-long")
    checkEquals(anomaly.kind, AnomalyKind.DESTINATION_FANOUT, "fanout dominant kind")
    checkEquals(anomaly.signals.single().count, 20, "fanout distinct prefix count")
    checkEquals(anomaly.signals.single().score, 25, "fanout long score")
    checkTrue(anomaly.destinationPrefix != null, "fanout destination prefix present")
    checkTrue(anomaly.destinationPrefix?.endsWith("/24") == true, "fanout prefix is /24")

    val shortFlows = (1L..3L).map { index -> flow(id = index, address = "198.51.${index}.10") }
    val short = OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, shortFlows, KIN_NOW)
    checkEquals(short.size, 1, "short fanout yields one anomaly")
    checkEquals(short.single().kind, AnomalyKind.DESTINATION_FANOUT, "short fanout kind")
    checkEquals(short.single().signals.single().score, 12, "short fanout low score")
    checkEquals(short.single().severity, Severity.INFO, "short fanout severity is INFO")

    val below = OutboundAnomalyEngine()
        .evaluate(TrafficSnapshot.IDLE, (1L..2L).map { index -> flow(id = index, address = "198.51.${index}.10") }, KIN_NOW)
    checkEquals(below.size, 0, "two distinct /24s stay quiet")

    val more = (1L..25L).map { index -> flow(id = index, address = "203.0.${index}.10", lastSeen = KIN_NOW - (index * 10_000L)) }
    val moreAnomalies = OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, more, KIN_NOW)
    checkEquals(moreAnomalies.single().signals.single().score, 30, "fanout score scales with prefix count")
}

private fun testBeacon() {
    val regular = (1L..6L).map { index ->
        val seen = KIN_NOW - 300_000L + (index - 1) * 60_000L
        flow(id = index, address = "45.33.33.50", openedAt = seen - 1_000L, lastSeen = seen)
    }
    val beacon = OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, regular, KIN_NOW)
    checkEquals(beacon.size, 1, "beacon yields one anomaly")
    val anomaly = beacon.single()
    checkAnomalyInvariants(anomaly, "beacon")
    checkEquals(anomaly.kind, AnomalyKind.BEACON_PATTERN, "beacon dominant kind")
    checkEquals(anomaly.signals.single().kind, AnomalyKind.BEACON_PATTERN, "beacon signal kind")
    checkEquals(anomaly.signals.single().count, 6, "beacon flow count")
    checkEquals(anomaly.signals.single().score, 30, "beacon minimum score")
    checkTrue(anomaly.signals.single().detail.contains("interval_s=60"), "beacon mean interval detail")
    checkTrue(anomaly.signals.single().detail.contains("jitter_pct=0"), "beacon jitter detail")

    val offsets = listOf(0L, 20_000L, 80_000L, 100_000L, 180_000L, 200_000L)
    val jittery = offsets.mapIndexed { index, offset ->
        val seen = KIN_NOW - 300_000L + offset
        flow(id = 100L + index, address = "45.33.33.60", openedAt = seen - 1_000L, lastSeen = seen)
    }
    checkEquals(OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, jittery, KIN_NOW).size, 0, "high jitter is not a beacon")

    val tooFast = (1L..6L).map { index ->
        val seen = KIN_NOW - 60_000L + index * 5_000L
        flow(id = 200L + index, address = "45.33.33.70", openedAt = seen - 1_000L, lastSeen = seen)
    }
    checkEquals(OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, tooFast, KIN_NOW).size, 0, "5s intervals are not a beacon")

    val slowConfig = AnomalyConfig(beaconWindowMillis = 7_200_000L)
    val tooSlow = (1L..6L).map { index ->
        val seen = KIN_NOW - 3_500_000L + index * 700_000L
        flow(id = 300L + index, address = "45.33.33.80", openedAt = seen - 1_000L, lastSeen = seen)
    }
    checkEquals(
        OutboundAnomalyEngine(config = slowConfig).evaluate(TrafficSnapshot.IDLE, tooSlow, KIN_NOW).size,
        0,
        "700s intervals are not a beacon",
    )
}

private fun testVolumeSpike() {
    val absoluteFlows = (1L..3L).map { index ->
        flow(id = index, address = "45.33.33.90", txBytes = 3L * MIB, rxBytes = 0L)
    }
    val absolute = OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, absoluteFlows, KIN_NOW)
    checkEquals(absolute.size, 1, "absolute volume spike yields one anomaly")
    val anomaly = absolute.single()
    checkAnomalyInvariants(anomaly, "volume-absolute")
    checkEquals(anomaly.kind, AnomalyKind.VOLUME_SPIKE, "volume dominant kind")
    checkEquals(anomaly.signals.single().score, 35, "absolute volume score")
    checkEquals(anomaly.severity, Severity.MEDIUM, "absolute volume severity")

    val ratioEngine = OutboundAnomalyEngine()
    val first = ratioEngine.evaluate(
        TrafficSnapshot.IDLE,
        listOf(flow(1L, address = "45.33.33.91", txBytes = 1L * MIB, rxBytes = 0L, lastSeen = KIN_NOW - 1_000L)),
        KIN_NOW,
    )
    checkEquals(first.size, 0, "baseline window is quiet")
    val second = ratioEngine.evaluate(
        TrafficSnapshot.IDLE,
        listOf(flow(2L, address = "45.33.33.91", txBytes = 5L * MIB, rxBytes = 0L, lastSeen = KIN_NOW + 9_000L)),
        KIN_NOW + 10_000L,
    )
    checkEquals(second.size, 1, "ratio volume spike yields one anomaly")
    checkEquals(second.single().kind, AnomalyKind.VOLUME_SPIKE, "ratio volume kind")
    checkEquals(second.single().signals.single().score, 25, "ratio volume score")
    checkTrue(second.single().signals.single().detail.contains("ratio_x10="), "ratio detail present")

    val negativeRatioEngine = OutboundAnomalyEngine()
    negativeRatioEngine.evaluate(
        TrafficSnapshot.IDLE,
        listOf(flow(1L, txBytes = 1L * MIB, rxBytes = 0L, lastSeen = KIN_NOW - 1_000L)),
        KIN_NOW,
    )
    val belowRatio = negativeRatioEngine.evaluate(
        TrafficSnapshot.IDLE,
        listOf(flow(2L, txBytes = 3L * MIB, rxBytes = 0L, lastSeen = KIN_NOW + 9_000L)),
        KIN_NOW + 10_000L,
    )
    checkEquals(belowRatio.size, 0, "3x previous window is not a spike")

    val belowAbsolute = OutboundAnomalyEngine().evaluate(
        TrafficSnapshot.IDLE,
        listOf(flow(1L, txBytes = 7L * MIB, rxBytes = 0L)),
        KIN_NOW,
    )
    checkEquals(belowAbsolute.size, 0, "7 MiB stays below absolute threshold")
}

private fun testRepeatedBlock() {
    val blocked = (1L..3L).map { id -> flow(id, action = TrafficAction.BLOCK, address = "45.33.33.100") }
    val positive = OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, blocked, KIN_NOW)
    checkEquals(positive.size, 1, "repeated block yields one anomaly")
    checkEquals(positive.single().kind, AnomalyKind.REPEATED_BLOCK, "repeated block kind")
    checkEquals(positive.single().signals.single().score, 30, "repeated block minimum score")
    checkEquals(positive.single().signals.single().count, 3, "repeated block count")
    val two = OutboundAnomalyEngine().evaluate(
        TrafficSnapshot.IDLE,
        (1L..2L).map { id -> flow(id, action = TrafficAction.BLOCK, address = "45.33.33.100") },
        KIN_NOW,
    )
    checkEquals(two.size, 0, "two blocked flows stay quiet")
}

private fun testTrackerCategory() {
    val trackerFlows = (1L..2L).map { id ->
        flow(id, action = TrafficAction.BLOCK, domain = "samba.tv", address = "45.33.33.110")
    }
    val positive = OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, trackerFlows, KIN_NOW)
    checkEquals(positive.size, 1, "tracker category yields one anomaly")
    checkEquals(positive.single().kind, AnomalyKind.TRACKER_CATEGORY, "tracker category kind")
    checkEquals(positive.single().signals.single().score, 25, "tracker category score")
    checkTrue(positive.single().signals.single().detail.contains("ACR"), "tracker category detail")
    val one = OutboundAnomalyEngine().evaluate(
        TrafficSnapshot.IDLE,
        listOf(flow(1L, action = TrafficAction.BLOCK, domain = "samba.tv", address = "45.33.33.110")),
        KIN_NOW,
    )
    checkEquals(one.size, 0, "single tracker block stays quiet")
    val nonTracker = OutboundAnomalyEngine().evaluate(
        TrafficSnapshot.IDLE,
        (1L..3L).map { id -> flow(id, action = TrafficAction.BLOCK, domain = "unclassified.example", address = "45.33.33.110") },
        KIN_NOW,
    )
    checkEquals(nonTracker.single().kind, AnomalyKind.REPEATED_BLOCK, "unclassified blocked domain is repeated block only")
}

private fun testC2Match() {
    val index = c2Index("45.33.32.0/24")
    val flows = listOf(
        flow(1L, action = TrafficAction.BLOCK, address = "45.33.32.7", country = "DE"),
        flow(2L, action = TrafficAction.BLOCK, address = "45.33.32.9", country = "DE"),
    )
    val positive = OutboundAnomalyEngine(threatIndex = index).evaluate(TrafficSnapshot.IDLE, flows, KIN_NOW)
    checkEquals(positive.size, 1, "C2 match yields one anomaly")
    val anomaly = positive.single()
    checkEquals(anomaly.kind, AnomalyKind.C2_MATCH, "C2 dominant kind")
    checkEquals(anomaly.signals.single().score, 65, "C2 score")
    checkEquals(anomaly.severity, Severity.HIGH, "C2 severity")
    checkEquals(anomaly.confidence, Confidence.HIGH, "C2 confidence")
    checkEquals(anomaly.countryCode, "DE", "C2 country")
    checkTrue(anomaly.signals.single().detail.contains("feeds=feodo"), "C2 feed detail")
    checkTrue((anomaly.destinationPrefix ?: "").endsWith("/24"), "C2 destination aggregate")

    val withoutIndex = OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, flows, KIN_NOW)
    checkEquals(withoutIndex.size, 0, "without TI index no C2 anomaly")

    val matching = c2Index("45.33.32.0/24", "45.33.33.0/24")
    val mixed = OutboundAnomalyEngine(threatIndex = matching).evaluate(
        TrafficSnapshot.IDLE,
        flows + listOf(flow(3L, action = TrafficAction.BLOCK, address = "45.33.33.44", country = "DE")),
        KIN_NOW,
    )
    checkTrue(mixed.single().signals.first { it.kind == AnomalyKind.C2_MATCH }.count >= 3, "C2 match counts all matching flows")
}

private fun testCorridor() {
    val flows = (1L..2L).map { id ->
        flow(id, country = "RU", address = "45.33.33.120", lastSeen = KIN_NOW - id * 1_000L)
    }
    val anomaly = OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, flows, KIN_NOW).single()
    checkAnomalyInvariants(anomaly, "corridor")
    checkEquals(anomaly.kind, AnomalyKind.HIGH_RISK_CORRIDOR, "corridor kind")
    checkEquals(anomaly.severity, Severity.INFO, "corridor severity INFO")
    checkEquals(anomaly.signals.single().score, 12, "corridor low score")
    checkEquals(anomaly.countryCode, "RU", "corridor country")
    checkEquals(anomaly.destinationPrefix, null, "corridor does not invent a containment target")

    val one = OutboundAnomalyEngine().evaluate(
        TrafficSnapshot.IDLE,
        listOf(flow(1L, country = "CN", address = "45.33.33.121")),
        KIN_NOW,
    )
    checkEquals(one.size, 0, "single corridor flow stays quiet")
}

private fun testCombinedAnomaly() {
    val index = c2Index("45.33.32.0/24")
    val engine = OutboundAnomalyEngine(threatIndex = index)
    val c2Flows = listOf(
        flow(1L, action = TrafficAction.BLOCK, address = "45.33.32.7", country = "DE"),
        flow(2L, action = TrafficAction.BLOCK, address = "45.33.32.9", country = "DE"),
    )
    val blockedFlows = (3L..5L).map { id -> flow(id, action = TrafficAction.BLOCK, address = "45.33.33.130", country = "DE") }
    val dnsFlows = (6L..30L).map { id -> flow(id, domain = "burst.example", address = "45.33.34.50", country = "DE") }
    val anomalies = engine.evaluate(TrafficSnapshot.IDLE, c2Flows + blockedFlows + dnsFlows, KIN_NOW)
    checkEquals(anomalies.size, 1, "combined evidence yields one app anomaly")
    val anomaly = anomalies.single()
    checkAnomalyInvariants(anomaly, "combined")
    checkSignalsSorted(anomaly, "combined")
    checkEquals(anomaly.kind, AnomalyKind.C2_MATCH, "C2 dominates combined anomaly")
    checkTrue(anomaly.signals.size >= 3, "combined anomaly has multiple independent signals")
    checkEquals(anomaly.score, 100, "combined score saturates")
    checkEquals(anomaly.severity, Severity.CRITICAL, "combined severity")
    checkEquals(anomaly.confidence, Confidence.HIGH, "combined confidence")
    checkEquals(anomaly.destinationPrefix, "45.33.32.0/24", "containment-capable destination aggregate")
    val addresses = anomaly.signals.flatMap { AnomalyDetailCodec.destinationAddresses(it.detail) }
    checkTrue(addresses.contains("45.33.32.7") && addresses.contains("45.33.32.9"), "combined detail carries both C2 addresses")

    val policy = ContainmentPolicy(enabled = true, minSignals = 2, minScore = 60)
    val proposals = OutboundContainmentPolicy.propose(listOf(anomaly), policy)
    checkEquals(proposals.size, 1, "combined anomaly yields containment proposal")
    checkEquals(proposals.single().reasonCode, "anomaly_c2_match", "proposal reason code")
    checkEquals(proposals.single().target.value, "45.33.32.0/24", "proposal target")
    checkEquals(proposals.single().proposedTtlMillis, policy.defaultTtlMillis, "proposal default ttl")
    checkEquals(proposals.single().signals, anomaly.signals, "proposal carries signals")
}

private fun testEngineBoundsAndOrdering() {
    val config = AnomalyConfig(maxAnomalies = 2, maxKnownApps = 3, previousWindowMaxApps = 2)
    val flows = ArrayList<TrafficFlow>()
    var id = 1L
    (0 until 10).forEach { appIndex ->
        repeat(25) {
            flows += flow(id++, packageName = "com.app.$appIndex", domain = "burst$appIndex.example", address = "45.33.34.${appIndex + 1}")
        }
    }
    val engine = OutboundAnomalyEngine(config = config)
    val anomalies = engine.evaluate(TrafficSnapshot.IDLE, flows, KIN_NOW)
    checkTrue(anomalies.size <= 2, "anomaly output bounded")
    checkTrue(engine.knownAppCount <= 3, "known app set bounded")
    checkTrue(engine.previousWindowAppCount <= 2, "previous window state bounded")
    checkEquals(engine.knownAppCount, 3, "known app cap reached deterministically")
    anomalies.forEach { anomaly -> checkAnomalyInvariants(anomaly, "bounded") }
    checkEquals(anomalies.map { it.id }.distinct().size, anomalies.size, "anomaly ids unique")
    val expectedOrder = anomalies.sortedWith(
        compareByDescending<OutboundAnomaly> { it.score }.thenByDescending { it.lastSeenMillis }.thenBy { it.id },
    )
    checkEquals(anomalies, expectedOrder, "anomaly ordering deterministic")

    val singleApp = OutboundAnomalyEngine().evaluate(
        TrafficSnapshot.IDLE,
        (1L..25L).map { flowId -> flow(flowId, domain = "one.example") },
        KIN_NOW,
    )
    checkEquals(singleApp.size, 1, "single app produces one anomaly")
    checkEquals(singleApp.single().observationCount, 25, "observation count from flows")
    checkTrue(!singleApp.single().id.startsWith("an-an-"), "anomaly id format")
}

private fun testEngineDeterminismAndReset() {
    val flows = listOf(
        flow(1L, action = TrafficAction.BLOCK, domain = "samba.tv", address = "45.33.33.140"),
        flow(2L, action = TrafficAction.BLOCK, domain = "samba.tv", address = "45.33.33.141"),
        flow(3L, action = TrafficAction.BLOCK, domain = "samba.tv", address = "45.33.33.142"),
    )
    val first = OutboundAnomalyEngine()
    val second = OutboundAnomalyEngine()
    val firstResult = first.evaluate(TrafficSnapshot.IDLE, flows, KIN_NOW)
    val secondResult = second.evaluate(TrafficSnapshot.IDLE, flows, KIN_NOW)
    checkEquals(firstResult, secondResult, "engine deterministic across instances")
    checkEquals(first.evaluate(TrafficSnapshot.IDLE, flows, KIN_NOW), firstResult, "engine deterministic across calls")

    val revisionBefore = first.revision()
    first.evaluate(TrafficSnapshot.IDLE, flows, KIN_NOW)
    checkTrue(first.revision() > revisionBefore, "revision advances per evaluation")
    checkTrue(first.knownAppCount > 0, "known apps tracked")
    val revisionBeforeReset = first.revision()
    first.reset()
    checkEquals(first.knownAppCount, 0, "reset clears known apps")
    checkEquals(first.previousWindowAppCount, 0, "reset clears previous window state")
    checkTrue(first.revision() > revisionBeforeReset, "reset advances revision")
}

private fun testEngineWindowsAndConfig() {
    val oldFlows = listOf(
        flow(
            1L,
            action = TrafficAction.BLOCK,
            domain = "samba.tv",
            openedAt = KIN_NOW - 3_700_000L,
            lastSeen = KIN_NOW - 3_600_000L,
        ),
    )
    checkEquals(OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, oldFlows, KIN_NOW).size, 0, "flows outside window ignored")
    val futureFlows = listOf(flow(1L, action = TrafficAction.BLOCK, domain = "samba.tv", lastSeen = KIN_NOW + MINUTE))
    checkEquals(OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, futureFlows, KIN_NOW).size, 0, "future flows ignored")
    checkEquals(OutboundAnomalyEngine().evaluate(TrafficSnapshot.IDLE, emptyList(), KIN_NOW).size, 0, "empty flow list quiet")

    checkThrows<IllegalArgumentException>("invalid DNS window") { AnomalyConfig(dnsBurstWindowMillis = 0L) }
    checkThrows<IllegalArgumentException>("invalid DNS threshold") { AnomalyConfig(dnsBurstThreshold = 0) }
    checkThrows<IllegalArgumentException>("invalid jitter fraction") { AnomalyConfig(beaconMaxJitterFraction = 2.0) }
    checkThrows<IllegalArgumentException>("invalid anomaly bound") { AnomalyConfig(maxAnomalies = 0) }
    checkThrows<IllegalArgumentException>("invalid volume ratio") { AnomalyConfig(volumeRatio = 0.5) }
    checkThrows<IllegalArgumentException>("invalid known app bound") { AnomalyConfig(maxKnownApps = 0) }
    checkTrue(AnomalyConfig.DEFAULT.maxAnomalies == 32, "default anomaly bound")
    checkTrue(AnomalyConfig.DEFAULT.beaconMinFlows == 6, "default beacon flow count")
    checkTrue(AnomalyConfig.DEFAULT.dnsBurstThreshold == 25, "default DNS threshold")
}

// --- containment proposal tests ----------------------------------------------------------------

private fun testProposalGuardrails() {
    val enabled = ContainmentPolicy(enabled = true)
    checkEquals(OutboundContainmentPolicy.propose(listOf(anomaly()), ContainmentPolicy()), emptyList<ContainmentProposal>(), "default policy is observe-only")
    checkEquals(OutboundContainmentPolicy.propose(listOf(anomaly()), enabled).size, 1, "enabled policy proposes")

    val lowScore = anomaly(score = 40)
    checkEquals(OutboundContainmentPolicy.propose(listOf(lowScore), enabled).size, 0, "low score rejected")
    val singleKind = anomaly(
        signals = listOf(
            signal(AnomalyKind.C2_MATCH, "x", 60, 1),
            signal(AnomalyKind.C2_MATCH, "y", 60, 1),
        ),
    )
    checkEquals(OutboundContainmentPolicy.propose(listOf(singleKind), enabled).size, 0, "duplicate signal kinds are not independent")
    val singleSignal = anomaly(signals = listOf(signal(AnomalyKind.C2_MATCH, "x", 60, 1)))
    checkEquals(OutboundContainmentPolicy.propose(listOf(singleSignal), enabled).size, 0, "one signal cannot contain")
    val noPrefix = anomaly(destinationPrefix = null)
    checkEquals(OutboundContainmentPolicy.propose(listOf(noPrefix), enabled).size, 0, "no destination aggregation rejected")
    val protectedPackage = anomaly(packageName = "com.android.settings")
    checkEquals(OutboundContainmentPolicy.propose(listOf(protectedPackage), enabled).size, 0, "protected package rejected")
    val ownPackage = anomaly(packageName = "de.visiongaia.gedefense.tv")
    checkEquals(OutboundContainmentPolicy.propose(listOf(ownPackage), enabled).size, 0, "own app protected")
    val unknownPackage = anomaly(packageName = null)
    checkEquals(OutboundContainmentPolicy.propose(listOf(unknownPackage), enabled).size, 0, "unknown package rejected")
}

private fun testProposalAllowlistGates() {
    val enabled = ContainmentPolicy(enabled = true)
    val allowlisted = anomaly(
        destinationPrefix = "142.250.4.0/24",
        signals = defaultSignals(listOf("142.250.4.7", "142.250.4.9")),
    )
    checkEquals(OutboundContainmentPolicy.propose(listOf(allowlisted), enabled).size, 0, "policy allowlist blocks Google CDN range")
    checkEquals(
        OutboundContainmentPolicy.propose(listOf(anomaly()), enabled, allowlistCheck = { true }).size,
        0,
        "caller allowlist check blocks proposal",
    )
    checkEquals(
        OutboundContainmentPolicy.propose(listOf(anomaly()), enabled, allowlistCheck = { prefix -> prefix == "45.33.32.0/24" }).size,
        0,
        "caller allowlist check receives canonical target",
    )
    val allowedCustom = ContainmentPolicy(enabled = true, allowlistedPrefixes = emptySet())
    checkEquals(OutboundContainmentPolicy.propose(listOf(allowlisted), allowedCustom).size, 1, "custom policy can allow CDN range")
    checkEquals(
        OutboundContainmentPolicy.propose(listOf(anomaly()), enabled, allowlistCheck = { prefix -> prefix.endsWith("/24") }).size,
        0,
        "caller allowlist predicate used verbatim",
    )
}

private fun testProposalAggregation() {
    val enabled = ContainmentPolicy(enabled = true)
    val singleAddress = anomaly(signals = defaultSignals(listOf("45.33.32.7")))
    checkEquals(OutboundContainmentPolicy.propose(listOf(singleAddress), enabled).size, 0, "single destination IP rejected")

    val fromHostPrefix = anomaly(
        destinationPrefix = "45.33.32.7/32",
        signals = defaultSignals(listOf("45.33.32.7", "45.33.32.9")),
    )
    val proposals = OutboundContainmentPolicy.propose(listOf(fromHostPrefix), enabled)
    checkEquals(proposals.size, 1, "host prefix aggregated to /24")
    checkEquals(proposals.single().target.value, "45.33.32.0/24", "IPv4 target is /24")

    val v6 = anomaly(
        destinationPrefix = "2606:4700:4700::1/128",
        signals = defaultSignals(listOf("2606:4700:4700::1", "2606:4700:4700::2")),
    )
    val v6Proposals = OutboundContainmentPolicy.propose(listOf(v6), enabled)
    checkEquals(v6Proposals.size, 1, "IPv6 containment proposal")
    checkEquals(v6Proposals.single().target.value, "2606:4700:4700::/64", "IPv6 target is /64")
    val twoAddressesOutsideTarget = anomaly(
        destinationPrefix = "45.33.32.0/24",
        signals = defaultSignals(listOf("45.33.33.7", "45.33.33.9")),
    )
    checkEquals(OutboundContainmentPolicy.propose(listOf(twoAddressesOutsideTarget), enabled).size, 0, "addresses outside target rejected")

    val overlapping = listOf(
        anomaly(id = "an-a", destinationPrefix = "45.33.32.0/24"),
        anomaly(id = "an-b", destinationPrefix = "45.33.32.128/25"),
    )
    checkEquals(OutboundContainmentPolicy.propose(overlapping, enabled).size, 1, "overlapping targets deduplicated")
}

private fun testProposalCountryAndDeterminism() {
    val enabled = ContainmentPolicy(enabled = true)
    val unknownCountry = anomaly(countryCode = "ZZ")
    checkEquals(OutboundContainmentPolicy.propose(listOf(unknownCountry), enabled).size, 0, "unknown country rejected by default")
    val relaxed = ContainmentPolicy(enabled = true, requireKnownCountry = false)
    checkEquals(OutboundContainmentPolicy.propose(listOf(unknownCountry), relaxed).size, 1, "unknown country allowed when policy relaxes")
    val nullCountry = anomaly(countryCode = null)
    checkEquals(OutboundContainmentPolicy.propose(listOf(nullCountry), enabled).size, 0, "null country rejected by default")

    val anomalies = listOf(anomaly(id = "an-b"), anomaly(id = "an-a"))
    val first = OutboundContainmentPolicy.propose(anomalies, enabled)
    val second = OutboundContainmentPolicy.propose(anomalies, enabled)
    checkEquals(first, second, "proposal output deterministic")
    checkEquals(first.size, 1, "overlapping anomalies collapse to one proposal")
    checkTrue(first.single().id.startsWith("prp-"), "proposal id prefix")
    checkTrue(first.single().proposedTtlMillis in ContainmentProposal.MIN_TTL_MILLIS..ContainmentProposal.MAX_TTL_MILLIS, "proposal ttl in bounds")

    val corridorOnly = anomaly(
        score = 12,
        kind = AnomalyKind.HIGH_RISK_CORRIDOR,
        destinationPrefix = null,
        signals = listOf(signal(AnomalyKind.HIGH_RISK_CORRIDOR, "countries=RU;flows=2", 12, 2)),
    )
    checkEquals(OutboundContainmentPolicy.propose(listOf(corridorOnly), ContainmentPolicy(enabled = true, minScore = 0)).size, 0, "corridor never contains by itself")
    checkEquals(OutboundContainmentPolicy.aggregationTarget("not-a-prefix"), null, "invalid aggregation input")
    checkEquals(OutboundContainmentPolicy.aggregationTarget("45.33.32.7/32")?.value, "45.33.32.0/24", "aggregation helper")
    checkEquals(OutboundContainmentPolicy.reasonCode(AnomalyKind.C2_MATCH), "anomaly_c2_match", "reason code C2")
    checkEquals(OutboundContainmentPolicy.reasonCode(AnomalyKind.DNS_BURST), "anomaly_dns_burst", "reason code DNS")
    AnomalyKind.entries.forEach { kind ->
        checkTrue(OutboundContainmentPolicy.reasonCode(kind).startsWith("anomaly_"), "reason code stable for $kind")
    }
}

// --- registry tests ----------------------------------------------------------------------------

private fun testRegistryApply() {
    val disabled = ContainmentRegistry()
    checkEquals(disabled.apply(proposal()), null, "disabled registry rejects apply")

    val clock = KineticClock()
    val registry = ContainmentRegistry(ContainmentPolicy(enabled = true), clock::read)
    val created = registry.apply(proposal())
    checkTrue(created != null, "enabled registry applies proposal")
    val record = created!!
    checkTrue(record.id.startsWith("cnt-"), "record id prefix")
    checkTrue(record.id.length <= 128, "record id length")
    checkEquals(record.state, ContainmentState.ACTIVE, "record state active")
    checkEquals(record.origin, ContainmentOrigin.AUTO, "record origin auto")
    checkEquals(record.createdAtMillis, clock.now, "record creation time")
    checkEquals(record.expiresAtMillis, clock.now + record.remainingMillis, "record expiry derived")
    checkEquals(record.remainingMillis, 10L * MINUTE, "record ttl")
    checkTrue(record.signals.size >= 2, "record signals")
    checkEquals(registry.active().size, 1, "one active record")
    checkTrue(registry.isActive(record.target), "target active")
    checkEquals(registry.apply(proposal()), null, "same proposal duplicate rejected")

    val clampRegistry = ContainmentRegistry(
        ContainmentPolicy(enabled = true, defaultTtlMillis = 5L * MINUTE, maxTtlMillis = 5L * MINUTE),
        clock::read,
    )
    val clamped = clampRegistry.apply(proposal(ttl = 20L * MINUTE))
    checkTrue(clamped != null, "ttl clamp apply accepted")
    checkEquals(clamped!!.remainingMillis, 5L * MINUTE, "ttl clamped to policy maximum")

    val maxActiveRegistry = ContainmentRegistry(ContainmentPolicy(enabled = true, maxActive = 1), clock::read)
    checkTrue(maxActiveRegistry.apply(proposal(target = "45.33.32.0/24")) != null, "first active accepted")
    checkEquals(maxActiveRegistry.apply(proposal(target = "45.33.33.0/24")), null, "max active enforced")

    val overlapRegistry = ContainmentRegistry(ContainmentPolicy(enabled = true), clock::read)
    checkTrue(overlapRegistry.apply(proposal(target = "45.33.32.0/24")) != null, "overlap base accepted")
    checkEquals(overlapRegistry.apply(proposal(target = "45.33.32.128/25")), null, "overlapping target rejected")
}

private fun testRegistryLifecycle() {
    val clock = KineticClock()
    val registry = ContainmentRegistry(ContainmentPolicy(enabled = true), clock::read)
    val record = registry.apply(proposal(ttl = 60_000L))!!
    checkEquals(registry.release(record.id), true, "release succeeds")
    checkEquals(registry.active().size, 0, "released record inactive")
    checkEquals(registry.release(record.id), false, "double release rejected")
    val released = registry.all().single()
    checkEquals(released.state, ContainmentState.RELEASED, "released state stored")
    checkTrue(released.releasedAtMillis != null, "release timestamp present")
    checkEquals(registry.isActive(record.target), false, "released target inactive")

    val expiryRegistry = ContainmentRegistry(ContainmentPolicy(enabled = true, defaultTtlMillis = 60_000L), clock::read)
    val expiring = expiryRegistry.apply(proposal(ttl = 60_000L))!!
    clock.now += 61_000L
    val expired = expiryRegistry.expire()
    checkEquals(expired.size, 1, "expire returns elapsed record")
    checkEquals(expired.single().id, expiring.id, "expired id")
    checkEquals(expired.single().state, ContainmentState.EXPIRED, "expired state")
    checkEquals(expiryRegistry.active().size, 0, "expired record inactive")
    checkEquals(expiryRegistry.isActive(expiring.target), false, "expired target inactive")
    checkEquals(expiryRegistry.expire().size, 0, "expire idempotent")

    val clearRegistry = ContainmentRegistry(ContainmentPolicy(enabled = true), clock::read)
    clearRegistry.apply(proposal(target = "45.33.32.0/24"))
    clearRegistry.clear()
    checkEquals(clearRegistry.all().size, 0, "clear removes records")
}

private fun testRegistryBoundsAndRevision() {
    val clock = KineticClock()
    val registry = ContainmentRegistry(ContainmentPolicy(enabled = true, maxActive = 16), clock::read)
    val initialRevision = registry.revision()
    (0 until 100).forEach { index ->
        val target = "203.0.${index}.0/24"
        val record = registry.apply(proposal(target = target))
        checkTrue(record != null, "apply record $index")
        checkTrue(registry.all().size <= ContainmentRegistry.MAX_RECORDS, "record bound at $index")
        checkTrue(registry.active().size <= 16, "active bound at $index")
        checkEquals(registry.release(record!!.id), true, "release record $index")
    }
    checkTrue(registry.revision() > initialRevision, "revision advanced")
    checkEquals(registry.all(0).size, 0, "history limit zero")
    checkTrue(registry.all(10).size <= 10, "history limit applied")
    checkTrue(registry.all(10).size <= ContainmentRegistry.MAX_RECORDS, "history bounded")

    val ordering = ContainmentRegistry(ContainmentPolicy(enabled = true, maxActive = 16), clock::read)
    val first = ordering.apply(proposal(target = "45.33.32.0/24"))!!
    clock.now += 1_000L
    val second = ordering.apply(proposal(target = "45.33.33.0/24"))!!
    checkEquals(ordering.active().map { it.id }, listOf(first.id, second.id), "active ordering oldest first")
    checkEquals(ordering.all(2).map { it.id }, listOf(second.id, first.id), "history newest first")

    val overlapRegistry = ContainmentRegistry(ContainmentPolicy(enabled = true), clock::read)
    val active = overlapRegistry.apply(proposal(target = "45.33.32.0/24"))!!
    checkTrue(overlapRegistry.isActive(ContainmentTarget(ContainmentTargetType.DESTINATION_PREFIX, "45.33.32.128/25")), "overlap active")
    checkTrue(!overlapRegistry.isActive(ContainmentTarget(ContainmentTargetType.DESTINATION_PREFIX, "45.33.33.0/24")), "different target inactive")
    checkTrue(active.remainingMillis > 0L, "record remaining positive")
}

// --- composeThreatIndex tests ------------------------------------------------------------------

private fun testComposeEmptyBase() {
    val active = listOf(record("45.33.32.0/24"))
    val composed = composeThreatIndex(ThreatIndex.empty(), active)
    checkEquals(composed.routePrefixes.size, 1, "one synthetic route prefix")
    checkEquals(composed.routePrefixes.single(), IpPrefix.parse("45.33.32.0/24"), "synthetic route prefix value")
    checkEquals(composed.routeOverflow, false, "no route overflow")
    val match = composed.match("45.33.32.7")
    checkTrue(match != null, "synthetic prefix matches address")
    checkTrue(match!!.hasBlockingSignal, "synthetic match blocks")
    checkTrue(match.feeds.any { it.id == "spamhaus-drop-v4" }, "synthetic uses ROUTE_BLOCK feed")
    checkEquals(composed.routePolicySha256.length, 64, "route policy hash length")
    val expected = composeThreatIndex(ThreatIndex.empty(), active)
    checkEquals(composed.routePolicySha256, expected.routePolicySha256, "compose deterministic")
    checkEquals(composed.fullPolicySha256, expected.fullPolicySha256, "compose full hash deterministic")

    val duplicate = listOf(record("45.33.32.0/24"), record("45.33.32.0/24", id = "cnt-other"))
    checkEquals(composeThreatIndex(ThreatIndex.empty(), duplicate).routePrefixes.size, 1, "duplicate targets deduplicated")
}

private fun testComposePreservesBase() {
    val base = ThreatIndex.build(
        listOf(
            ThreatRecord("cins", IpPrefix.parse("45.33.33.0/24")!!),
            ThreatRecord("tor-exits", IpPrefix.parse("45.33.34.0/24")!!),
            ThreatRecord("feodo", IpPrefix.parse("45.33.32.0/24")!!),
        ),
    )
    val composed = composeThreatIndex(base, emptyList())
    checkEquals(composed.fullPolicySha256, base.fullPolicySha256, "base full policy preserved")
    checkEquals(composed.routePolicySha256, base.routePolicySha256, "base route policy preserved")
    checkEquals(composed.count, base.count, "base record count preserved")
    val correlate = composed.match("45.33.33.7")
    checkTrue(correlate != null, "correlate record preserved")
    checkTrue(correlate!!.feeds.any { it.id == "cins" }, "correlate feed preserved")
    checkTrue(!correlate.hasBlockingSignal, "correlate feed does not block")
    val annotate = composed.match("45.33.34.9")
    checkTrue(annotate != null && annotate.feeds.any { it.id == "tor-exits" }, "annotate feed preserved")

    val withContainment = composeThreatIndex(base, listOf(record("45.33.32.0/24")))
    val blocked = withContainment.match("45.33.32.7")
    checkTrue(blocked != null && blocked.hasBlockingSignal, "synthetic containment blocks")
    checkTrue(withContainment.fullPolicySha256 != base.fullPolicySha256, "containment changes full policy")
    checkEquals(composed.fullPolicySha256, base.fullPolicySha256, "empty active list leaves base unchanged")

    checkEquals(composeThreatIndex(base, listOf(record("45.33.32.0/24", state = ContainmentState.RELEASED))).fullPolicySha256, base.fullPolicySha256, "released record ignored")
    checkEquals(composeThreatIndex(base, listOf(record("45.33.32.0/24", state = ContainmentState.EXPIRED))).fullPolicySha256, base.fullPolicySha256, "expired record ignored")
}

private fun testComposeV6AndDeterminism() {
    val v6Base = composeThreatIndex(ThreatIndex.empty(), listOf(record("2606:4700:4700::/64")))
    checkEquals(v6Base.routePrefixes.single().family, 6, "IPv6 synthetic route family")
    val v6Match = v6Base.match("2606:4700:4700::2")
    checkTrue(v6Match != null && v6Match.hasBlockingSignal, "IPv6 containment blocks")
    checkTrue(v6Match!!.feeds.any { it.id == "spamhaus-drop-v6" }, "IPv6 synthetic feed")

    val base = ThreatIndex.build(listOf(ThreatRecord("cins", IpPrefix.parse("45.33.33.0/24")!!)))
    val records = (0 until 100).map { index ->
        record(target = "45.33.${index * 2}.0/24", id = "cnt-bounded-$index")
    }
    val forward = composeThreatIndex(base, records)
    val reversed = composeThreatIndex(base, records.reversed())
    checkEquals(forward.routePolicySha256, reversed.routePolicySha256, "compose order independent")
    checkEquals(forward.fullPolicySha256, reversed.fullPolicySha256, "compose order independent full hash")
    checkTrue(forward.routePrefixes.size <= 64, "synthetic prefix cap")
    checkEquals(forward.routePrefixes.size, 64, "synthetic cap applied")
    forward.routePrefixes.take(20).forEachIndexed { index, prefix ->
        checkTrue(forward.match(prefix.toInetAddress().hostAddress)?.hasBlockingSignal == true, "synthetic prefix $index blocks")
    }
}

// --- source/build checks -----------------------------------------------------------------------

private fun testSourceAndBuildChecks() {
    val anomalyRoot = File("src/main/kotlin/de/visiongaia/gedefense/tv/core/anomaly")
    checkTrue(anomalyRoot.isDirectory, "anomaly source directory exists")
    val sourceFiles = anomalyRoot.walkTopDown().filter { file -> file.isFile && file.extension == "kt" }.toList()
    checkTrue(sourceFiles.size >= 4, "anomaly source files present (${sourceFiles.size})")
    sourceFiles.forEach { file ->
        file.readLines().forEachIndexed { index, line ->
            val trimmed = line.trimStart()
            checkTrue(!trimmed.startsWith("import android"), "no Android import in ${file.name}:${index + 1}")
            checkTrue(!trimmed.contains("android.content") && !trimmed.contains("android.app"), "no Android API in ${file.name}:${index + 1}")
        }
    }
    val buildFile = File("build.gradle.kts")
    checkTrue(buildFile.isFile, "build file present")
    val buildText = buildFile.readText()
    checkTrue(buildText.contains("tvKineticCheck"), "kinetic verification task registered")
    checkTrue(buildText.contains("tvV2Check"), "V2 task preserved")
    checkTrue(buildText.contains("tvCoreCheck"), "V1 task preserved")
    checkTrue(buildText.contains("""implementation(project(":core"))"""), "vendored core dependency preserved")

    AnomalyKind.entries.forEach { kind ->
        checkTrue(kind.name.isNotEmpty(), "anomaly kind name $kind")
    }
    checkTrue(AnomalyDetailCodec.encode(listOf("45.33.32.7", "45.33.32.9", "45.33.32.11")).length <= 160, "detail bounded")
    checkEquals(
        AnomalyDetailCodec.destinationAddresses(AnomalyDetailCodec.encode(listOf("45.33.32.7", "45.33.32.9"))),
        listOf("45.33.32.7", "45.33.32.9"),
        "detail codec roundtrip",
    )
    checkEquals(AnomalyDetailCodec.destinationAddresses("no-marker"), emptyList<String>(), "detail codec tolerates missing marker")
    checkEquals(AnomalyDetailCodec.encode(listOf("not-an-ip")), "dst=", "invalid address ignored")
}
