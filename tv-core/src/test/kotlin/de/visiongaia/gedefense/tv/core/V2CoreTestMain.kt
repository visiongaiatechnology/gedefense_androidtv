package de.visiongaia.gedefense.tv.core

import de.visiongaia.gedefense.mobile.core.IpPrefix
import de.visiongaia.gedefense.mobile.core.PrivacyBreakageRisk
import de.visiongaia.gedefense.mobile.core.PrivacyCategory
import de.visiongaia.gedefense.mobile.core.PrivacyConfidence
import de.visiongaia.gedefense.mobile.core.PrivacyIntelligenceRegistry
import de.visiongaia.gedefense.mobile.core.PrivacyProfile
import de.visiongaia.gedefense.mobile.core.PrivacyProvenance
import de.visiongaia.gedefense.mobile.core.PrivacyRule
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.mobile.core.ThreatRecord
import de.visiongaia.gedefense.tv.core.geo.CountryCentroids
import de.visiongaia.gedefense.tv.core.geo.GeoLookup
import de.visiongaia.gedefense.tv.core.geo.GeoPrefixEntry
import de.visiongaia.gedefense.tv.core.geo.PrefixTableGeoLookup
import de.visiongaia.gedefense.tv.core.geo.countryCodeOrUnknown
import de.visiongaia.gedefense.tv.core.model.CollectorCategory
import de.visiongaia.gedefense.tv.core.model.Confidence
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.EvidenceRef
import de.visiongaia.gedefense.tv.core.model.PolicyAction
import de.visiongaia.gedefense.tv.core.model.TrafficAction
import de.visiongaia.gedefense.tv.core.model.TrafficFlow
import de.visiongaia.gedefense.tv.core.model.TrafficSnapshot
import de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile
import de.visiongaia.gedefense.tv.core.policy.TrafficMatchSource
import de.visiongaia.gedefense.tv.core.policy.TrafficPolicy
import de.visiongaia.gedefense.tv.core.policy.TrafficPolicyRequest
import de.visiongaia.gedefense.tv.core.policy.TrackerCatalog
import de.visiongaia.gedefense.tv.core.policy.TrackerCategory
import de.visiongaia.gedefense.tv.core.policy.TrackerRule
import de.visiongaia.gedefense.tv.core.policy.toPrivacyProfile
import de.visiongaia.gedefense.tv.core.policy.toTrackerCategory
import de.visiongaia.gedefense.tv.core.text.DeCatalog
import de.visiongaia.gedefense.tv.core.traffic.TrafficAggregator
import de.visiongaia.gedefense.tv.core.traffic.TrafficCaps
import de.visiongaia.gedefense.tv.core.xdr.TvXdrEngine
import de.visiongaia.gedefense.tv.core.xdr.XdrConfig
import de.visiongaia.gedefense.tv.core.xdr.XdrIncident
import de.visiongaia.gedefense.tv.core.xdr.XdrSignalKind
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess

// --- tiny assertion harness (same counters/wording convention as TvCoreTestMain) ----------------

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

private fun checkEquals(actual: Any?, expected: Any?, message: String) {
    check(actual == expected, "$message (expected=$expected actual=$actual)")
}

private fun checkTrue(condition: Boolean, message: String) {
    check(condition, message)
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
    test("geo: country centroids table", ::testCountryCentroids)
    test("geo: prefix lookup, longest match and UNKNOWN", ::testGeoLookup)
    test("policy: threat-intel mapping", ::testPolicyThreatIntel)
    test("policy: privacy registry mapping and profiles", ::testPolicyPrivacy)
    test("policy: essential privacy rule wins and TI precedence", ::testPolicyEssentialAndPrecedence)
    test("policy: curated tracker categories per profile", ::testPolicyTrackerProfiles)
    test("policy: custom C2 tracker entry, no-signal and determinism", ::testPolicyC2AndNoSignal)
    test("aggregator: open/update/close accounting", ::testAggregatorAccounting)
    test("aggregator: unknown geo is honest", ::testAggregatorUnknownGeo)
    test("aggregator: blocked flow accounting", ::testAggregatorBlocked)
    test("aggregator: action counters", ::testAggregatorActionCounters)
    test("aggregator: active flow, app and history caps", ::testAggregatorFlowAppHistoryCaps)
    test("aggregator: country and domain caps with deterministic top-N", ::testAggregatorCountryDomainCaps)
    test("aggregator: reset, clearSession, stop and flow limits", ::testAggregatorLifecycle)
    test("aggregator: concurrent producers remain consistent", ::testAggregatorConcurrent)
    test("xdr: repeated blocked flows positive and negative", ::testXdrRepeated)
    test("xdr: blocked tracker category", ::testXdrTracker)
    test("xdr: C2 threat-intel match", ::testXdrC2)
    test("xdr: high-risk corridor is INFO only", ::testXdrCorridor)
    test("xdr: correlation with explainable score", ::testXdrCorrelation)
    test("xdr: dedupe window suppresses repeats", ::testXdrDedupe)
    test("xdr: new app first-seen signal", ::testXdrNewApp)
    test("xdr: bounded memory, window and incident caps", ::testXdrBounds)
    test("xdr: toFinding mapping and catalog coverage", ::testXdrFinding)
    test("xdr: deterministic evaluation", ::testXdrDeterminism)
    test("config: caps and XDR configuration validation", ::testConfigValidation)
    test("source: no Android imports and no external dependencies", ::testNoAndroidImports)
    test("catalog: XDR message keys are complete", ::testCatalogXdrKeys)
}

// --- fixtures ----------------------------------------------------------------------------------

private const val MINUTE = 60_000L
private const val XDR_NOW = 1_700_000_000_000L

private class MutableClock(var now: Long = 1_700_000_000_000L) {
    fun read(): Long = now
}

private fun threatIndex(): ThreatIndex = ThreatIndex.build(
    listOf(
        ThreatRecord("feodo", IpPrefix.parse("203.0.113.7/32")!!),
        ThreatRecord("cins", IpPrefix.parse("198.51.100.7/32")!!),
        ThreatRecord("tor-exits", IpPrefix.parse("192.0.2.55/32")!!),
    ),
)

private fun geoTable(): PrefixTableGeoLookup = PrefixTableGeoLookup.build(
    listOfNotNull(
        GeoPrefixEntry.parse("203.0.113.0/24", "DE"),
        GeoPrefixEntry.parse("203.0.113.128/25", "FR"),
        GeoPrefixEntry.parse("198.51.100.0/24", "US"),
        GeoPrefixEntry.parse("2001:db8::/32", "JP"),
    ),
)

private fun privacyProvenance(): PrivacyProvenance = PrivacyProvenance(
    sourceId = "test-source",
    sourceUrl = "https://example.org/privacy-rules.json",
    licenseId = "CC0-1.0",
    observedAt = "2026-10-01",
)

private fun privacyRule(
    id: String,
    domain: String,
    category: PrivacyCategory,
    confidence: PrivacyConfidence,
    breakageRisk: PrivacyBreakageRisk = PrivacyBreakageRisk.LOW,
    essential: Boolean = false,
): PrivacyRule = PrivacyRule(
    id = id,
    domain = domain,
    includeSubdomains = true,
    category = category,
    confidence = confidence,
    breakageRisk = breakageRisk,
    essential = essential,
    provenance = privacyProvenance(),
)

private fun privacyRegistry(): PrivacyIntelligenceRegistry = PrivacyIntelligenceRegistry.build(
    listOf(
        privacyRule("ads-observe", "ads.example.org", PrivacyCategory.ADS, PrivacyConfidence.MEDIUM),
        privacyRule("analytics-balanced", "track.example.net", PrivacyCategory.ANALYTICS, PrivacyConfidence.MEDIUM),
        privacyRule("strict-high-breakage", "strict.example.net", PrivacyCategory.ANALYTICS, PrivacyConfidence.MEDIUM, PrivacyBreakageRisk.HIGH),
        privacyRule("essential-update", "samba.tv", PrivacyCategory.ESSENTIAL_UPDATE, PrivacyConfidence.HIGH, essential = true),
    ),
)

private fun xdrFlow(
    id: Long,
    packageName: String,
    action: TrafficAction,
    domain: String? = null,
    country: String? = null,
    address: String = "198.51.100.20",
    openedAt: Long = XDR_NOW - 2_000L,
    lastSeen: Long = XDR_NOW - 1_000L,
    txBytes: Long = 10L,
    rxBytes: Long = 20L,
): TrafficFlow = TrafficFlow(
    id = id,
    ownerPackage = packageName,
    ownerLabel = packageName,
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

private fun primeKnownApp(engine: TvXdrEngine, packageName: String, nowMillis: Long) {
    engine.evaluate(
        TrafficSnapshot.IDLE,
        listOf(xdrFlow(9_000L, packageName, TrafficAction.ALLOW, openedAt = nowMillis - 3_000L, lastSeen = nowMillis - 2_500L)),
        nowMillis,
    )
}

// --- geo tests ---------------------------------------------------------------------------------

private fun testCountryCentroids() {
    checkTrue(CountryCentroids.size >= 200, "centroid table is substantial (${CountryCentroids.size})")
    checkTrue(CountryCentroids.codes.all { it.matches(Regex("[A-Z]{2}")) }, "centroid codes are ISO alpha-2")
    val germany = CountryCentroids.lookup("DE")
    checkTrue(germany != null, "DE anchor present")
    checkEquals(germany?.latitude, 51.0, "DE latitude")
    checkEquals(germany?.longitude, 9.0, "DE longitude")
    checkTrue(CountryCentroids.lookup("de") != null, "lowercase lookup normalised")
    checkTrue(CountryCentroids.lookup(" us ") != null, "whitespace lookup normalised")
    checkEquals(CountryCentroids.lookup("ZZ"), null, "unknown code returns null")
    checkEquals(CountryCentroids.lookup(null), null, "null code returns null")
    checkEquals(CountryCentroids.lookup("DEU"), null, "three letter code rejected")
    CountryCentroids.codes.forEach { code ->
        val point = CountryCentroids.lookup(code) ?: throw AssertionError("missing anchor for $code")
        checkTrue(point.latitude in -90.0..90.0 && point.longitude in -180.0..180.0, "valid anchor for $code")
    }
}

private fun testGeoLookup() {
    val table = geoTable()
    checkEquals(table.size, 4, "table size")
    checkEquals(table.countryCode("203.0.113.7"), "DE", "IPv4 /24 match")
    checkEquals(table.countryCode("203.0.113.200"), "FR", "longest prefix wins")
    checkEquals(table.countryCode("198.51.100.44"), "US", "second IPv4 range")
    checkEquals(table.countryCode("2001:db8::1"), "JP", "IPv6 match")
    checkEquals(table.countryCode("2001:db9::1"), null, "IPv6 outside table is unknown")
    checkEquals(table.countryCode("192.0.2.1"), null, "unmapped IPv4 is unknown")
    checkEquals(table.countryCode("not-an-ip"), null, "invalid address is unknown")
    checkEquals(table.countryCode(""), null, "empty address is unknown")
    checkEquals(table.countryCode("203.0.113.7"), table.countryCode("203.0.113.7"), "lookup deterministic")

    checkEquals(GeoLookup.NONE.countryCode("203.0.113.7"), null, "NONE lookup is honest")
    checkEquals(GeoLookup.NONE.countryCodeOrUnknown("203.0.113.7"), "ZZ", "unknown country code")
    checkEquals(GeoLookup.NONE.countryCodeOrUnknown("203.0.113.7"), GeoLookup.UNKNOWN_COUNTRY, "unknown constant")

    checkEquals(GeoPrefixEntry.parse("203.0.113.0/24", "de")?.countryCode, "DE", "entry country normalised")
    checkEquals(GeoPrefixEntry.parse("not-a-prefix", "DE"), null, "invalid prefix rejected")
    checkEquals(GeoPrefixEntry.parse("203.0.113.0/24", "DEU"), null, "invalid country rejected")

    checkThrows<IllegalArgumentException>("conflicting duplicate prefix rejected") {
        PrefixTableGeoLookup.build(
            listOf(
                GeoPrefixEntry.parse("203.0.113.0/24", "DE")!!,
                GeoPrefixEntry.parse("203.0.113.0/24", "FR")!!,
            ),
        )
    }
    checkThrows<IllegalArgumentException>("geo entry cap enforced") {
        PrefixTableGeoLookup.build(
            listOf(
                GeoPrefixEntry.parse("203.0.113.0/24", "DE")!!,
                GeoPrefixEntry.parse("198.51.100.0/24", "US")!!,
            ),
            maxEntries = 1,
        )
    }
    val duplicateSameCountry = PrefixTableGeoLookup.build(
        listOf(
            GeoPrefixEntry.parse("203.0.113.0/24", "DE")!!,
            GeoPrefixEntry.parse("203.0.113.0/24", "DE")!!,
        ),
    )
    checkEquals(duplicateSameCountry.size, 1, "identical duplicate collapses")
    checkEquals(duplicateSameCountry.countryCode("203.0.113.9"), "DE", "collapsed duplicate still resolves")
}

// --- policy tests ------------------------------------------------------------------------------

private fun testPolicyThreatIntel() {
    val policy = TrafficPolicy(threatIndex = threatIndex())
    val block = policy.evaluate(TrafficPolicyRequest(destinationAddress = "203.0.113.7", profile = TvPrivacyProfile.BALANCED))
    checkEquals(block.action, TrafficAction.BLOCK, "TI route-block blocks")
    checkEquals(block.source, TrafficMatchSource.THREAT_INTEL, "TI source")
    checkEquals(block.reasonCode, TrafficPolicy.REASON_TI_BLOCK, "TI block reason")
    checkEquals(block.category, TrackerCategory.C2, "malicious C2 feed maps to C2 category")
    checkEquals(block.confidence, Confidence.HIGH, "TI block confidence")
    checkTrue(block.ruleId.startsWith("ti.feodo"), "TI rule id names blocking feed (${block.ruleId})")

    val correlate = policy.evaluate(TrafficPolicyRequest(destinationAddress = "198.51.100.7"))
    checkEquals(correlate.action, TrafficAction.CORRELATE, "TI correlate-only maps to CORRELATE")
    checkEquals(correlate.reasonCode, TrafficPolicy.REASON_TI_CORRELATE, "TI correlate reason")
    checkEquals(correlate.confidence, Confidence.MEDIUM, "TI correlate confidence")
    checkEquals(correlate.category, null, "non-C2 TI has no tracker category")

    val annotate = policy.evaluate(TrafficPolicyRequest(destinationAddress = "192.0.2.55"))
    checkEquals(annotate.action, TrafficAction.ANNOTATE, "TI annotate-only maps to ANNOTATE")
    checkEquals(annotate.reasonCode, TrafficPolicy.REASON_TI_ANNOTATE, "TI annotate reason")

    val unmatched = policy.evaluate(TrafficPolicyRequest(destinationAddress = "192.0.2.200", profile = TvPrivacyProfile.STRICT))
    checkEquals(unmatched.action, TrafficAction.ALLOW, "unmatched destination allowed")
    checkEquals(unmatched.source, TrafficMatchSource.NONE, "unmatched source NONE")
    checkEquals(unmatched.reasonCode, TrafficPolicy.REASON_NO_SIGNAL, "unmatched reason code")

    val noAddress = policy.evaluate(TrafficPolicyRequest(destinationDomain = "unrelated.example", profile = TvPrivacyProfile.BALANCED))
    checkEquals(noAddress.action, TrafficAction.ALLOW, "domain-only request without match allows")
}

private fun testPolicyPrivacy() {
    val policy = TrafficPolicy(privacyRegistry = privacyRegistry())
    val balanced = policy.evaluate(TrafficPolicyRequest(destinationDomain = "track.example.net", profile = TvPrivacyProfile.BALANCED))
    checkEquals(balanced.action, TrafficAction.BLOCK, "balanced profile blocks medium-confidence analytics")
    checkEquals(balanced.source, TrafficMatchSource.PRIVACY_INTELLIGENCE, "privacy source")
    checkEquals(balanced.reasonCode, TrafficPolicy.REASON_PRIVACY_BLOCK, "privacy block reason")
    checkEquals(balanced.category, TrackerCategory.ANALYTICS, "privacy category mapping")

    val conservative = policy.evaluate(TrafficPolicyRequest(destinationDomain = "track.example.net", profile = TvPrivacyProfile.CONSERVATIVE))
    checkEquals(conservative.action, TrafficAction.ANNOTATE, "conservative only annotates medium confidence")
    checkEquals(conservative.reasonCode, TrafficPolicy.REASON_PRIVACY_OBSERVE, "privacy observe reason")
    checkTrue(conservative.ruleId == "analytics-balanced", "privacy rule id exposed")

    val strict = policy.evaluate(TrafficPolicyRequest(destinationDomain = "strict.example.net", profile = TvPrivacyProfile.STRICT))
    checkEquals(strict.action, TrafficAction.ANNOTATE, "strict skips high breakage risk")
    checkEquals(strict.reasonCode, TrafficPolicy.REASON_PRIVACY_OBSERVE, "high breakage observe reason")

    val off = policy.evaluate(TrafficPolicyRequest(destinationDomain = "track.example.net", profile = TvPrivacyProfile.OFF))
    checkEquals(off.action, TrafficAction.ALLOW, "OFF profile disables privacy rules")
    checkEquals(off.source, TrafficMatchSource.NONE, "OFF profile has no privacy source")

    val adsBalanced = policy.evaluate(TrafficPolicyRequest(destinationDomain = "ads.example.org", profile = TvPrivacyProfile.BALANCED))
    checkEquals(adsBalanced.action, TrafficAction.BLOCK, "ads rule blocks under balanced")

    checkEquals(TvPrivacyProfile.STRICT.toPrivacyProfile(), PrivacyProfile.STRICT, "profile extension mapping")
    checkEquals(PrivacyCategory.ADS.toTrackerCategory(), TrackerCategory.ADS, "category extension mapping")
    checkEquals(PrivacyCategory.ESSENTIAL_UPDATE.toTrackerCategory(), null, "essential category has no tracker category")
}

private fun testPolicyEssentialAndPrecedence() {
    val policy = TrafficPolicy(
        threatIndex = threatIndex(),
        privacyRegistry = privacyRegistry(),
    )
    val essential = policy.evaluate(TrafficPolicyRequest(destinationDomain = "samba.tv", profile = TvPrivacyProfile.STRICT))
    checkEquals(essential.action, TrafficAction.ALLOW, "essential rule allows even under strict profile")
    checkEquals(essential.source, TrafficMatchSource.PRIVACY_INTELLIGENCE, "essential source")
    checkEquals(essential.reasonCode, TrafficPolicy.REASON_PRIVACY_ESSENTIAL_ALLOW, "essential allow reason")
    checkEquals(essential.ruleId, "essential-update", "essential rule id")

    val trackerOnly = TrafficPolicy(trackerCatalog = TrackerCatalog.TV_DEFAULT)
    checkEquals(
        trackerOnly.evaluate(TrafficPolicyRequest(destinationDomain = "samba.tv", profile = TvPrivacyProfile.STRICT)).action,
        TrafficAction.BLOCK,
        "without privacy rule the tracker catalog blocks ACR under strict",
    )

    val tiWins = policy.evaluate(
        TrafficPolicyRequest(destinationAddress = "203.0.113.7", destinationDomain = "samba.tv", profile = TvPrivacyProfile.STRICT),
    )
    checkEquals(tiWins.action, TrafficAction.BLOCK, "TI block beats essential allow")
    checkEquals(tiWins.source, TrafficMatchSource.THREAT_INTEL, "TI precedence source")
}

private fun testPolicyTrackerProfiles() {
    val policy = TrafficPolicy()
    val telemetryDomain = "device-metrics-us.amazon.com"

    val off = policy.evaluate(TrafficPolicyRequest(destinationDomain = telemetryDomain, profile = TvPrivacyProfile.OFF))
    checkEquals(off.action, TrafficAction.ALLOW, "OFF profile allows tracker")
    checkEquals(off.reasonCode, TrafficPolicy.REASON_TRACKER_OFF_PROFILE, "OFF profile reason")
    checkEquals(off.source, TrafficMatchSource.TRACKER_CATALOG, "OFF profile still reports the catalog match")

    val conservative = policy.evaluate(TrafficPolicyRequest(destinationDomain = telemetryDomain, profile = TvPrivacyProfile.CONSERVATIVE))
    checkEquals(conservative.action, TrafficAction.ANNOTATE, "conservative annotates medium-confidence telemetry")
    checkEquals(conservative.reasonCode, "tracker_telemetry_annotate", "tracker annotate reason code")

    val balanced = policy.evaluate(TrafficPolicyRequest(destinationDomain = telemetryDomain, profile = TvPrivacyProfile.BALANCED))
    checkEquals(balanced.action, TrafficAction.BLOCK, "balanced blocks medium-confidence telemetry")
    checkEquals(balanced.reasonCode, "tracker_telemetry_block", "tracker block reason code")
    checkEquals(balanced.category, TrackerCategory.TELEMETRY, "tracker telemetry category")

    val strict = policy.evaluate(TrafficPolicyRequest(destinationDomain = telemetryDomain, profile = TvPrivacyProfile.STRICT))
    checkEquals(strict.action, TrafficAction.BLOCK, "strict blocks telemetry")

    val acr = policy.evaluate(TrafficPolicyRequest(destinationDomain = "eu.samba.tv", profile = TvPrivacyProfile.CONSERVATIVE))
    checkEquals(acr.action, TrafficAction.BLOCK, "conservative blocks high-confidence ACR")
    checkEquals(acr.category, TrackerCategory.ACR, "subdomain ACR category")
    checkEquals(acr.confidence, Confidence.HIGH, "ACR confidence from catalog")

    val ads = policy.evaluate(TrafficPolicyRequest(destinationDomain = "doubleclick.net", profile = TvPrivacyProfile.BALANCED))
    checkEquals(ads.action, TrafficAction.BLOCK, "balanced blocks high-confidence ads")
    checkEquals(ads.category, TrackerCategory.ADS, "ads category")

    val unknown = policy.evaluate(TrafficPolicyRequest(destinationDomain = "example.org", profile = TvPrivacyProfile.STRICT))
    checkEquals(unknown.action, TrafficAction.ALLOW, "unknown domain is not classified")
    checkEquals(unknown.reasonCode, TrafficPolicy.REASON_NO_SIGNAL, "unknown domain no signal")

    checkEquals(TrackerCatalog.TV_DEFAULT.match("SAMBA.TV")?.category, TrackerCategory.ACR, "catalog domain canonicalised")
    checkEquals(TrackerCatalog.TV_DEFAULT.match("eu.samba.tv")?.category, TrackerCategory.ACR, "catalog subdomain match")
    checkEquals(TrackerCatalog.TV_DEFAULT.match("not-a-domain"), null, "invalid domain has no match")
    checkEquals(TrackerCatalog.TV_DEFAULT.match("unknown.example"), null, "curated catalog is not a catch-all")
    checkTrue(TrackerCatalog.TV_DEFAULT.size >= 30, "curated catalog substantial (${TrackerCatalog.TV_DEFAULT.size})")
}

private fun testPolicyC2AndNoSignal() {
    val customCatalog = TrackerCatalog.build(
        listOf(
            TrackerRule("custom-c2", "c2.example", true, TrackerCategory.C2, Confidence.HIGH),
            TrackerRule("custom-ads", "ads.example.tv", true, TrackerCategory.ADS, Confidence.LOW),
        ),
    )
    val policy = TrafficPolicy(trackerCatalog = customCatalog)
    val c2 = policy.evaluate(TrafficPolicyRequest(destinationDomain = "c2.example", profile = TvPrivacyProfile.BALANCED))
    checkEquals(c2.action, TrafficAction.BLOCK, "custom C2 entry always blocks")
    checkEquals(c2.category, TrackerCategory.C2, "custom C2 category")
    checkEquals(c2.reasonCode, "tracker_c2_block", "C2 reason code")

    val lowConfidence = policy.evaluate(TrafficPolicyRequest(destinationDomain = "ads.example.tv", profile = TvPrivacyProfile.BALANCED))
    checkEquals(lowConfidence.action, TrafficAction.ANNOTATE, "balanced annotates low-confidence entries")
    val strict = policy.evaluate(TrafficPolicyRequest(destinationDomain = "ads.example.tv", profile = TvPrivacyProfile.STRICT))
    checkEquals(strict.action, TrafficAction.BLOCK, "strict blocks low-confidence entries")

    checkThrows<IllegalArgumentException>("duplicate tracker rule classification rejected") {
        TrackerCatalog.build(
            listOf(
                TrackerRule("duplicate-a", "ads.example.tv", true, TrackerCategory.ADS, Confidence.MEDIUM),
                TrackerRule("duplicate-b", "ads.example.tv", true, TrackerCategory.ADS, Confidence.HIGH),
            ),
        )
    }
    checkThrows<IllegalArgumentException>("tracker rule cap enforced") {
        TrackerCatalog.build(
            listOf(
                TrackerRule("rule-a", "a.example", true, TrackerCategory.ADS, Confidence.MEDIUM),
                TrackerRule("rule-b", "b.example", true, TrackerCategory.ADS, Confidence.MEDIUM),
            ),
            maxRules = 1,
        )
    }
    checkTrue(policy.evaluate(TrafficPolicyRequest(profile = TvPrivacyProfile.BALANCED)).reasonCode.isNotBlank(), "empty request is explainable")
    val request = TrafficPolicyRequest(destinationDomain = "samba.tv", profile = TvPrivacyProfile.CONSERVATIVE)
    checkEquals(policy.evaluate(request), policy.evaluate(request), "policy deterministic for identical request")
    val defaultPolicy = TrafficPolicy(threatIndex = threatIndex(), privacyRegistry = privacyRegistry())
    val sample = TrafficPolicyRequest(destinationAddress = "203.0.113.7", destinationDomain = "track.example.net", profile = TvPrivacyProfile.BALANCED)
    checkEquals(defaultPolicy.evaluate(sample), defaultPolicy.evaluate(sample), "combined policy deterministic")
}

// --- aggregator tests --------------------------------------------------------------------------

private fun testAggregatorAccounting() {
    val clock = MutableClock()
    val aggregator = TrafficAggregator(geoLookup = geoTable(), clock = clock::read)
    aggregator.reset("ACTIVE")
    checkEquals(aggregator.snapshot().state, "ACTIVE", "reset sets state")
    checkTrue(aggregator.open(1L, "com.example.tv", "TV App", "203.0.113.5", "example.com", TrafficAction.ALLOW, "tcp", clock.now + 100), "flow opened")
    checkEquals(aggregator.activeFlowCount(), 1, "active flow counted")
    checkEquals(aggregator.snapshot().apps.single().openedFlows, 1L, "opened flows counted")
    checkTrue(aggregator.update(1L, 100L, 200L, clock.now + 200), "flow updated")
    val updated = aggregator.snapshot()
    checkEquals(updated.txBytes, 100L, "tx bytes after update")
    checkEquals(updated.rxBytes, 200L, "rx bytes after update")
    checkTrue(aggregator.close(1L, 150L, 250L, clock.now + 300), "flow closed")
    val closed = aggregator.snapshot()
    checkEquals(closed.txBytes, 150L, "tx bytes after close")
    checkEquals(closed.rxBytes, 250L, "rx bytes after close")
    checkEquals(closed.activeFlows, 0, "no active flow after close")
    checkEquals(closed.apps.single().activeFlows, 0, "app active flows cleared")
    checkEquals(closed.apps.single().openedFlows, 1L, "app opened flows kept")
    val countries = closed.countries.single()
    checkEquals(countries.countryCode, "DE", "country attribution from geo lookup")
    checkEquals(countries.bytes, 400L, "country bytes including final delta")
    checkEquals(countries.flows, 1, "country flow count")
    checkEquals(aggregator.flows().size, 1, "flow history entry created on close")
    val history = aggregator.flows().single()
    checkEquals(history.ownerPackage, "com.example.tv", "history owner")
    checkEquals(history.countryCode, "DE", "history country")
    checkEquals(history.action, TrafficAction.ALLOW, "history action")
    checkEquals(history.txBytes, 150L, "history tx bytes")
    checkEquals(history.rxBytes, 250L, "history rx bytes")
    checkEquals(history.openedAtMillis, clock.now + 100, "history opened timestamp")
    checkEquals(history.lastSeenMillis, clock.now + 300, "history last seen timestamp")
}

private fun testAggregatorUnknownGeo() {
    val clock = MutableClock()
    val aggregator = TrafficAggregator(geoLookup = GeoLookup.NONE, clock = clock::read)
    checkTrue(aggregator.open(7L, "com.example.tv", "TV App", "1.2.3.4", null, TrafficAction.ALLOW, "tcp", clock.now + 10), "unknown-geo flow opened")
    aggregator.update(7L, 5L, 6L, clock.now + 20)
    aggregator.close(7L, 5L, 6L, clock.now + 30)
    val snapshot = aggregator.snapshot()
    checkEquals(snapshot.countries.single().countryCode, "ZZ", "unknown country aggregated under ZZ")
    checkEquals(snapshot.countries.single().bytes, 11L, "unknown country bytes kept")
    checkEquals(aggregator.flows().single().countryCode, null, "flow history keeps country honestly null")
    checkEquals(snapshot.txBytes, 5L, "global tx bytes counted without geo")
}

private fun testAggregatorBlocked() {
    val clock = MutableClock()
    val aggregator = TrafficAggregator(geoLookup = geoTable(), clock = clock::read)
    checkTrue(
        aggregator.recordBlocked(
            "com.example.tv", "TV App", "203.0.113.5", "samba.tv", 500L, "udp", clock.now + 10, clock.now + 20,
        ),
        "blocked flow recorded",
    )
    val snapshot = aggregator.snapshot()
    checkEquals(snapshot.blockedFlows, 1L, "blocked flow counter")
    checkEquals(snapshot.txBytes, 500L, "blocked bytes counted")
    checkEquals(snapshot.apps.single().blockedFlows, 1L, "app blocked counter")
    val country = snapshot.countries.single()
    checkEquals(country.countryCode, "DE", "blocked country attribution")
    checkEquals(country.blockedFlows, 1, "country blocked flow count")
    val domain = snapshot.domains.single()
    checkEquals(domain.domain, "samba.tv", "blocked domain counted")
    checkEquals(domain.queries, 1L, "blocked domain query count")
    checkEquals(domain.blockedQueries, 1L, "blocked domain blocked count")
    val history = aggregator.flows().single()
    checkEquals(history.action, TrafficAction.BLOCK, "blocked history action")
    checkEquals(history.destinationDomain, "samba.tv", "blocked history domain")
    checkEquals(history.txBytes, 500L, "blocked history bytes")

    checkTrue(
        aggregator.recordBlocked("com.example.tv", "TV App", "203.0.113.5", "invalid domain", 10L, "udp", clock.now + 30, clock.now + 40),
        "invalid domain does not abort blocked accounting",
    )
    checkTrue(aggregator.snapshot().domains.none { it.domain == "invalid domain" }, "invalid domain not counted")
    checkEquals(aggregator.snapshot().blockedFlows, 2L, "invalid domain still counted as blocked flow")

    checkEquals(aggregator.recordBlocked("", "label", "203.0.113.5", null, 1L), false, "blank package rejected")
    checkEquals(aggregator.recordBlocked("pkg", "label", "", null, 1L), false, "blank address rejected")
    checkEquals(aggregator.recordBlocked("pkg", "label", "203.0.113.5", null, 1L, "tcp/udp"), false, "invalid protocol rejected")
    checkTrue(aggregator.recordBlocked("pkg2", "label", "203.0.113.5", null, Long.MAX_VALUE, "udp", clock.now + 50, clock.now + 60), "huge blocked bytes accepted bounded")
    checkTrue(aggregator.snapshot().txBytes >= 500L, "huge blocked bytes bounded and counted")
}

private fun testAggregatorActionCounters() {
    val clock = MutableClock()
    val aggregator = TrafficAggregator(geoLookup = geoTable(), clock = clock::read)
    checkTrue(aggregator.open(1L, "pkg.correlate", "Correlate", "203.0.113.5", null, TrafficAction.CORRELATE, "tcp", clock.now + 10), "correlate flow opened")
    checkTrue(aggregator.open(2L, "pkg.annotate", "Annotate", "203.0.113.6", null, TrafficAction.ANNOTATE, "tcp", clock.now + 20), "annotate flow opened")
    checkTrue(aggregator.open(3L, "pkg.block", "Block", "203.0.113.7", null, TrafficAction.BLOCK, "tcp", clock.now + 30), "blocked flow opened")
    val snapshot = aggregator.snapshot()
    checkEquals(snapshot.correlatedFlows, 1L, "correlated counter")
    checkEquals(snapshot.annotatedFlows, 1L, "annotated counter")
    checkEquals(snapshot.blockedFlows, 1L, "blocked counter")
    checkEquals(snapshot.apps.first { it.packageName == "pkg.correlate" }.correlatedFlows, 1L, "app correlated counter")
    checkEquals(snapshot.apps.first { it.packageName == "pkg.annotate" }.annotatedFlows, 1L, "app annotated counter")
    checkEquals(snapshot.apps.first { it.packageName == "pkg.block" }.blockedFlows, 1L, "app blocked counter")
    checkEquals(aggregator.close(3L, 0L, 0L, clock.now + 40), true, "blocked action flow closes")
}

private fun testAggregatorFlowAppHistoryCaps() {
    val clock = MutableClock()
    val flowCaps = TrafficCaps(maxActiveFlows = 2, maxHistoryFlows = 3, maxApps = 2)
    val flowAggregator = TrafficAggregator(caps = flowCaps, clock = clock::read)
    checkTrue(flowAggregator.open(1L, "pkg.a", "A", "203.0.113.5", null, TrafficAction.ALLOW, "tcp", clock.now + 10), "flow 1 opened")
    checkTrue(flowAggregator.open(2L, "pkg.b", "B", "203.0.113.6", null, TrafficAction.ALLOW, "tcp", clock.now + 20), "flow 2 opened")
    checkEquals(flowAggregator.open(3L, "pkg.c", "C", "203.0.113.7", null, TrafficAction.ALLOW, "tcp", clock.now + 30), false, "active flow cap enforced")

    val historyAggregator = TrafficAggregator(caps = TrafficCaps(maxHistoryFlows = 3), clock = clock::read)
    (1L..5L).forEach { id ->
        checkTrue(historyAggregator.open(id, "pkg.history", "History", "203.0.113.5", null, TrafficAction.ALLOW, "tcp", clock.now + 100 + id), "history flow $id opened")
        checkTrue(historyAggregator.close(id, 1L, 1L, clock.now + 200 + id), "history flow $id closed")
    }
    val history = historyAggregator.flows()
    checkEquals(history.size, 3, "history ring buffer capped")
    checkEquals(history.map { it.id }, listOf(5L, 4L, 3L), "history newest first")
    checkEquals(historyAggregator.flows(0).size, 0, "history limit zero")
    checkEquals(historyAggregator.flows(-9).size, 0, "negative history limit clamped")
    checkEquals(historyAggregator.flows(10_000).size, 3, "history limit capped at ring size")

    val appsAggregator = TrafficAggregator(caps = TrafficCaps(maxApps = 2), clock = clock::read)
    checkTrue(appsAggregator.open(1L, "pkg.a", "A", "203.0.113.5", null, TrafficAction.ALLOW, "tcp", clock.now + 10), "app A accepted")
    appsAggregator.close(1L, 1L, 1L, clock.now + 20)
    checkTrue(appsAggregator.open(2L, "pkg.b", "B", "203.0.113.6", null, TrafficAction.ALLOW, "tcp", clock.now + 30), "app B accepted")
    appsAggregator.close(2L, 1L, 1L, clock.now + 40)
    checkEquals(appsAggregator.open(3L, "pkg.c", "C", "203.0.113.7", null, TrafficAction.ALLOW, "tcp", clock.now + 50), false, "app cap rejects new app")
    checkEquals(appsAggregator.snapshot().apps.size, 2, "snapshot app list bounded")
}

private fun testAggregatorCountryDomainCaps() {
    val clock = MutableClock()
    val aggregator = TrafficAggregator(
        geoLookup = geoTable(),
        caps = TrafficCaps(maxCountries = 2, maxDomains = 2),
        clock = clock::read,
    )
    aggregator.open(1L, "pkg.a", "A", "203.0.113.5", null, TrafficAction.ALLOW, "tcp", clock.now + 10)
    aggregator.close(1L, 10L, 0L, clock.now + 20)
    aggregator.open(2L, "pkg.a", "A", "198.51.100.5", null, TrafficAction.ALLOW, "tcp", clock.now + 30)
    aggregator.close(2L, 20L, 0L, clock.now + 40)
    aggregator.open(3L, "pkg.a", "A", "2001:db8::5", null, TrafficAction.ALLOW, "tcp", clock.now + 50)
    aggregator.close(3L, 30L, 0L, clock.now + 60)
    val snapshot = aggregator.snapshot()
    checkTrue(snapshot.countries.size <= 2, "country cap enforced")
    checkEquals(snapshot.countries.first().countryCode, "US", "top country sorted by bytes")
    checkEquals(snapshot.countries.map { it.countryCode }, listOf("US", "DE"), "country rows sorted deterministically")
    checkTrue(snapshot.countries.none { it.countryCode == "JP" }, "third country beyond cap is not invented")
    checkEquals(snapshot.txBytes, 60L, "bytes beyond country cap stay in global totals")

    checkTrue(aggregator.dnsQuery("pkg.a", "A", "one.example", clock.now + 70), "domain one")
    checkTrue(aggregator.dnsQuery("pkg.a", "A", "two.example", clock.now + 80), "domain two")
    checkTrue(aggregator.dnsQuery("pkg.a", "A", "three.example", clock.now + 90), "domain three")
    val domains = aggregator.snapshot().domains
    checkEquals(domains.size, 2, "domain cap enforced")
    checkTrue(domains.all { it.queries == 1L }, "domain query counts")
    checkEquals(domains.map { it.domain }, domains.map { it.domain }.sorted(), "domain ties sorted lexicographically")
}

private fun testAggregatorLifecycle() {
    val clock = MutableClock()
    val aggregator = TrafficAggregator(geoLookup = geoTable(), clock = clock::read)
    aggregator.reset("ACTIVE")
    aggregator.open(1L, "pkg.a", "A", "203.0.113.5", null, TrafficAction.ALLOW, "tcp", clock.now + 10)
    aggregator.update(1L, 10L, 10L, clock.now + 20)
    aggregator.transportError()
    checkEquals(aggregator.snapshot().transportErrors, 1L, "transport error counted")
    aggregator.clearSession()
    val cleared = aggregator.snapshot()
    checkEquals(cleared.state, "ACTIVE", "clearSession keeps state")
    checkEquals(cleared.txBytes, 0L, "clearSession resets bytes")
    checkEquals(cleared.transportErrors, 0L, "clearSession resets errors")
    checkEquals(cleared.activeFlows, 0, "clearSession resets active flows")
    checkTrue(aggregator.open(2L, "pkg.a", "A", "203.0.113.5", null, TrafficAction.ALLOW, "tcp", clock.now + 30), "flow after clear accepted")
    aggregator.stop()
    val stopped = aggregator.snapshot()
    checkEquals(stopped.state, "STOPPED", "stop sets state")
    checkEquals(stopped.activeFlows, 0, "stop clears active flows")
    aggregator.reset("IDLE")
    checkEquals(aggregator.snapshot().state, "IDLE", "reset IDLE")
    checkEquals(aggregator.snapshot().apps.size, 0, "reset clears apps")

    val timestampAggregator = TrafficAggregator(clock = clock::read)
    timestampAggregator.open(5L, "pkg.t", "T", "203.0.113.5", null, TrafficAction.ALLOW, "tcp", clock.now + 100)
    timestampAggregator.close(5L, 0L, 0L, clock.now)
    checkEquals(timestampAggregator.flows().single().lastSeenMillis, clock.now + 100, "history last seen clamped to opened")
}

private fun testAggregatorConcurrent() {
    val clock = MutableClock()
    val aggregator = TrafficAggregator(geoLookup = geoTable(), clock = clock::read)
    val threads = 4
    val iterations = 50
    val start = CountDownLatch(1)
    val workers = (0 until threads).map { threadIndex ->
        Thread {
            start.await()
            repeat(iterations) { iteration ->
                val id = (threadIndex.toLong() * 1_000L) + iteration
                aggregator.open(id, "pkg.concurrent", "Concurrent", "203.0.113.5", null, TrafficAction.ALLOW, "tcp", clock.now + 10)
                aggregator.update(id, 10L, 20L, clock.now + 20)
                aggregator.close(id, 10L, 20L, clock.now + 30)
            }
        }.apply { isDaemon = true; start() }
    }
    start.countDown()
    workers.forEach { it.join(TimeUnit.SECONDS.toMillis(10)) }
    checkTrue(workers.none { it.isAlive }, "concurrent workers finished")
    val snapshot = aggregator.snapshot()
    checkEquals(snapshot.activeFlows, 0, "no active flows left")
    checkEquals(snapshot.txBytes, threads.toLong() * iterations * 10L, "concurrent tx totals consistent")
    checkEquals(snapshot.rxBytes, threads.toLong() * iterations * 20L, "concurrent rx totals consistent")
    checkEquals(aggregator.flows().size, threads * iterations, "flow history contains every closed flow")
}

// --- xdr tests ---------------------------------------------------------------------------------

private fun testXdrRepeated() {
    val engine = TvXdrEngine()
    primeKnownApp(engine, "com.bad.tv", XDR_NOW)
    val flows = (1L..3L).map { id -> xdrFlow(id, "com.bad.tv", TrafficAction.BLOCK) }
    val incidents = engine.evaluate(TrafficSnapshot.IDLE, flows, XDR_NOW)
    checkEquals(incidents.size, 1, "one repeated-block incident")
    val incident = incidents.single()
    checkEquals(incident.ruleId, "xdr-repeated-block", "repeated rule id")
    checkEquals(incident.severity, de.visiongaia.gedefense.tv.core.model.Severity.MEDIUM, "repeated severity")
    checkTrue(incident.signals.any { it.kind == XdrSignalKind.REPEATED_BLOCKED }, "repeated signal kind")
    checkEquals(incident.count, 3, "repeated count")
    checkEquals(incident.policyAction, PolicyAction.OBSERVE, "no auto enforcement")

    val quietEngine = TvXdrEngine()
    primeKnownApp(quietEngine, "com.bad.tv", XDR_NOW)
    val twoFlows = (11L..12L).map { id -> xdrFlow(id, "com.bad.tv", TrafficAction.BLOCK) }
    checkEquals(quietEngine.evaluate(TrafficSnapshot.IDLE, twoFlows, XDR_NOW).size, 0, "below threshold stays quiet")
}

private fun testXdrTracker() {
    val engine = TvXdrEngine()
    primeKnownApp(engine, "com.tracker.tv", XDR_NOW)
    val flows = listOf(xdrFlow(21L, "com.tracker.tv", TrafficAction.BLOCK, domain = "samba.tv"))
    val incident = engine.evaluate(TrafficSnapshot.IDLE, flows, XDR_NOW).single()
    checkEquals(incident.ruleId, "xdr-tracker-block", "tracker rule id")
    checkEquals(incident.category, TrackerCategory.ACR, "ACR category incident")
    checkEquals(incident.severity, de.visiongaia.gedefense.tv.core.model.Severity.MEDIUM, "ACR incident severity")
    checkTrue(incident.title.key == "xdr.trackerblock.title", "tracker title key")
}

private fun testXdrC2() {
    val c2Index = ThreatIndex.build(listOf(ThreatRecord("feodo", IpPrefix.parse("203.0.113.9/32")!!)))
    val engine = TvXdrEngine(threatIndex = c2Index)
    primeKnownApp(engine, "com.c2.tv", XDR_NOW)
    val flows = listOf(xdrFlow(31L, "com.c2.tv", TrafficAction.BLOCK, address = "203.0.113.9"))
    val incident = engine.evaluate(TrafficSnapshot.IDLE, flows, XDR_NOW).single()
    checkEquals(incident.ruleId, "xdr-c2-match", "C2 rule id")
    checkEquals(incident.category, TrackerCategory.C2, "C2 category")
    checkEquals(incident.severity, de.visiongaia.gedefense.tv.core.model.Severity.HIGH, "C2 severity")
    checkEquals(incident.confidence, Confidence.HIGH, "C2 confidence")
    checkEquals(incident.collectorCategory, CollectorCategory.THREAT_INTEL, "C2 collector category")
}

private fun testXdrCorridor() {
    val engine = TvXdrEngine()
    primeKnownApp(engine, "com.corridor.tv", XDR_NOW)
    val flows = listOf(
        xdrFlow(41L, "com.corridor.tv", TrafficAction.ALLOW, country = "RU"),
        xdrFlow(42L, "com.corridor.tv", TrafficAction.ALLOW, country = "RU"),
    )
    val incident = engine.evaluate(TrafficSnapshot.IDLE, flows, XDR_NOW).single()
    checkEquals(incident.ruleId, "xdr-high-risk-corridor", "corridor rule id")
    checkEquals(incident.severity, de.visiongaia.gedefense.tv.core.model.Severity.INFO, "corridor severity is INFO only")
    checkEquals(incident.countryCode, "RU", "corridor country")
    checkEquals(incident.policyAction, PolicyAction.OBSERVE, "corridor observes only")
    checkEquals(engine.evaluate(TrafficSnapshot.IDLE, flows, XDR_NOW).size, 0, "corridor deduped within window")
}

private fun testXdrCorrelation() {
    val engine = TvXdrEngine()
    primeKnownApp(engine, "com.correlated.tv", XDR_NOW)
    val flows = listOf(
        xdrFlow(51L, "com.correlated.tv", TrafficAction.BLOCK),
        xdrFlow(52L, "com.correlated.tv", TrafficAction.BLOCK),
        xdrFlow(53L, "com.correlated.tv", TrafficAction.BLOCK),
        xdrFlow(54L, "com.correlated.tv", TrafficAction.BLOCK, domain = "samba.tv"),
        xdrFlow(56L, "com.correlated.tv", TrafficAction.ALLOW, country = "RU"),
    )
    val incident = engine.evaluate(TrafficSnapshot.IDLE, flows, XDR_NOW).single()
    checkEquals(incident.ruleId, "xdr-correlated", "correlated rule id")
    val kinds = incident.signals.map { it.kind }.toSet()
    checkTrue(XdrSignalKind.REPEATED_BLOCKED in kinds, "repeated signal correlated")
    checkTrue(XdrSignalKind.TRACKER_BLOCK in kinds, "tracker signal correlated")
    checkTrue(XdrSignalKind.HIGH_RISK_CORRIDOR in kinds, "corridor signal correlated")
    checkEquals(incident.score, incident.signals.sumOf { it.score }.coerceIn(0, 100), "correlated score is explainable sum")
    checkEquals(incident.score, 65, "expected correlated score")
    checkEquals(incident.severity, de.visiongaia.gedefense.tv.core.model.Severity.MEDIUM, "correlated severity")
    checkEquals(incident.category, TrackerCategory.ACR, "ACR preferred category")
    checkTrue(incident.signals.first { it.kind == XdrSignalKind.HIGH_RISK_CORRIDOR }.score == 5, "corridor contribution remains small")
    checkEquals(incident.policyAction, PolicyAction.OBSERVE, "correlated incident observes")
}

private fun testXdrDedupe() {
    val config = XdrConfig(dedupeWindowMillis = 60_000L)
    val engine = TvXdrEngine(config = config)
    primeKnownApp(engine, "com.dedupe.tv", XDR_NOW)
    val flows = listOf(xdrFlow(61L, "com.dedupe.tv", TrafficAction.BLOCK, domain = "samba.tv"))
    checkEquals(engine.evaluate(TrafficSnapshot.IDLE, flows, XDR_NOW).size, 1, "first evaluation emits")
    checkEquals(engine.evaluate(TrafficSnapshot.IDLE, flows, XDR_NOW + 1_000L).size, 0, "same window deduped")
    val later = XDR_NOW + config.dedupeWindowMillis * 3L
    checkTrue(engine.evaluate(TrafficSnapshot.IDLE, flows.map { it.copy(lastSeenMillis = later - 1_000L) }, later).isNotEmpty(), "new window emits again")
}

private fun testXdrNewApp() {
    val engine = TvXdrEngine()
    val flows = listOf(xdrFlow(71L, "com.new.tv", TrafficAction.ALLOW))
    val first = engine.evaluate(TrafficSnapshot.IDLE, flows, XDR_NOW)
    checkEquals(first.single().ruleId, "xdr-new-app", "new app rule id")
    checkEquals(first.single().severity, de.visiongaia.gedefense.tv.core.model.Severity.INFO, "new app severity")
    checkEquals(engine.knownAppCount, 1, "known app recorded")
    checkEquals(engine.evaluate(TrafficSnapshot.IDLE, listOf(xdrFlow(72L, "com.new.tv", TrafficAction.ALLOW)), XDR_NOW).size, 0, "known app not re-announced")
}

private fun testXdrBounds() {
    val config = XdrConfig(maxKnownApps = 3, maxIncidents = 2, scanFlowLimit = 100)
    val engine = TvXdrEngine(config = config)
    val flows = (1L..10L).map { id -> xdrFlow(id, "com.app.$id", TrafficAction.ALLOW) }
    val incidents = engine.evaluate(TrafficSnapshot.IDLE, flows, XDR_NOW)
    checkTrue(engine.knownAppCount <= 3, "known app set bounded")
    checkTrue(incidents.size <= 2, "incident output bounded")
    checkTrue(incidents.all { it.ruleId == "xdr-new-app" }, "only new-app incidents emitted")

    val windowEngine = TvXdrEngine()
    val oldFlows = listOf(
        xdrFlow(
            81L,
            "com.old.tv",
            TrafficAction.BLOCK,
            openedAt = XDR_NOW - 22 * MINUTE,
            lastSeen = XDR_NOW - 20 * MINUTE,
        ),
    )
    checkEquals(windowEngine.evaluate(TrafficSnapshot.IDLE, oldFlows, XDR_NOW).size, 0, "flows outside window ignored")
    val futureFlows = listOf(
        xdrFlow(
            82L,
            "com.future.tv",
            TrafficAction.BLOCK,
            openedAt = XDR_NOW,
            lastSeen = XDR_NOW + 5 * MINUTE,
        ),
    )
    checkEquals(windowEngine.evaluate(TrafficSnapshot.IDLE, futureFlows, XDR_NOW).size, 0, "future flows ignored")
}

private fun testXdrFinding() {
    val engine = TvXdrEngine()
    primeKnownApp(engine, "com.finding.tv", XDR_NOW)
    val flows = listOf(xdrFlow(91L, "com.finding.tv", TrafficAction.BLOCK, domain = "samba.tv"))
    val incident = engine.evaluate(TrafficSnapshot.IDLE, flows, XDR_NOW).single()
    checkTrue(incident.id.matches(Regex("[a-z0-9][a-z0-9._-]{2,127}")), "incident id compatible with Finding")
    val evidence = EvidenceRef("xdr", XDR_NOW - 500L)
    val finding = incident.toFinding(evidence)
    checkEquals(finding.id, incident.id, "finding id from incident")
    checkEquals(finding.ruleId, incident.ruleId, "finding rule id")
    checkEquals(finding.policyAction, PolicyAction.OBSERVE, "finding policy action observability only")
    checkEquals(finding.visibility, DataVisibility.PARTIAL, "XDR findings are partial visibility")
    checkEquals(finding.evidence, evidence, "finding evidence attached")
    checkEquals(finding.category, incident.collectorCategory, "finding category")
    checkTrue(finding.title.key == incident.title.key, "finding title message")
    listOf(finding.title, finding.why, finding.recommendation!!).forEach { ref ->
        checkTrue(DeCatalog.isDefined(ref.key), "XDR message key catalogued: ${ref.key}")
    }
    checkTrue(incident.signals.isNotEmpty(), "incident retains explainable signals")
}

private fun testXdrDeterminism() {
    val flows = listOf(
        xdrFlow(101L, "com.det.tv", TrafficAction.BLOCK),
        xdrFlow(102L, "com.det.tv", TrafficAction.BLOCK),
        xdrFlow(103L, "com.det.tv", TrafficAction.BLOCK),
        xdrFlow(104L, "com.det.tv", TrafficAction.BLOCK, domain = "samba.tv"),
        xdrFlow(105L, "com.det.tv", TrafficAction.ALLOW, country = "RU"),
    )
    val first = TvXdrEngine()
    primeKnownApp(first, "com.det.tv", XDR_NOW)
    val second = TvXdrEngine()
    primeKnownApp(second, "com.det.tv", XDR_NOW)
    checkEquals(first.evaluate(TrafficSnapshot.IDLE, flows, XDR_NOW), second.evaluate(TrafficSnapshot.IDLE, flows, XDR_NOW), "XDR deterministic")
    first.reset()
    checkEquals(first.knownAppCount, 0, "reset clears known apps")
}

// --- configuration and source checks -----------------------------------------------------------

private fun testConfigValidation() {
    checkThrows<IllegalArgumentException>("invalid traffic active-flow cap") { TrafficCaps(maxActiveFlows = 0) }
    checkThrows<IllegalArgumentException>("traffic app cap above snapshot bound") { TrafficCaps(maxApps = 201) }
    checkThrows<IllegalArgumentException>("invalid history cap") { TrafficCaps(maxHistoryFlows = 0) }
    checkThrows<IllegalArgumentException>("invalid XDR window") { XdrConfig(windowMillis = 1L) }
    checkThrows<IllegalArgumentException>("invalid XDR repeat threshold") { XdrConfig(repeatedBlockThreshold = 0) }
    checkThrows<IllegalArgumentException>("invalid XDR country code") { XdrConfig(highRiskCountries = setOf("RUS")) }
    checkEquals(TrafficCaps.DEFAULT.maxHistoryFlows, 500, "default history cap")
    checkEquals(XdrConfig().maxIncidents, 32, "default incident cap")
    checkEquals(TrafficCaps.DEFAULT.maxApps, 200, "default app cap")
    checkEquals(TrafficCaps.DEFAULT.maxActiveFlows, 2_000, "default active flow cap")
}

private fun testNoAndroidImports() {
    val roots = listOf("geo", "policy", "traffic", "xdr")
        .map { packagePart -> File("src/main/kotlin/de/visiongaia/gedefense/tv/core/$packagePart") }
    roots.forEach { root -> checkTrue(root.isDirectory, "source directory exists: ${root.path}") }
    val sourceFiles = roots.flatMap { root ->
        root.walkTopDown().filter { file -> file.isFile && file.extension == "kt" }.toList()
    }
    checkTrue(sourceFiles.size >= 6, "V2 source files found (${sourceFiles.size})")
    sourceFiles.forEach { file ->
        file.readLines().forEachIndexed { index, line ->
            val trimmed = line.trimStart()
            checkTrue(!trimmed.startsWith("import android"), "no Android import in ${file.name}:${index + 1}")
            checkTrue(!trimmed.contains("android.content") && !trimmed.contains("android.app"), "no Android API usage in ${file.name}:${index + 1}")
        }
    }
    val buildFile = File("build.gradle.kts")
    checkTrue(buildFile.isFile, "tv-core build file present")
    val buildText = buildFile.readText()
    checkTrue(buildText.contains("""implementation(project(":core"))"""), "vendored core dependency declared")
    checkTrue(!buildText.contains("""implementation(""""), "no external implementation dependency")
    checkTrue(buildText.contains("tvV2Check"), "V2 verification task registered")
    checkTrue(buildText.contains("tvCoreCheck"), "existing V1 verification task kept")
}

private fun testCatalogXdrKeys() {
    val keys = listOf(
        "xdr.repeatedblock.title", "xdr.repeatedblock.why", "xdr.repeatedblock.recommendation",
        "xdr.trackerblock.title", "xdr.trackerblock.why", "xdr.trackerblock.recommendation",
        "xdr.newapp.title", "xdr.newapp.why", "xdr.newapp.recommendation",
        "xdr.c2match.title", "xdr.c2match.why", "xdr.c2match.recommendation",
        "xdr.corridor.title", "xdr.corridor.why", "xdr.corridor.recommendation",
        "xdr.correlated.title", "xdr.correlated.why", "xdr.correlated.recommendation",
    )
    keys.forEach { key ->
        checkTrue(DeCatalog.isDefined(key), "catalog key defined: $key")
        val ref = de.visiongaia.gedefense.tv.core.model.MessageRef(key)
        checkTrue(DeCatalog.resolve(ref) != key, "catalog resolves: $key")
    }
}
