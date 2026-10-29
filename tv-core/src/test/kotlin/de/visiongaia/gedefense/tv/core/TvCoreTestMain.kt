package de.visiongaia.gedefense.tv.core

import de.visiongaia.gedefense.tv.core.event.DefaultEventCodec
import de.visiongaia.gedefense.tv.core.model.AccessibilityService
import de.visiongaia.gedefense.tv.core.model.AppInventory
import de.visiongaia.gedefense.tv.core.model.CapabilityState
import de.visiongaia.gedefense.tv.core.model.CancelSignal
import de.visiongaia.gedefense.tv.core.model.Collector
import de.visiongaia.gedefense.tv.core.model.CollectorCategory
import de.visiongaia.gedefense.tv.core.model.CollectorCoverage
import de.visiongaia.gedefense.tv.core.model.CollectorDescriptor
import de.visiongaia.gedefense.tv.core.model.CollectorEnvironment
import de.visiongaia.gedefense.tv.core.model.CollectorResult
import de.visiongaia.gedefense.tv.core.model.Confidence
import de.visiongaia.gedefense.tv.core.model.DataQuality
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.EvidenceHealth
import de.visiongaia.gedefense.tv.core.model.EvidenceRef
import de.visiongaia.gedefense.tv.core.model.EventClass
import de.visiongaia.gedefense.tv.core.model.FeedSnapshot
import de.visiongaia.gedefense.tv.core.model.Finding
import de.visiongaia.gedefense.tv.core.model.HardeningObservations
import de.visiongaia.gedefense.tv.core.model.InstalledApp
import de.visiongaia.gedefense.tv.core.model.InventoryDelta
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.Observed
import de.visiongaia.gedefense.tv.core.model.PassthroughTextCatalog
import de.visiongaia.gedefense.tv.core.model.PatchAssessment
import de.visiongaia.gedefense.tv.core.model.PatchPolicy
import de.visiongaia.gedefense.tv.core.model.PatchStatus
import de.visiongaia.gedefense.tv.core.model.PlatformIdentity
import de.visiongaia.gedefense.tv.core.model.PolicyAction
import de.visiongaia.gedefense.tv.core.model.PostureBand
import de.visiongaia.gedefense.tv.core.model.PostureScore
import de.visiongaia.gedefense.tv.core.model.ScanOutcome
import de.visiongaia.gedefense.tv.core.model.ScanProgress
import de.visiongaia.gedefense.tv.core.model.ScanResult
import de.visiongaia.gedefense.tv.core.model.ScanState
import de.visiongaia.gedefense.tv.core.model.SecurityReport
import de.visiongaia.gedefense.tv.core.model.Severity
import de.visiongaia.gedefense.tv.core.model.ThreatIntelStatus
import de.visiongaia.gedefense.tv.core.model.TvEvent
import de.visiongaia.gedefense.tv.core.report.DefaultReportRenderer
import de.visiongaia.gedefense.tv.core.rules.DefaultHardeningRules
import de.visiongaia.gedefense.tv.core.scan.DefaultScanEngine
import de.visiongaia.gedefense.tv.core.scan.ScanEngineConfig
import de.visiongaia.gedefense.tv.core.score.DefaultCoverageAggregator
import de.visiongaia.gedefense.tv.core.score.RuleBasedScoringEngine
import de.visiongaia.gedefense.tv.core.text.DeCatalog
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.system.exitProcess

// --- tiny assertion harness --------------------------------------------------------------------

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

private fun checkTrue(condition: Boolean, message: String) = check(condition, message)

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
            throwable.stackTrace.take(6).forEach { frame -> println("       at $frame") }
        }
    }
    println()
    println("PASS $passedChecks / FAIL $failedChecks")
    println("TESTS: ${tests.size - failedTestCases} passed, $failedTestCases failed")
    if (failedChecks > 0 || failedTestCases > 0) exitProcess(1)
}

private fun registerTests() {
    test("scan: completed run, progress and score", ::testScanCompletedRun)
    test("scan: failure isolation", ::testScanFailureIsolation)
    test("scan: collector timeout", ::testScanTimeout)
    test("scan: cancellation via signal", ::testScanCancellationViaSignal)
    test("scan: cancellation before first collector", ::testScanCancelledBeforeStart)
    test("scan: interrupted engine thread throws", ::testScanInterruptedThread)
    test("scan: duplicate collectors rejected", ::testScanRejectsDuplicateCollectors)
    test("scan: unattributable result isolated", ::testScanInvalidAttribution)
    test("coverage: aggregation matrix", ::testCoverageAggregation)
    test("score: clean full coverage is strong", ::testScoreCleanFullCoverage)
    test("score: finding penalties explained", ::testScoreFindingPenalties)
    test("score: partial and stale never strong", ::testScorePartialNeverStrong)
    test("score: no visibility gives insufficient coverage", ::testScoreInsufficientCoverage)
    test("score: patch policy penalties and unknown patch cap", ::testScorePatchPolicy)
    test("score: contribution list is bounded", ::testScoreContributionBound)
    test("score: duplicate finding ids counted once", ::testScoreDeduplicatesFindings)
    test("patch: thresholds and date handling", ::testPatchPolicyThresholds)
    test("patch: future and invalid values are unknown", ::testPatchPolicyFutureAndInvalid)
    test("event: full roundtrip and determinism", ::testEventRoundTrip)
    test("event: escaping of control characters", ::testEventEscaping)
    test("event: encodeAll JSONL shape", ::testEventEncodeAll)
    test("event: malformed input rejected", ::testEventMalformedRejected)
    test("hardening: adb and developer options", ::testHardeningFlags)
    test("hardening: unknown sources for own app", ::testHardeningUnknownSources)
    test("hardening: test-keys and debug build", ::testHardeningTestKeys)
    test("hardening: device admins", ::testHardeningDeviceAdmins)
    test("hardening: accessibility services", ::testHardeningAccessibility)
    test("hardening: non-store installers", ::testHardeningInstallers)
    test("hardening: unreadable values never secure", ::testHardeningUnreadable)
    test("report: German text scope, freshness and determinism", ::testReportText)
    test("report: partial scan is not presented as clean", ::testReportPartialNoCleanClaim)
    test("report: JSON stable key order and determinism", ::testReportJson)
    test("report: inventory and evidence limitations labelled", ::testReportInventoryAndEvidence)
    test("catalog: covers every emitted message reference", ::testCatalogCompleteness)
    test("catalog: missing keys are detectable", ::testCatalogMissingDetection)
}

// --- fixtures ----------------------------------------------------------------------------------

private const val DAY_MILLIS = 24L * 60L * 60L * 1000L
private val NOW: Long = Instant.parse("2026-10-29T00:00:00Z").toEpochMilli()
private val DEVICE_ID = "tv_0123456789abcdef0123456789abcdef"
private val EVIDENCE_TIME = NOW - 5_000L

private fun platformIdentity(): PlatformIdentity = PlatformIdentity(
    sdkInt = 34,
    androidRelease = "14",
    manufacturer = "VisionGaia",
    model = "TestTV",
    device = "testtv",
    fingerprint = "visiongaia/testtv/testtv:14/UP1A.231005.007/1:user/release-keys",
    securityPatch = "2026-10-01",
    buildTimeMillis = NOW - 30 * DAY_MILLIS,
    supportedAbis = listOf("arm64-v8a"),
    appVersionName = "0.1.0-alpha1",
    appVersionCode = 1L,
    appDebuggable = false,
)

private fun currentPatch(): PatchAssessment = PatchPolicy.assess("2026-10-01", NOW)

private fun patchForAgeDays(ageDays: Long): PatchAssessment =
    PatchPolicy.assess(dateForAgeDays(ageDays), NOW)

private fun dateForAgeDays(ageDays: Long): String =
    Instant.ofEpochMilli(NOW - ageDays * DAY_MILLIS).toString().substring(0, 10)

private fun environment(patch: PatchAssessment = currentPatch()): CollectorEnvironment =
    CollectorEnvironment(
        collectedAtMillis = NOW,
        deviceId = DEVICE_ID,
        platform = platformIdentity(),
        patch = patch,
    )

private fun descriptor(
    id: String,
    category: CollectorCategory = CollectorCategory.PLATFORM,
): CollectorDescriptor = CollectorDescriptor(
    id = id,
    category = category,
    title = MessageRef("collector.platform.title"),
    description = MessageRef("collector.platform.description"),
    restrictedOnSomeDevices = false,
)

private class FakeCollector(
    override val descriptor: CollectorDescriptor,
    private val body: (CollectorEnvironment, CancelSignal) -> CollectorResult,
) : Collector {
    var executions: Int = 0
        private set

    override fun collect(environment: CollectorEnvironment, cancel: CancelSignal): CollectorResult {
        executions += 1
        return body(environment, cancel)
    }
}

private fun collectorResult(
    descriptor: CollectorDescriptor,
    findings: List<Finding> = emptyList(),
    visibility: DataVisibility = DataVisibility.FULL,
    capability: CapabilityState = CapabilityState.SUPPORTED,
    dataQuality: DataQuality = DataQuality.FRESH,
    coverage: CollectorCoverage? = null,
    errorKey: MessageRef? = null,
): CollectorResult = CollectorResult(
    collectorId = descriptor.id,
    category = descriptor.category,
    capability = capability,
    visibility = visibility,
    dataQuality = dataQuality,
    startedAtMillis = NOW - 100,
    completedAtMillis = NOW - 50,
    findings = findings,
    coverage = coverage,
    errorKey = errorKey,
)

private fun testFinding(
    ruleId: String = "test-rule",
    severity: Severity = Severity.HIGH,
    component: String = "test-component",
    category: CollectorCategory = CollectorCategory.HARDENING,
    visibility: DataVisibility = DataVisibility.FULL,
): Finding = Finding(
    id = Finding.identity(ruleId, component),
    ruleId = ruleId,
    severity = severity,
    confidence = Confidence.HIGH,
    category = category,
    title = MessageRef("hardening.adb.enabled.title"),
    why = MessageRef("hardening.adb.enabled.why"),
    component = component,
    evidence = EvidenceRef("hardening", EVIDENCE_TIME),
    recommendation = MessageRef("hardening.adb.enabled.recommendation"),
    visibility = visibility,
    firstSeenMillis = EVIDENCE_TIME,
    lastSeenMillis = NOW,
    policyAction = PolicyAction.RECOMMEND_MANUAL,
)

private fun hardeningEvidence(): EvidenceRef = EvidenceRef("hardening", EVIDENCE_TIME)

private fun hardeningObservations(
    adb: Observed<Boolean> = Observed.of(false),
    developerOptions: Observed<Boolean> = Observed.of(false),
    unknownSources: Observed<Boolean> = Observed.of(false),
    buildTags: List<String> = listOf("release-keys"),
    buildType: String = "user",
    admins: List<String> = emptyList(),
    accessibility: List<AccessibilityService> = emptyList(),
    knownSystemPackages: Set<String> = emptySet(),
    installers: List<String> = emptyList(),
    ownInstaller: String? = "com.android.vending",
    collectedAtMillis: Long = NOW,
): HardeningObservations = HardeningObservations(
    collectedAtMillis = collectedAtMillis,
    adbEnabled = adb,
    developerOptionsEnabled = developerOptions,
    ownAppCanInstallUnknownApps = unknownSources,
    buildTags = buildTags,
    buildType = buildType,
    activeDeviceAdminPackages = admins,
    accessibilityEnabledServices = accessibility,
    accessibilityKnownSystemPackages = knownSystemPackages,
    visibleNonStoreInstallers = installers,
    ownInstallerPackage = ownInstaller,
)

private fun inventory(restricted: Boolean = true): AppInventory = AppInventory(
    apps = listOf(
        InstalledApp(
            packageName = "com.example.app",
            label = "Example",
            versionName = "1.0",
            versionCode = 1L,
            isSystemApp = false,
            installerPackage = "com.android.vending",
            firstInstallTimeMillis = NOW - 2 * DAY_MILLIS,
            lastUpdateTimeMillis = NOW - DAY_MILLIS,
            signatureSha256 = emptyList(),
            enabled = true,
        ),
    ),
    visibility = DataVisibility.PARTIAL,
    scannedAtMillis = NOW,
    packageVisibilityRestricted = restricted,
    declaredQueryPackages = 3,
    launcherCandidates = 1,
)

private fun threatIntelStatus(): ThreatIntelStatus = ThreatIntelStatus(
    feeds = listOf(
        FeedSnapshot(
            id = "vgt-core",
            name = "VGT Core",
            available = true,
            fresh = true,
            records = 120,
            fetchedAtMillis = NOW - 3_600_000L,
            enforcement = "observe",
        ),
    ),
    lastSyncMillis = NOW - 3_600_000L,
    syncHealthy = true,
)

private fun securityReport(
    scan: ScanResult,
    evidence: EvidenceHealth = EvidenceHealth(healthy = true, records = 12L),
    threatIntel: ThreatIntelStatus = threatIntelStatus(),
): SecurityReport = SecurityReport(
    reportId = "report-test-0001",
    generatedAtMillis = NOW + 10_000L,
    deviceId = DEVICE_ID,
    scan = scan,
    evidence = evidence,
    threatIntel = threatIntel,
)

private fun runScan(
    collectors: List<Collector>,
    engine: DefaultScanEngine = DefaultScanEngine(),
    cancel: CancelSignal = CancelSignal.NEVER,
): Pair<ScanOutcome, List<ScanProgress>> {
    val progress = mutableListOf<ScanProgress>()
    val outcome = engine.run(collectors, environment(), cancel) { progress += it }
    return outcome to progress
}

private fun ScanOutcome.asScanResult(
    patch: PatchAssessment = currentPatch(),
    inventory: AppInventory? = inventory(),
    delta: InventoryDelta = InventoryDelta.NONE,
): ScanResult = ScanResult.compose(this, platformIdentity(), patch, inventory, delta)

// --- scan engine tests -------------------------------------------------------------------------

private fun testScanCompletedRun() {
    val descriptors = listOf(
        descriptor("platform", CollectorCategory.PLATFORM),
        descriptor("app-inventory", CollectorCategory.APPS),
        descriptor("hardening", CollectorCategory.HARDENING),
    )
    val collectors = descriptors.map { d -> FakeCollector(d) { _, _ -> collectorResult(d) } }
    val (outcome, progress) = runScan(collectors)

    checkEquals(outcome.state, ScanState.COMPLETED, "scan state")
    checkEquals(outcome.collectorResults.size, 3, "collector result count")
    checkEquals(outcome.coverage, DataVisibility.FULL, "coverage")
    checkEquals(outcome.score.value, 100, "clean score")
    checkEquals(outcome.score.band, PostureBand.STRONG, "clean band")
    checkTrue(outcome.scanId.matches(Regex("[a-z0-9-]{8,64}")), "scan id matches contract")
    checkTrue(outcome.completedAtMillis >= outcome.startedAtMillis, "scan timestamps ordered")
    checkTrue(outcome.collectorResults.all { it.findings.isEmpty() }, "no invented findings")

    checkEquals(progress.size, 4, "progress updates: one per collector plus final")
    checkTrue(progress.zipWithNext().all { (a, b) -> b.completedCollectors >= a.completedCollectors }, "progress monotonic")
    checkTrue(progress.all { it.totalCollectors == 3 }, "progress total")
    checkEquals(progress.first().currentCollectorId, "platform", "first progress current collector")
    checkEquals(progress.last().currentCollectorId, null, "final progress clears current collector")
    checkEquals(progress.last().completedCollectors, 3, "final progress completed")
    checkTrue(collectors.all { it.executions == 1 }, "each collector executes exactly once")
}

private fun testScanFailureIsolation() {
    val first = descriptor("first", CollectorCategory.PLATFORM)
    val throwing = descriptor("throwing", CollectorCategory.APPS)
    val last = descriptor("last", CollectorCategory.HARDENING)
    val goodFinding = testFinding(category = CollectorCategory.HARDENING)
    val collectors = listOf(
        FakeCollector(first) { _, _ -> collectorResult(first) },
        FakeCollector(throwing) { _, _ -> throw IllegalStateException("boom") },
        FakeCollector(last) { _, _ -> collectorResult(last, findings = listOf(goodFinding)) },
    )
    val outcome = runScan(collectors).first

    checkEquals(outcome.collectorResults.size, 3, "all collectors reported")
    val failed = outcome.collectorResults.first { it.collectorId == "throwing" }
    checkEquals(failed.capability, CapabilityState.FAILED, "throwing collector failed")
    checkEquals(failed.errorKey?.key, "collector.failed", "stable failure key")
    checkEquals(failed.visibility, DataVisibility.NONE, "failed collector invisible")
    checkEquals(outcome.collectorResults.first { it.collectorId == "last" }.findings.size, 1, "later collector still runs")
    checkEquals(outcome.state, ScanState.PARTIAL, "partial scan state")
    checkEquals(outcome.coverage, DataVisibility.NONE, "failed area makes coverage NONE")
    checkEquals(outcome.score.value, null, "no numeric score with failed area")
    checkEquals(outcome.score.band, PostureBand.INSUFFICIENT_COVERAGE, "insufficient coverage band")
}

private fun testScanTimeout() {
    val fastDescriptor = descriptor("fast", CollectorCategory.PLATFORM)
    val slowDescriptor = descriptor("slow", CollectorCategory.HARDENING)
    val fast = FakeCollector(fastDescriptor) { _, _ -> collectorResult(fastDescriptor) }
    val slow = FakeCollector(slowDescriptor) { _, _ ->
        Thread.sleep(10_000L)
        collectorResult(slowDescriptor)
    }
    val engine = DefaultScanEngine(config = ScanEngineConfig(collectorTimeoutMillis = 1_000L))
    val startedAt = System.currentTimeMillis()
    val outcome = engine.run(listOf(fast, slow), environment(), CancelSignal.NEVER) {}
    val elapsed = System.currentTimeMillis() - startedAt

    checkTrue(elapsed < 8_000L, "timeout bounded the slow collector (elapsed=$elapsed ms)")
    val slowResult = outcome.collectorResults.first { it.collectorId == "slow" }
    checkEquals(slowResult.capability, CapabilityState.FAILED, "timed out collector failed")
    checkEquals(slowResult.errorKey?.key, "collector.timeout", "timeout error key")
    checkEquals(outcome.collectorResults.size, 2, "fast result preserved")
    checkEquals(outcome.state, ScanState.PARTIAL, "timeout leaves a partial scan")
}

private fun testScanCancellationViaSignal() {
    val cancelled = AtomicBoolean(false)
    val firstDescriptor = descriptor("cancel-first", CollectorCategory.PLATFORM)
    val secondDescriptor = descriptor("cancel-second", CollectorCategory.APPS)
    val first = FakeCollector(firstDescriptor) { _, _ ->
        cancelled.set(true)
        collectorResult(firstDescriptor)
    }
    val second = FakeCollector(secondDescriptor) { _, _ -> collectorResult(secondDescriptor) }
    val progress = mutableListOf<ScanProgress>()
    val outcome = DefaultScanEngine().run(
        listOf(first, second),
        environment(),
        CancelSignal { cancelled.get() },
    ) { progress += it }

    checkEquals(outcome.state, ScanState.CANCELLED, "cancelled scan state")
    checkEquals(outcome.collectorResults.size, 1, "only completed collector reported")
    checkEquals(second.executions, 0, "cancelled collector is not started")
    checkEquals(progress.last().currentCollectorId, null, "final progress clears current collector")
    checkEquals(progress.last().completedCollectors, 1, "final progress reflects completed work")
}

private fun testScanCancelledBeforeStart() {
    val d = descriptor("never-started", CollectorCategory.PLATFORM)
    val collector = FakeCollector(d) { _, _ -> collectorResult(d) }
    val progress = mutableListOf<ScanProgress>()
    val outcome = DefaultScanEngine().run(listOf(collector), environment(), CancelSignal { true }) { progress += it }

    checkEquals(outcome.state, ScanState.CANCELLED, "cancelled before start")
    checkEquals(outcome.collectorResults.size, 0, "no collector results")
    checkEquals(collector.executions, 0, "collector never executed")
    checkEquals(progress.size, 1, "exactly one cancellation progress update")
    checkEquals(outcome.coverage, DataVisibility.NONE, "no coverage when cancelled")
    checkEquals(outcome.score.band, PostureBand.INSUFFICIENT_COVERAGE, "cancelled run cannot look clean")
}

private fun testScanInterruptedThread() {
    val slowDescriptor = descriptor("interruptible", CollectorCategory.PLATFORM)
    val workerStarted = CountDownLatch(1)
    val slow = FakeCollector(slowDescriptor) { _, _ ->
        workerStarted.countDown()
        Thread.sleep(10_000L)
        collectorResult(slowDescriptor)
    }
    var interrupted = false
    val engineThread = Thread {
        try {
            DefaultScanEngine().run(listOf(slow), environment(), CancelSignal.NEVER) {}
        } catch (_: InterruptedException) {
            interrupted = true
        }
    }
    engineThread.start()
    checkTrue(workerStarted.await(5, TimeUnit.SECONDS), "worker collector started")
    engineThread.interrupt()
    engineThread.join(5_000L)
    checkTrue(interrupted, "interrupted engine thread throws InterruptedException")
    checkTrue(!engineThread.isAlive, "engine thread terminates after interruption")
}

private fun testScanRejectsDuplicateCollectors() {
    val d = descriptor("duplicate-collector", CollectorCategory.PLATFORM)
    val first = FakeCollector(d) { _, _ -> collectorResult(d) }
    val second = FakeCollector(d) { _, _ -> collectorResult(d) }
    checkThrows<IllegalArgumentException>("duplicate collector ids rejected") {
        DefaultScanEngine().run(listOf(first, second), environment(), CancelSignal.NEVER) {}
    }

    val collectorCount = 3
    val descriptors = (0 until collectorCount).map { descriptor("bounded-$it") }
    val collectors = descriptors.map { item -> FakeCollector(item) { _, _ -> collectorResult(item) } }
    checkThrows<IllegalArgumentException>("collector bound enforced") {
        DefaultScanEngine(config = ScanEngineConfig(maxCollectors = 2)).run(
            collectors,
            environment(),
            CancelSignal.NEVER,
        ) {}
    }
}

private fun testScanInvalidAttribution() {
    val d = descriptor("attribution", CollectorCategory.PLATFORM)
    val wrong = CollectorResult(
        collectorId = "other-collector",
        category = CollectorCategory.PLATFORM,
        capability = CapabilityState.SUPPORTED,
        visibility = DataVisibility.FULL,
        dataQuality = DataQuality.FRESH,
        startedAtMillis = NOW - 10L,
        completedAtMillis = NOW,
    )
    val collector = FakeCollector(d) { _, _ -> wrong }
    val outcome = runScan(listOf(collector)).first
    val result = outcome.collectorResults.single()
    checkEquals(result.collectorId, "attribution", "result attributed to descriptor id")
    checkEquals(result.capability, CapabilityState.FAILED, "unattributable result treated as failure")
    checkEquals(result.errorKey?.key, "collector.invalidresult", "invalid result error key")
}

// --- coverage aggregation tests ----------------------------------------------------------------

private fun testCoverageAggregation() {
    val full = descriptor("full", CollectorCategory.PLATFORM)
    val partial = descriptor("partial", CollectorCategory.APPS)
    val stale = descriptor("stale", CollectorCategory.CONNECTIVITY)
    val permission = descriptor("permission", CollectorCategory.SENSOR_HEALTH)

    checkEquals(
        DefaultCoverageAggregator.aggregate(emptyList()),
        DataVisibility.NONE,
        "empty result set is no coverage",
    )
    checkEquals(
        DefaultCoverageAggregator.aggregate(listOf(collectorResult(full))),
        DataVisibility.FULL,
        "single full result",
    )
    checkEquals(
        DefaultCoverageAggregator.aggregate(listOf(collectorResult(full), collectorResult(partial, visibility = DataVisibility.PARTIAL))),
        DataVisibility.PARTIAL,
        "partial worsens aggregate",
    )
    checkEquals(
        DefaultCoverageAggregator.aggregate(listOf(collectorResult(stale, visibility = DataVisibility.STALE))),
        DataVisibility.STALE,
        "stale aggregate",
    )
    checkEquals(
        DefaultCoverageAggregator.aggregate(
            listOf(collectorResult(full), collectorResult(permission, visibility = DataVisibility.PARTIAL)),
        ),
        DataVisibility.PARTIAL,
        "partial beats stale ordering only when stale absent",
    )
    checkEquals(
        DefaultCoverageAggregator.aggregate(
            listOf(
                collectorResult(full),
                collectorResult(permission, visibility = DataVisibility.NONE, capability = CapabilityState.PERMISSION_REQUIRED, dataQuality = DataQuality.UNKNOWN),
            ),
        ),
        DataVisibility.NONE,
        "unobservable collector makes aggregate NONE",
    )
    checkEquals(
        DefaultCoverageAggregator.aggregate(
            listOf(collectorResult(full, coverage = CollectorCoverage(observed = 1, total = 2))),
        ),
        DataVisibility.PARTIAL,
        "incomplete quantitative coverage downgrades aggregate",
    )
    checkEquals(
        DefaultCoverageAggregator.aggregate(
            listOf(collectorResult(full, coverage = CollectorCoverage(observed = 5, total = null))),
        ),
        DataVisibility.FULL,
        "unknown denominator is not a downgrade",
    )
    val failed = CollectorResult.failed(
        collectorId = "failed",
        category = CollectorCategory.PLATFORM,
        startedAtMillis = NOW - 10L,
        completedAtMillis = NOW,
        errorKey = MessageRef("collector.failed"),
    )
    checkEquals(
        DefaultCoverageAggregator.aggregate(listOf(collectorResult(full), failed)),
        DataVisibility.NONE,
        "failed collector makes aggregate NONE",
    )
}

// --- scoring tests -----------------------------------------------------------------------------

private fun testScoreCleanFullCoverage() {
    val d = descriptor("platform", CollectorCategory.PLATFORM)
    val score = RuleBasedScoringEngine.score(listOf(collectorResult(d)), currentPatch())
    checkEquals(score.value, 100, "clean score value")
    checkEquals(score.band, PostureBand.STRONG, "clean score band")
    checkEquals(score.visibility, DataVisibility.FULL, "clean score visibility")
    checkEquals(score.findingCount, 0, "no negative contributions")
    checkEquals(score.capReason, null, "clean score uncapped")
    checkTrue(score.contributions.isNotEmpty(), "score explains its patch contribution")
    checkTrue(score.contributions.all { it.delta == 0 }, "clean contribution deltas zero")
    checkTrue(score.contributions.all { it.ruleId.matches(Regex("[a-z][a-z0-9-]{2,63}")) }, "contribution rule ids valid")
}

private fun testScoreFindingPenalties() {
    val d = descriptor("hardening", CollectorCategory.HARDENING)
    val high = testFinding(ruleId = "test-high", severity = Severity.HIGH, component = "high-component")
    val medium = testFinding(ruleId = "test-medium", severity = Severity.MEDIUM, component = "medium-component")
    val low = testFinding(ruleId = "test-low", severity = Severity.LOW, component = "low-component")
    val info = testFinding(ruleId = "test-info", severity = Severity.INFO, component = "info-component")
    val score = RuleBasedScoringEngine.score(
        listOf(collectorResult(d, findings = listOf(high, medium, low, info))),
        currentPatch(),
    )
    val expected = (100 - 25 - 12 - 5).coerceIn(0, 100)
    checkEquals(score.value, expected, "penalties subtract from base score")
    checkEquals(score.band, PostureBand.MODERATE, "penalised band")
    checkEquals(score.findingCount, 3, "three negative findings counted")
    checkEquals(
        score.value,
        (100 + score.contributions.sumOf { it.delta }).coerceIn(0, 100),
        "score equals base plus contribution sum",
    )
    val highContribution = score.contributions.first { it.ruleId == "test-high" }
    checkEquals(highContribution.delta, -25, "high penalty contribution")
    checkTrue(highContribution.message.key.startsWith("score.finding."), "contribution message key")
    checkTrue(score.contributions.any { it.ruleId == "test-info" && it.delta == 0 }, "info finding stays explainable")

    val critical = testFinding(ruleId = "test-critical", severity = Severity.CRITICAL, component = "critical-component")
    val worst = RuleBasedScoringEngine.score(listOf(collectorResult(d, findings = listOf(critical, critical.copy(id = "test-critical.second", component = "second")))), currentPatch())
    checkTrue(worst.value != null && worst.value in 0..100, "score clamped into 0..100")

    val manyCritical = (0 until 6).map { index ->
        testFinding(ruleId = "test-critical", severity = Severity.CRITICAL, component = "critical-$index")
    }
    val floor = RuleBasedScoringEngine.score(listOf(collectorResult(d, findings = manyCritical)), currentPatch())
    checkEquals(floor.value, 0, "score floor is zero")
    checkEquals(floor.band, PostureBand.WEAK, "zero score is weak")
}

private fun testScorePartialNeverStrong() {
    val partialDescriptor = descriptor("partial", CollectorCategory.APPS)
    val partialScore = RuleBasedScoringEngine.score(
        listOf(collectorResult(partialDescriptor, visibility = DataVisibility.PARTIAL)),
        currentPatch(),
    )
    checkEquals(partialScore.value, 100, "partial clean score value")
    checkTrue(partialScore.band != PostureBand.STRONG, "partial coverage is never strong")
    checkEquals(partialScore.band, PostureBand.MODERATE, "partial coverage capped to moderate")
    checkEquals(partialScore.visibility, DataVisibility.PARTIAL, "partial visibility exposed")
    checkEquals(partialScore.capReason?.key, "score.cap.partial", "partial cap reason")

    val staleDescriptor = descriptor("stale", CollectorCategory.CONNECTIVITY)
    val staleScore = RuleBasedScoringEngine.score(
        listOf(collectorResult(staleDescriptor, visibility = DataVisibility.STALE)),
        currentPatch(),
    )
    checkTrue(staleScore.band != PostureBand.STRONG, "stale coverage is never strong")
    checkEquals(staleScore.capReason?.key, "score.cap.stale", "stale cap reason")
}

private fun testScoreInsufficientCoverage() {
    val d = descriptor("sensor", CollectorCategory.SENSOR_HEALTH)
    val noneResult = collectorResult(
        d,
        visibility = DataVisibility.NONE,
        capability = CapabilityState.PERMISSION_REQUIRED,
        dataQuality = DataQuality.UNKNOWN,
    )
    val score = RuleBasedScoringEngine.score(listOf(noneResult), currentPatch())
    checkEquals(score.value, null, "no numeric score without visibility")
    checkEquals(score.band, PostureBand.INSUFFICIENT_COVERAGE, "insufficient coverage band")
    checkEquals(score.visibility, DataVisibility.NONE, "none visibility")
    checkTrue(score.contributions.any { it.message.key == "score.coverage.none" }, "coverage explanation contribution")

    val emptyScore = RuleBasedScoringEngine.score(emptyList(), currentPatch())
    checkEquals(emptyScore.value, null, "empty scan has no value")
    checkEquals(emptyScore.band, PostureBand.INSUFFICIENT_COVERAGE, "empty scan band")
    checkEquals(emptyScore.visibility, DataVisibility.NONE, "empty scan visibility")
}

private fun testScorePatchPolicy() {
    val d = descriptor("platform", CollectorCategory.PLATFORM)
    val results = listOf(collectorResult(d))

    val aging = RuleBasedScoringEngine.score(results, patchForAgeDays(120))
    checkEquals(aging.value, 95, "aging patch penalty")
    checkEquals(aging.band, PostureBand.STRONG, "aging patch stays explainable strong")

    val outdated = RuleBasedScoringEngine.score(results, patchForAgeDays(200))
    checkEquals(outdated.value, 85, "outdated patch penalty")

    val criticallyOutdated = RuleBasedScoringEngine.score(results, patchForAgeDays(400))
    checkEquals(criticallyOutdated.value, 75, "critically outdated patch penalty")
    checkEquals(criticallyOutdated.band, PostureBand.MODERATE, "critically outdated band")

    val unknownPatch = PatchPolicy.assess(null, NOW)
    val unknown = RuleBasedScoringEngine.score(results, unknownPatch)
    checkEquals(unknown.value, 100, "unknown patch does not invent a penalty")
    checkEquals(unknown.visibility, DataVisibility.PARTIAL, "unknown patch limits visibility")
    checkEquals(unknown.band, PostureBand.MODERATE, "unknown patch caps strong band")
    checkEquals(unknown.capReason?.key, "score.cap.patchunknown", "unknown patch cap reason")

    val unknownContribution = unknown.contributions.first { it.ruleId == "patch-policy" }
    checkEquals(unknownContribution.delta, 0, "unknown patch delta is zero")

    // An outdated patch is "old", never "known vulnerable": the message wording is asserted in the catalog test.
    val outdatedContribution = outdated.contributions.first { it.ruleId == "patch-policy" }
    checkTrue(outdatedContribution.delta < 0, "outdated patch contributes a penalty")
}

private fun testScoreContributionBound() {
    val d = descriptor("hardening", CollectorCategory.HARDENING)
    val findings = (0 until 210).map { index ->
        testFinding(ruleId = "test-rule", severity = Severity.HIGH, component = "component-$index")
    }
    val score = RuleBasedScoringEngine.score(listOf(collectorResult(d, findings = findings)), currentPatch())
    checkTrue(score.contributions.size <= 256, "contributions stay within model bound")
    checkEquals(score.contributions.size, 200, "contribution bound applied")
    checkEquals(score.value, 0, "many findings clamp score to zero")
    checkEquals(score.value, (100 + score.contributions.sumOf { it.delta }).coerceIn(0, 100), "compacted contribution sum")
    val last = score.contributions.last()
    checkEquals(last.ruleId, "score-compaction", "compaction contribution rule id")
    checkTrue(DeCatalog.isDefined(last.message.key), "compaction message is catalogued")
}

private fun testScoreDeduplicatesFindings() {
    val d = descriptor("hardening", CollectorCategory.HARDENING)
    val finding = testFinding(ruleId = "test-rule", severity = Severity.HIGH, component = "duplicate-component")
    val score = RuleBasedScoringEngine.score(
        listOf(collectorResult(d, findings = listOf(finding, finding.copy()))),
        currentPatch(),
    )
    checkEquals(score.value, 75, "duplicate finding counted once")
    checkEquals(score.contributions.count { it.ruleId == "test-rule" }, 1, "single contribution for duplicate finding")
}

// --- patch policy tests ------------------------------------------------------------------------

private fun testPatchPolicyThresholds() {
    checkEquals(patchForAgeDays(0).status, PatchStatus.CURRENT, "today is current")
    checkEquals(patchForAgeDays(89).status, PatchStatus.CURRENT, "89 days is current")
    checkEquals(patchForAgeDays(90).status, PatchStatus.AGING, "90 days starts aging")
    checkEquals(patchForAgeDays(179).status, PatchStatus.AGING, "179 days is aging")
    checkEquals(patchForAgeDays(180).status, PatchStatus.OUTDATED, "180 days starts outdated")
    checkEquals(patchForAgeDays(364).status, PatchStatus.OUTDATED, "364 days is outdated")
    checkEquals(patchForAgeDays(365).status, PatchStatus.CRITICALLY_OUTDATED, "365 days is critically outdated")
    checkEquals(patchForAgeDays(900).status, PatchStatus.CRITICALLY_OUTDATED, "900 days is critically outdated")

    val aging = patchForAgeDays(120)
    checkEquals(aging.ageDays, 120, "patch age days")
    checkTrue(aging.patchDateMillis != null, "parsed patch date present")
    checkTrue(aging.summary.key.startsWith("patch."), "patch summary key")
    checkTrue(DeCatalog.isDefined(aging.summary.key), "patch summary catalogued")

    val critical = patchForAgeDays(400)
    checkTrue(DeCatalog.isDefined(critical.summary.key), "critically outdated summary catalogued")
}

private fun testPatchPolicyFutureAndInvalid() {
    val futureDate = Instant.ofEpochMilli(NOW + 3 * DAY_MILLIS).toString().substring(0, 10)
    val nearFuture = PatchPolicy.assess(futureDate, NOW)
    checkEquals(nearFuture.status, PatchStatus.CURRENT, "small future skew tolerated")
    checkEquals(nearFuture.ageDays, 0, "future age clamped to zero")
    checkTrue(nearFuture.patchDateMillis != null, "near-future date parsed")

    val farFutureDate = Instant.ofEpochMilli(NOW + 8 * DAY_MILLIS).toString().substring(0, 10)
    val farFuture = PatchPolicy.assess(farFutureDate, NOW)
    checkEquals(farFuture.status, PatchStatus.UNKNOWN, "implausible future date is unknown")
    checkEquals(farFuture.patchDateMillis, null, "unknown future has no date")

    checkEquals(PatchPolicy.parsePatchDate(null), null, "null patch date")
    checkEquals(PatchPolicy.parsePatchDate(""), null, "blank patch date")
    checkEquals(PatchPolicy.parsePatchDate("abc"), null, "non-date patch value")
    checkEquals(PatchPolicy.parsePatchDate("2026-02-31"), null, "normalised overflow rejected")
    checkEquals(PatchPolicy.parsePatchDate("2026-13-01"), null, "invalid month rejected")
    checkEquals(PatchPolicy.parsePatchDate("2006-12-01"), null, "implausible year rejected")
    checkEquals(PatchPolicy.parsePatchDate("2101-01-01"), null, "far future year rejected")
    checkTrue(PatchPolicy.parsePatchDate("2026-10-01") != null, "valid patch date accepted")

    val unknown = PatchPolicy.assess(null, NOW)
    checkEquals(unknown.status, PatchStatus.UNKNOWN, "missing patch value is unknown")
    checkEquals(unknown.ageDays, null, "unknown patch has no age")
    checkEquals(unknown.summary.key, "patch.unknown", "unknown patch summary key")
}

// --- event codec tests -------------------------------------------------------------------------

private fun sampleEvent(): TvEvent = TvEvent(
    eventClass = EventClass.TV_DEVICE_STATE,
    eventId = "01234567-89ab-cdef-0123-456789abcdef",
    deviceId = DEVICE_ID,
    eventTimeMillis = NOW,
    collectorId = "platform",
    platform = TvEvent.PLATFORM,
    osApiLevel = 34,
    subject = "Test\nZeile \"quoted\" \\slash \u0001 tab\tende",
    dataQuality = DataQuality.FRESH,
    severity = Severity.HIGH,
    confidence = Confidence.HIGH,
    evidenceRef = "sha256:abc",
    ruleId = "hardening-adb",
    policyAction = PolicyAction.RECOMMEND_MANUAL,
    firstSeenMillis = NOW - 1_000L,
    lastSeenMillis = NOW,
    attributes = mapOf("zz" to "1", "aa" to "2", "note" to "zwei Worte"),
)

private fun testEventRoundTrip() {
    val event = sampleEvent()
    val encoded = DefaultEventCodec.encode(event)
    checkTrue(!encoded.contains('\n') && !encoded.contains('\r'), "encoded event is a single line")
    checkTrue(encoded.startsWith("{") && encoded.endsWith("}"), "encoded event is a JSON object")
    checkTrue(encoded.contains("\"schema\":\"gedefense-tv-event/1\""), "schema tag present")
    val decoded = DefaultEventCodec.decode(encoded)
    checkEquals(decoded, event, "full event roundtrip")
    checkEquals(DefaultEventCodec.encode(event), encoded, "encoding is deterministic")

    val reorderedAttributes = event.copy(attributes = linkedMapOf("aa" to "2", "note" to "zwei Worte", "zz" to "1"))
    checkEquals(DefaultEventCodec.encode(reorderedAttributes), encoded, "attributes sorted deterministically")
    checkTrue(encoded.indexOf("\"aa\":\"2\"") < encoded.indexOf("\"zz\":\"1\""), "attribute order stable")

    val minimal = event.copy(
        severity = null,
        confidence = null,
        evidenceRef = null,
        ruleId = null,
        policyAction = null,
        firstSeenMillis = null,
        lastSeenMillis = null,
        attributes = emptyMap(),
    )
    val minimalEncoded = DefaultEventCodec.encode(minimal)
    checkTrue(minimalEncoded.contains("\"severity\":null"), "unknown optional fields stay null")
    checkEquals(DefaultEventCodec.decode(minimalEncoded), minimal, "minimal event roundtrip")
}

private fun testEventEscaping() {
    val event = sampleEvent().copy(subject = "Anführungszeichen \" \\ Steuerzeichen \u0001\u0002 Tabulator\t Neu\nZeile")
    val encoded = DefaultEventCodec.encode(event)
    checkTrue(encoded.contains("\\\"") && encoded.contains("\\\\"), "quotes and backslashes escaped")
    checkTrue(encoded.contains("\\u0001") && encoded.contains("\\u0002"), "control characters escaped")
    checkTrue(encoded.contains("\\t") && encoded.contains("\\n"), "tab and newline escaped")
    checkTrue(!encoded.contains('\n') && !encoded.contains('\r'), "no raw line breaks")
    checkTrue(encoded.toByteArray(Charsets.UTF_8).none { it.toInt() in 0..0x1F }, "no raw control bytes")
    checkEquals(DefaultEventCodec.decode(encoded), event, "escaped event roundtrip")
}

private fun testEventEncodeAll() {
    val first = sampleEvent()
    val second = sampleEvent().copy(
        eventClass = EventClass.TV_TI_MATCH,
        eventId = "fedcba98-7654-3210-fedc-ba9876543210",
        collectorId = "threat-intel",
        subject = "ioc-match",
    )
    checkEquals(DefaultEventCodec.encodeAll(emptyList()), "", "empty event list encodes empty string")
    val lines = DefaultEventCodec.encodeAll(listOf(first, second))
    checkTrue(lines.endsWith("\n"), "JSONL stream ends with newline")
    val split = lines.split("\n").filter { it.isNotEmpty() }
    checkEquals(split.size, 2, "one event per line")
    checkEquals(DefaultEventCodec.decode(split[0]), first, "first JSONL line decodes")
    checkEquals(DefaultEventCodec.decode(split[1]), second, "second JSONL line decodes")
    checkEquals(DefaultEventCodec.encodeAll(listOf(first, second)), lines, "encodeAll deterministic")
}

private fun testEventMalformedRejected() {
    val event = sampleEvent()
    val encoded = DefaultEventCodec.encode(event)
    checkTrue(DefaultEventCodec.decode(encoded) != null, "control decode works")

    checkEquals(DefaultEventCodec.decode(""), null, "empty line rejected")
    checkEquals(DefaultEventCodec.decode("   "), null, "blank line rejected")
    checkEquals(DefaultEventCodec.decode("not json"), null, "non-JSON rejected")
    checkEquals(DefaultEventCodec.decode("{}"), null, "empty object rejected")
    checkEquals(DefaultEventCodec.decode(encoded.substring(0, encoded.length - 1)), null, "truncated object rejected")
    checkEquals(DefaultEventCodec.decode(encoded + " x"), null, "trailing garbage rejected")
    checkEquals(
        DefaultEventCodec.decode(encoded.replace("\"event_id\":\"${event.eventId}\",", "")),
        null,
        "missing required field rejected",
    )
    checkEquals(
        DefaultEventCodec.decode(encoded.replaceFirst("{", "{\"unknown_key\":1,")),
        null,
        "unknown field rejected",
    )
    checkEquals(
        DefaultEventCodec.decode(encoded.replaceFirst("{", "{\"event_class\":\"TV_DEVICE_STATE\",")),
        null,
        "duplicate key rejected",
    )
    checkEquals(
        DefaultEventCodec.decode(encoded.replace("\"data_quality\":\"FRESH\"", "\"data_quality\":\"BOGUS\"")),
        null,
        "unknown enum value rejected",
    )
    checkEquals(
        DefaultEventCodec.decode(encoded.replace("\"os_api_level\":34", "\"os_api_level\":\"34\"")),
        null,
        "wrong field type rejected",
    )
    checkEquals(
        DefaultEventCodec.decode(encoded.replace("\\n", "\n")),
        null,
        "raw control character in string rejected",
    )
    checkEquals(
        DefaultEventCodec.decode(encoded.replace("2026-10-29T00:00:00Z", "2026-10-29T02:00:00+02:00")),
        null,
        "non-canonical timestamp rejected",
    )
    checkEquals(
        DefaultEventCodec.decode(encoded.replace("\"aa\":\"2\"", "\"aa\":2")),
        null,
        "non-string attribute rejected",
    )
    checkEquals(
        DefaultEventCodec.decode(encoded.replace(event.deviceId, "not-a-device-id")),
        null,
        "invalid device id rejected",
    )
    checkEquals(
        DefaultEventCodec.decode(encoded.replace(event.eventId, "NOT-A-UUID")),
        null,
        "invalid event id rejected",
    )
}

// --- hardening tests ---------------------------------------------------------------------------

private fun testHardeningFlags() {
    val enabled = DefaultHardeningRules.evaluate(
        hardeningObservations(adb = Observed.of(true), developerOptions = Observed.of(true)),
        hardeningEvidence(),
    )
    val adb = enabled.firstOrNull { it.ruleId == "hardening-adb" }
    checkTrue(adb != null, "adb enabled finding")
    checkEquals(adb?.severity, Severity.HIGH, "adb severity")
    checkEquals(adb?.title?.key, "hardening.adb.enabled.title", "adb title key")
    checkTrue(adb?.recommendation != null, "adb recommendation present")
    val devOptions = enabled.firstOrNull { it.ruleId == "hardening-devoptions" }
    checkTrue(devOptions != null, "developer options finding")
    checkEquals(devOptions?.severity, Severity.MEDIUM, "developer options severity")

    val disabled = DefaultHardeningRules.evaluate(hardeningObservations(), hardeningEvidence())
    checkTrue(disabled.isEmpty(), "readable disabled flags produce no findings")
}

private fun testHardeningUnknownSources() {
    val enabled = DefaultHardeningRules.evaluate(
        hardeningObservations(unknownSources = Observed.of(true)),
        hardeningEvidence(),
    )
    val finding = enabled.firstOrNull { it.ruleId == "hardening-unknownsources" }
    checkTrue(finding != null, "unknown sources finding")
    checkEquals(finding?.severity, Severity.HIGH, "unknown sources severity")
    checkEquals(finding?.component, "own-app-install-unknown", "unknown sources component")
    val disabled = DefaultHardeningRules.evaluate(
        hardeningObservations(unknownSources = Observed.of(false)),
        hardeningEvidence(),
    )
    checkTrue(disabled.isEmpty(), "readable disabled unknown sources is quiet")
}

private fun testHardeningTestKeys() {
    val tagged = DefaultHardeningRules.evaluate(
        hardeningObservations(buildTags = listOf("release-keys", "test-keys")),
        hardeningEvidence(),
    )
    checkTrue(tagged.any { it.ruleId == "hardening-testkeys" }, "test-keys tag detected")
    val userdebug = DefaultHardeningRules.evaluate(
        hardeningObservations(buildType = "userdebug"),
        hardeningEvidence(),
    )
    checkTrue(userdebug.any { it.ruleId == "hardening-testkeys" }, "userdebug build detected")
    val eng = DefaultHardeningRules.evaluate(
        hardeningObservations(buildType = "eng"),
        hardeningEvidence(),
    )
    checkTrue(eng.any { it.ruleId == "hardening-testkeys" }, "eng build detected")
    val production = DefaultHardeningRules.evaluate(hardeningObservations(), hardeningEvidence())
    checkTrue(production.none { it.ruleId == "hardening-testkeys" }, "production build not flagged")

    val finding = tagged.first { it.ruleId == "hardening-testkeys" }
    checkEquals(finding.severity, Severity.HIGH, "test-keys severity")
    checkEquals(finding.component, "build", "test-keys component")
}

private fun testHardeningDeviceAdmins() {
    val findings = DefaultHardeningRules.evaluate(
        hardeningObservations(admins = listOf("com.example.admin", "com.android.deviceadmin", "com.example.admin")),
        hardeningEvidence(),
    ).filter { it.ruleId == "hardening-deviceadmin" }
    checkEquals(findings.size, 2, "device admins deduplicated and reported")
    checkEquals(findings.map { it.component }, listOf("com.android.deviceadmin", "com.example.admin"), "admin findings sorted")
    checkTrue(findings.all { it.severity == Severity.MEDIUM }, "admin severity")
    checkTrue(findings.first().title.args == listOf("com.android.deviceadmin"), "admin title argument")
    val none = DefaultHardeningRules.evaluate(hardeningObservations(), hardeningEvidence())
    checkTrue(none.none { it.ruleId == "hardening-deviceadmin" }, "no admins produces no finding")
}

private fun testHardeningAccessibility() {
    val thirdParty = AccessibilityService("com.example.a11y", "Example Helper", false)
    val system = AccessibilityService("com.android.talkback", "Talkback", true)
    val knownSystem = AccessibilityService("com.example.known", "Known System Helper", false)
    val findings = DefaultHardeningRules.evaluate(
        hardeningObservations(
            accessibility = listOf(thirdParty, system, knownSystem),
            knownSystemPackages = setOf("com.example.known"),
        ),
        hardeningEvidence(),
    ).filter { it.ruleId == "hardening-accessibility" }
    checkEquals(findings.size, 1, "only unknown third-party accessibility services are reported")
    checkEquals(findings.single().component, "com.example.a11y", "accessibility component")
    checkEquals(findings.single().severity, Severity.HIGH, "accessibility severity")
    checkTrue(
        findings.single().title.args == listOf("com.example.a11y"),
        "accessibility title argument",
    )
    val clean = DefaultHardeningRules.evaluate(
        hardeningObservations(accessibility = listOf(system), knownSystemPackages = setOf("com.example.known")),
        hardeningEvidence(),
    )
    checkTrue(clean.none { it.ruleId == "hardening-accessibility" }, "system accessibility services are not reported")
}

private fun testHardeningInstallers() {
    val findings = DefaultHardeningRules.evaluate(
        hardeningObservations(installers = listOf("com.example.sideload", "com.example.sideload")),
        hardeningEvidence(),
    ).filter { it.ruleId == "hardening-installer" }
    checkEquals(findings.size, 1, "non-store installers deduplicated")
    checkEquals(findings.single().component, "com.example.sideload", "installer component")
    checkEquals(findings.single().severity, Severity.LOW, "installer severity")
    val clean = DefaultHardeningRules.evaluate(hardeningObservations(), hardeningEvidence())
    checkTrue(clean.none { it.ruleId == "hardening-installer" }, "store-installed apps not flagged")
}

private fun testHardeningUnreadable() {
    val evidence = hardeningEvidence()
    val findings = DefaultHardeningRules.evaluate(
        hardeningObservations(
            adb = Observed.unreadable(),
            developerOptions = Observed.unreadable(),
            unknownSources = Observed.unreadable(),
        ),
        evidence,
    )
    val notes = findings.filter { it.ruleId.endsWith("-unreadable") }
    checkEquals(notes.size, 3, "unreadable flags produce visibility notes")
    checkTrue(notes.all { it.visibility == DataVisibility.NONE }, "visibility notes are not full visibility")
    checkTrue(notes.all { it.severity == Severity.INFO }, "visibility notes are informational")
    checkTrue(notes.all { it.recommendation != null }, "visibility notes carry a recommendation")
    checkTrue(findings.none { it.severity.rank > Severity.INFO.rank }, "unreadable values never produce a risk claim")
    checkTrue(findings.all { it.evidence == evidence }, "findings carry the provided evidence")
    checkTrue(findings.all { it.firstSeenMillis == NOW && it.lastSeenMillis == NOW }, "finding timestamps from observation time")

    val enabled = DefaultHardeningRules.evaluate(hardeningObservations(adb = Observed.of(true)), evidence)
    checkTrue(enabled.all { it.evidence == evidence }, "risk findings carry the provided evidence")
    checkEquals(
        DefaultHardeningRules.evaluate(hardeningObservations(adb = Observed.of(true)), evidence),
        DefaultHardeningRules.evaluate(hardeningObservations(adb = Observed.of(true)), evidence),
        "hardening evaluation is deterministic",
    )
    val ids = DefaultHardeningRules.evaluate(
        hardeningObservations(
            adb = Observed.of(true),
            developerOptions = Observed.of(true),
            unknownSources = Observed.of(true),
            buildTags = listOf("test-keys"),
            admins = listOf("com.example.admin"),
            accessibility = listOf(AccessibilityService("com.example.a11y", "Example", false)),
            installers = listOf("com.example.sideload"),
        ),
        evidence,
    ).map { it.id }
    checkEquals(ids.size, ids.toSet().size, "finding ids are unique")
}

// --- report tests ------------------------------------------------------------------------------

private fun hardeningReport(): SecurityReport {
    val platformDescriptor = descriptor("platform", CollectorCategory.PLATFORM)
    val hardeningDescriptor = descriptor("hardening", CollectorCategory.HARDENING)
    val observations = hardeningObservations(
        adb = Observed.of(true),
        developerOptions = Observed.of(true),
        unknownSources = Observed.of(true),
        buildTags = listOf("release-keys", "test-keys"),
        admins = listOf("com.example.admin"),
        accessibility = listOf(AccessibilityService("com.example.a11y", "Example Helper", false)),
        installers = listOf("com.example.sideload"),
    )
    val findings = DefaultHardeningRules.evaluate(observations, hardeningEvidence())
    val collectors = listOf(
        FakeCollector(platformDescriptor) { _, _ -> collectorResult(platformDescriptor) },
        FakeCollector(hardeningDescriptor) { _, _ -> collectorResult(hardeningDescriptor, findings = findings) },
    )
    val (outcome, _) = runScan(collectors)
    val delta = InventoryDelta(
        newPackages = listOf("com.example.new"),
        changedPackages = listOf("com.example.app"),
        removedPackages = listOf("com.example.old"),
        baselineAvailable = true,
        baselineAtMillis = NOW - DAY_MILLIS,
    )
    return securityReport(outcome.asScanResult(delta = delta))
}

private fun partialReport(): SecurityReport {
    val platformDescriptor = descriptor("platform", CollectorCategory.PLATFORM)
    val appsDescriptor = descriptor("app-inventory", CollectorCategory.APPS)
    val collectors = listOf(
        FakeCollector(platformDescriptor) { _, _ -> collectorResult(platformDescriptor) },
        FakeCollector(appsDescriptor) { _, _ ->
            collectorResult(
                appsDescriptor,
                visibility = DataVisibility.PARTIAL,
                coverage = CollectorCoverage(observed = 4, total = 9),
            )
        },
    )
    return securityReport(runScan(collectors).first.asScanResult())
}

private fun insufficientReport(): SecurityReport {
    val sensorDescriptor = descriptor("sensor-health", CollectorCategory.SENSOR_HEALTH)
    val collector = FakeCollector(sensorDescriptor) { _, _ ->
        collectorResult(
            sensorDescriptor,
            visibility = DataVisibility.NONE,
            capability = CapabilityState.PERMISSION_REQUIRED,
            dataQuality = DataQuality.UNKNOWN,
        )
    }
    return securityReport(runScan(listOf(collector)).first.asScanResult())
}

private fun testReportText() {
    val report = hardeningReport()
    val text = DefaultReportRenderer.renderText(report, DeCatalog)
    checkTrue(text.contains("Sicherheitsbericht"), "report title")
    checkTrue(text.contains("Prüfumfang"), "scope section")
    checkTrue(text.contains("Grenzen der Aussage"), "limitations section")
    checkTrue(text.contains("Datenfrische"), "freshness section")
    checkTrue(text.contains("Sicherheitsbewertung"), "posture section")
    checkTrue(text.contains("Beiträge zur Bewertung"), "score explanation section")
    checkTrue(text.contains("ADB-/Debugging-Zugriff ist aktiviert"), "German finding title resolved")
    checkTrue(text.contains("Paket-Sichtbarkeit"), "package visibility limitation present")
    checkTrue(text.contains("Keine privilegierten Endpoint-"), "privileged sensor limitation present")
    checkTrue(!text.contains("{0}") && !text.contains("{1}"), "no unresolved placeholders")
    checkTrue(!FALLBACK_PATTERN.containsMatchIn(text), "no raw message keys fall back in report text")
    checkTrue(!text.contains("TODO") && !text.contains("dummy"), "no placeholder markers")
    checkEquals(DefaultReportRenderer.renderText(report, DeCatalog), text, "text rendering is deterministic")

    val fallbackRendered = DefaultReportRenderer.renderText(report, PassthroughTextCatalog)
    checkTrue(fallbackRendered.contains("report.title"), "passthrough catalog keeps missing keys visible for tests")
}

private val FALLBACK_PATTERN = Regex("\\b(report|score|hardening|patch|collector|evidence|coverage|export|scan|ti|sensor|event)\\.[a-z0-9_.]{2,}")

private fun testReportPartialNoCleanClaim() {
    val report = partialReport()
    val text = DefaultReportRenderer.renderText(report, DeCatalog)
    checkEquals(report.scan.score.band, PostureBand.MODERATE, "partial score band capped")
    checkTrue(text.contains("Nur teilweise sichtbar"), "partial coverage wording")
    checkTrue(!text.contains("Stark"), "partial scan is never labelled strong")
    val json = DefaultReportRenderer.renderJson(report)
    checkTrue(json.contains("\"value\":100"), "partial score still numeric")
    checkTrue(json.contains("\"band\":\"MODERATE\""), "partial band in JSON")
    checkTrue(json.contains("\"limitations\":["), "limitations exported")

    val insufficient = insufficientReport()
    val insufficientText = DefaultReportRenderer.renderText(insufficient, DeCatalog)
    checkEquals(insufficient.scan.score.value, null, "insufficient scan has no numeric score")
    checkTrue(insufficientText.contains("Kein numerischer Wert"), "insufficient score wording")
    checkTrue(!insufficientText.contains("von 100"), "no numeric score claim without coverage")
    val insufficientJson = DefaultReportRenderer.renderJson(insufficient)
    checkTrue(insufficientJson.contains("\"value\":null"), "JSON score value is null")
    checkTrue(insufficientJson.contains("\"band\":\"INSUFFICIENT_COVERAGE\""), "JSON insufficient band")
}

private fun testReportJson() {
    val report = hardeningReport()
    val json = DefaultReportRenderer.renderJson(report)
    checkTrue(json.startsWith("{") && json.endsWith("}"), "JSON object")
    checkTrue(json.all { it.code < 128 }, "JSON is locale-independent ASCII for this input")
    checkEquals(DefaultReportRenderer.renderJson(report), json, "JSON rendering is deterministic")
    checkTrue(json.contains("\"schema\":\"gedefense-tv-report/1\""), "schema tag")
    checkTrue(json.contains("\"report_id\":\"report-test-0001\""), "report id")
    checkTrue(json.contains("\"scan\":"), "scan object")
    checkTrue(json.contains("\"scope\":["), "scope codes")
    checkTrue(json.contains("\"limitations\":["), "limitation codes")
    checkTrue(json.contains("\"findings\":["), "findings array")
    checkTrue(json.contains("\"contributions\":["), "score contributions")
    checkTrue(json.contains("\"evidence\":"), "evidence section")
    checkTrue(json.contains("\"threat_intel\":"), "threat intel section")

    val order = listOf(
        "\"schema\"",
        "\"report_id\"",
        "\"generated_at_utc\"",
        "\"device_id\"",
        "\"scan\"",
        "\"evidence\"",
        "\"threat_intel\"",
        "\"scope\"",
        "\"limitations\"",
    )
    val indices = order.map { json.indexOf(it) }
    checkTrue(indices.all { it >= 0 }, "all top-level keys present")
    checkTrue(indices.zipWithNext().all { (a, b) -> a < b }, "stable top-level key order")

    val scanOrder = listOf(
        "\"scan_id\"",
        "\"started_at_utc\"",
        "\"completed_at_utc\"",
        "\"state\"",
        "\"coverage\"",
        "\"platform\"",
        "\"patch\"",
        "\"score\"",
        "\"collectors\"",
        "\"findings\"",
        "\"inventory\"",
        "\"inventory_delta\"",
    )
    val scanIndices = scanOrder.map { json.indexOf(it) }
    checkTrue(scanIndices.all { it >= 0 }, "all scan keys present")
    checkTrue(scanIndices.zipWithNext().all { (a, b) -> a < b }, "stable scan key order")

    val noFindings = securityReport(runScan(emptyList()).first.asScanResult())
    val noFindingsText = DefaultReportRenderer.renderText(noFindings, DeCatalog)
    checkTrue(noFindingsText.contains("Keine Befunde im sichtbaren Bereich."), "empty findings wording")
    val noFindingsJson = DefaultReportRenderer.renderJson(noFindings)
    checkTrue(noFindingsJson.contains("\"findings\":[]"), "empty findings array")
}

private fun testReportInventoryAndEvidence() {
    val report = hardeningReport()
    val text = DefaultReportRenderer.renderText(report, DeCatalog)
    checkTrue(text.contains("Sichtbare Apps: 1"), "visible app count from inventory")
    checkTrue(text.contains("Die Paket-Sichtbarkeit kann die App-Liste einschränken"), "inventory limitation note")
    checkTrue(text.contains("1 neu, 1 geändert, 1 entfernt"), "inventory delta rendered")
    checkTrue(text.contains("Threat Intelligence"), "threat intel section")
    checkTrue(text.contains("Evidenzspeicher intakt"), "evidence health rendered")

    val unhealthy = securityReport(
        report.scan.copy(),
        evidence = EvidenceHealth.UNAVAILABLE,
    )
    val unhealthyText = DefaultReportRenderer.renderText(unhealthy, DeCatalog)
    checkTrue(unhealthyText.contains("Evidenzspeicher eingeschränkt"), "unhealthy evidence labelled")
    val unhealthyJson = DefaultReportRenderer.renderJson(unhealthy)
    checkTrue(unhealthyJson.contains("\"reason\":\"evidence.unavailable\""), "evidence reason key in JSON")

    val noInventory = securityReport(report.scan.copy(inventory = null), evidence = EvidenceHealth(healthy = true, records = 0L))
    val noInventoryText = DefaultReportRenderer.renderText(noInventory, DeCatalog)
    checkTrue(noInventoryText.contains("App-Inventar nicht verfügbar."), "missing inventory labelled")
}

// --- catalog tests -----------------------------------------------------------------------------

private fun collectMessageRefs(report: SecurityReport): List<MessageRef> {
    val refs = mutableListOf<MessageRef>()
    val scan = report.scan
    refs += scan.patch.summary
    scan.score.capReason?.let { refs += it }
    refs += scan.score.contributions.map { it.message }
    scan.collectorResults.forEach { result ->
        result.errorKey?.let { refs += it }
        result.coverage?.note?.let { refs += it }
    }
    scan.findings.forEach { finding ->
        refs += finding.title
        refs += finding.why
        finding.recommendation?.let { refs += it }
    }
    report.evidence.reason?.let { refs += it }
    report.threatIntel.note?.let { refs += it }
    return refs
}

private fun testCatalogCompleteness() {
    val refs = mutableListOf<MessageRef>()
    refs += collectMessageRefs(hardeningReport())
    refs += collectMessageRefs(partialReport())
    refs += collectMessageRefs(insufficientReport())

    val hardeningFindings = DefaultHardeningRules.evaluate(
        hardeningObservations(
            adb = Observed.unreadable(),
            developerOptions = Observed.unreadable(),
            unknownSources = Observed.unreadable(),
            buildTags = listOf("test-keys"),
            buildType = "userdebug",
            admins = listOf("com.example.admin"),
            accessibility = listOf(AccessibilityService("com.example.a11y", "Example", false)),
            installers = listOf("com.example.sideload"),
        ),
        hardeningEvidence(),
    )
    hardeningFindings.forEach { finding ->
        refs += finding.title
        refs += finding.why
        finding.recommendation?.let { refs += it }
    }

    // Engine error keys from real fault paths.
    val failingDescriptor = descriptor("failing", CollectorCategory.APPS)
    val failing = FakeCollector(failingDescriptor) { _, _ -> throw IllegalStateException("boom") }
    refs += runScan(listOf(failing)).first.collectorResults.flatMap { result -> listOfNotNull(result.errorKey) }
    val timeoutDescriptor = descriptor("timeout", CollectorCategory.HARDENING)
    val timeoutCollector = FakeCollector(timeoutDescriptor) { _, _ ->
        Thread.sleep(10_000L)
        collectorResult(timeoutDescriptor)
    }
    refs += DefaultScanEngine(config = ScanEngineConfig(collectorTimeoutMillis = 1_000L))
        .run(listOf(timeoutCollector), environment(), CancelSignal.NEVER) {}
        .collectorResults.flatMap { result -> listOfNotNull(result.errorKey) }

    // Patch status and score coverage message variants.
    refs += listOf(
        currentPatch().summary,
        patchForAgeDays(120).summary,
        patchForAgeDays(200).summary,
        patchForAgeDays(400).summary,
        PatchPolicy.assess(null, NOW).summary,
    )
    val coverageVariants = listOf(
        DataVisibility.PARTIAL to CapabilityState.SUPPORTED,
        DataVisibility.STALE to CapabilityState.SUPPORTED,
        DataVisibility.NONE to CapabilityState.PERMISSION_REQUIRED,
    )
    coverageVariants.forEach { (visibility, capability) ->
        val d = descriptor("coverage-variant", CollectorCategory.PLATFORM)
        val result = collectorResult(
            d,
            visibility = visibility,
            capability = capability,
            dataQuality = if (visibility == DataVisibility.FULL) DataQuality.FRESH else DataQuality.PARTIAL,
        )
        val score = RuleBasedScoringEngine.score(listOf(result), currentPatch())
        refs += score.contributions.map { it.message }
        score.capReason?.let { refs += it }
    }
    refs += PatchPolicy.assess(null, NOW).let { RuleBasedScoringEngine.score(emptyList(), it) }.contributions.map { it.message }

    checkTrue(refs.isNotEmpty(), "collected message references from real pipeline")
    refs.forEach { ref ->
        checkTrue(DeCatalog.isDefined(ref.key), "catalog defines ${ref.key}")
        val resolved = DeCatalog.resolve(ref)
        val fallback = PassthroughTextCatalog.resolve(ref)
        checkTrue(resolved != fallback, "catalog resolves ${ref.key} instead of falling back")
        checkTrue(!resolved.contains("{0}") && !resolved.contains("{1}"), "no unresolved placeholder in ${ref.key}")
    }

    val requiredKeys = listOf(
        "collector.platform.title",
        "collector.platform.description",
        "collector.appinventory.title",
        "collector.appinventory.description",
        "collector.hardening.title",
        "collector.connectivity.title",
        "collector.threatintel.title",
        "collector.sensorhealth.title",
        "collector.failed",
        "collector.timeout",
        "collector.permission_required",
        "collector.unsupported",
        "collector.restricted",
        "collector.partial_coverage",
        "collector.stale",
        "collector.platform.failed",
        "collector.apps.failed",
        "collector.hardening.failed",
        "collector.hardening.evaluationfailed",
        "collector.connectivity.failed",
        "collector.sensorhealth.failed",
        "collector.threatintel.failed",
        "coverage.packagevisibility",
        "coverage.partial",
        "evidence.initializing",
        "evidence.degraded",
        "evidence.recordfailed",
        "evidence.clearfailed",
        "evidence.cleared",
        "export.ok",
        "export.partial",
        "export.cancelled",
        "export.failed",
        "export.unavailable",
        "scan.cancelled",
        "scan.failed",
        "ti.syncok",
        "ti.syncpartial",
        "ti.syncfailed",
        "ti.keyunavailable",
        "ti.stale",
        "sensor.permission.title",
        "sensor.permission.why",
        "sensor.permission.recommendation",
        "sensor.evidence.title",
        "sensor.evidence.why",
        "event.device_state",
        "event.app_inventory",
        "event.connectivity",
        "event.ti_match",
        "event.sensor_health",
        "event.enforcement",
    )
    requiredKeys.forEach { key -> checkTrue(DeCatalog.isDefined(key), "required catalog key $key") }

    DeCatalog.keys.forEach { key ->
        MessageRef(key)
    }
    checkTrue(DeCatalog.size > 100, "catalog is substantial (${DeCatalog.size} keys)")
}

private fun testCatalogMissingDetection() {
    checkTrue(!DeCatalog.isDefined("report.definitely.missing"), "unknown key is not reported as defined")
    checkEquals(
        DeCatalog.resolve(MessageRef("report.definitely.missing")),
        "report.definitely.missing",
        "unknown key resolves to its visible fallback",
    )
    checkEquals(
        DeCatalog.missingKeys(listOf("patch.current", "report.definitely.missing", "patch.current")),
        listOf("report.definitely.missing"),
        "missing key detection is distinct and sorted",
    )
    val resolved = DeCatalog.resolve(MessageRef("patch.current", listOf("42")))
    checkTrue(resolved.contains("42"), "positional argument substituted")
    checkTrue(!resolved.contains("{0}"), "placeholder replaced")
    checkEquals(
        DeCatalog.resolve(MessageRef("score.band.strong")),
        "Stark",
        "German label for strong band",
    )
    checkTrue(
        DeCatalog.resolve(MessageRef("patch.outdated", listOf("200"))).contains("veraltet"),
        "outdated patch wording is old, not vulnerable",
    )
    checkTrue(
        !DeCatalog.resolve(MessageRef("patch.outdated", listOf("200"))).contains("verwundbar", ignoreCase = true),
        "patch wording never claims a concrete vulnerability",
    )
}
