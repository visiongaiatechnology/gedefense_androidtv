package de.visiongaia.gedefense.tv.core.model

/**
 * Qualitative posture bands. [UNKNOWN] and [INSUFFICIENT_COVERAGE] are first-class states: a score
 * may never look "clean" when the collectors could not observe enough of the device.
 */
enum class PostureBand { STRONG, MODERATE, WEAK, UNKNOWN, INSUFFICIENT_COVERAGE }

/** One explainable score component. Every point of the score must be traceable to a rule. */
data class ScoreContribution(
    val ruleId: String,
    val delta: Int,
    val message: MessageRef,
) {
    init {
        require(ruleId.matches(Regex("[a-z][a-z0-9-]{2,63}"))) { "invalid score rule id" }
        require(delta in -100..100) { "score delta out of range" }
    }
}

/**
 * Explainable posture score.
 *
 * [value] is null whenever [band] is [PostureBand.UNKNOWN] or [PostureBand.INSUFFICIENT_COVERAGE]:
 * a numeric score without coverage would imply precision that does not exist. [capReason] explains
 * why a mathematically high score was capped (for example visible apps only = partial coverage).
 */
data class PostureScore(
    val value: Int?,
    val band: PostureBand,
    val contributions: List<ScoreContribution>,
    val visibility: DataVisibility,
    val capReason: MessageRef? = null,
) {
    init {
        require((value == null) == (band == PostureBand.UNKNOWN || band == PostureBand.INSUFFICIENT_COVERAGE)) {
            "score value and band disagree"
        }
        require(value == null || value in 0..100) { "score value out of range" }
        require(contributions.size <= 256) { "too many score contributions" }
        require(visibility != DataVisibility.FULL || capReason == null) { "full visibility cannot be capped" }
    }

    val findingCount: Int get() = contributions.count { it.delta < 0 }
}

/** Immutable snapshot of one completed scan, ready for UI and report rendering. */
data class ScanResult(
    val scanId: String,
    val startedAtMillis: Long,
    val completedAtMillis: Long,
    val state: ScanState,
    val platform: PlatformIdentity,
    val patch: PatchAssessment,
    val inventory: AppInventory?,
    val inventoryDelta: InventoryDelta,
    val collectorResults: List<CollectorResult>,
    val score: PostureScore,
    val coverage: DataVisibility,
) {
    init {
        require(scanId.matches(Regex("[a-z0-9-]{8,64}"))) { "invalid scan id" }
        require(completedAtMillis >= startedAtMillis) { "scan completed before start" }
        require(collectorResults.size <= 64) { "too many collectors" }
        require(collectorResults.map { it.collectorId }.toSet().size == collectorResults.size) { "duplicate collector result" }
    }

    val findings: List<Finding> = collectorResults.flatMap { it.findings }
        .sortedWith(compareByDescending<Finding> { it.severity.rank }.thenBy { it.firstSeenMillis })

    fun findingsFor(category: CollectorCategory): List<Finding> = findings.filter { it.category == category }

    fun resultFor(collectorId: String): CollectorResult? = collectorResults.firstOrNull { it.collectorId == collectorId }

    companion object {
        /**
         * Composes the engine outcome with app-layer inputs (platform identity, inventory) into the
         * immutable scan snapshot consumed by UI and report.
         */
        fun compose(
            outcome: ScanOutcome,
            platform: PlatformIdentity,
            patch: PatchAssessment,
            inventory: AppInventory?,
            inventoryDelta: InventoryDelta,
        ): ScanResult = ScanResult(
            scanId = outcome.scanId,
            startedAtMillis = outcome.startedAtMillis,
            completedAtMillis = outcome.completedAtMillis,
            state = outcome.state,
            platform = platform,
            patch = patch,
            inventory = inventory,
            inventoryDelta = inventoryDelta,
            collectorResults = outcome.collectorResults,
            score = outcome.score,
            coverage = outcome.coverage,
        )
    }
}

/**
 * Raw result of a scan-engine run. The app layer complements it with platform identity and app
 * inventory to form a [ScanResult].
 */
data class ScanOutcome(
    val scanId: String,
    val startedAtMillis: Long,
    val completedAtMillis: Long,
    val state: ScanState,
    val collectorResults: List<CollectorResult>,
    val score: PostureScore,
    val coverage: DataVisibility,
) {
    init {
        require(scanId.matches(Regex("[a-z0-9-]{8,64}"))) { "invalid scan id" }
        require(completedAtMillis >= startedAtMillis) { "scan completed before start" }
        require(collectorResults.size <= 64) { "too many collector results" }
    }

    val findings: List<Finding> = collectorResults.flatMap { it.findings }
        .sortedWith(compareByDescending<Finding> { it.severity.rank }.thenBy { it.firstSeenMillis })
}

/** Terminal scan states exposed to the UI. */
enum class ScanState { COMPLETED, PARTIAL, CANCELLED, FAILED }

/** Live progress emitted while a scan runs. */
data class ScanProgress(
    val completedCollectors: Int,
    val totalCollectors: Int,
    val currentCollectorId: String?,
    val currentTitle: MessageRef?,
    val findingsSoFar: Int,
) {
    init {
        require(totalCollectors >= 0 && completedCollectors in 0..totalCollectors) { "invalid scan progress" }
    }

    val fraction: Float
        get() = if (totalCollectors <= 0) 0f else completedCollectors.toFloat() / totalCollectors.toFloat()
}
