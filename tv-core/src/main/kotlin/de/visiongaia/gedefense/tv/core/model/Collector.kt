package de.visiongaia.gedefense.tv.core.model

/**
 * Static description of a collector. Kept language-neutral via [title] and [description] refs.
 */
data class CollectorDescriptor(
    val id: String,
    val category: CollectorCategory,
    val title: MessageRef,
    val description: MessageRef,
    /** True when the collector reads platform data that may be restricted per OEM/API level. */
    val restrictedOnSomeDevices: Boolean,
) {
    init {
        require(id.matches(Regex("[a-z][a-z0-9-]{1,63}"))) { "invalid collector id: $id" }
    }
}

/**
 * Quantitative coverage of a collector run.
 *
 * [total] is null when the platform provides no trustworthy denominator (honest unknown). In that
 * case callers may never claim complete coverage even if [observed] looks plausible.
 */
data class CollectorCoverage(
    val observed: Int,
    val total: Int? = null,
    val note: MessageRef? = null,
) {
    init {
        require(observed >= 0) { "negative coverage" }
        require(total == null || total >= observed) { "coverage total smaller than observed" }
    }

    val complete: Boolean get() = total != null && total > 0 && observed >= total
}

/**
 * Result of one collector execution.
 *
 * [errorKey] is a message reference, not a raw exception message: exceptions are logged internally
 * and mapped to stable, user-safe text.
 */
data class CollectorResult(
    val collectorId: String,
    val category: CollectorCategory,
    val capability: CapabilityState,
    val visibility: DataVisibility,
    val dataQuality: DataQuality,
    val startedAtMillis: Long,
    val completedAtMillis: Long,
    val findings: List<Finding> = emptyList(),
    val coverage: CollectorCoverage? = null,
    val errorKey: MessageRef? = null,
) {
    init {
        require(collectorId.matches(Regex("[a-z][a-z0-9-]{1,63}"))) { "invalid collector id: $collectorId" }
        require(completedAtMillis >= startedAtMillis) { "collector completed before start" }
        require(capability != CapabilityState.FAILED || errorKey != null) { "failed collector needs an error key" }
        require(visibility != DataVisibility.FULL || capability == CapabilityState.SUPPORTED) {
            "full visibility requires a supported capability"
        }
    }

    fun withFindings(newFindings: List<Finding>): CollectorResult = copy(findings = findings + newFindings)

    companion object {
        /** Fail-closed synthetic result used when a collector throws before producing a result. */
        fun failed(
            collectorId: String,
            category: CollectorCategory,
            startedAtMillis: Long,
            completedAtMillis: Long,
            errorKey: MessageRef,
        ): CollectorResult = CollectorResult(
            collectorId = collectorId,
            category = category,
            capability = CapabilityState.FAILED,
            visibility = DataVisibility.NONE,
            dataQuality = DataQuality.UNKNOWN,
            startedAtMillis = startedAtMillis,
            completedAtMillis = completedAtMillis,
            errorKey = errorKey,
        )
    }
}

/** Cancellation token shared between the scan engine and collectors. */
fun interface CancelSignal {
    fun isCancelled(): Boolean

    companion object {
        val NEVER: CancelSignal = CancelSignal { false }
    }
}

/**
 * Immutable snapshot of everything a collector may read from the app layer. Collectors must not
 * invent additional state; anything not present here is explicitly unavailable.
 */
data class CollectorEnvironment(
    val collectedAtMillis: Long,
    val deviceId: String,
    val platform: PlatformIdentity,
    val patch: PatchAssessment,
) {
    init {
        require(collectedAtMillis > 0L) { "invalid environment timestamp" }
        require(deviceId.matches(TvEvent.DEVICE_ID_PATTERN)) { "invalid environment device id" }
    }
}

/**
 * A single read-only TV collector. Implementations gather platform data, normalise it and produce
 * findings through the pure rule engines in [de.visiongaia.gedefense.tv.core.rules].
 *
 * Contract:
 *  - must poll [cancel] between expensive operations and throw [InterruptedException] when cancelled;
 *  - must never throw arbitrary exceptions for a *missing* permission/API — that is a
 *    [CapabilityState.PERMISSION_REQUIRED]/[CapabilityState.UNSUPPORTED] result instead;
 *  - must respect the configured time budget and return partial results rather than hanging.
 */
interface Collector {
    val descriptor: CollectorDescriptor

    @Throws(InterruptedException::class)
    fun collect(environment: CollectorEnvironment, cancel: CancelSignal): CollectorResult
}
