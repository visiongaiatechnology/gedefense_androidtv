package de.visiongaia.gedefense.tv.core.score

import de.visiongaia.gedefense.tv.core.model.CapabilityState
import de.visiongaia.gedefense.tv.core.model.CollectorResult
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.Finding
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.PatchAssessment
import de.visiongaia.gedefense.tv.core.model.PatchStatus
import de.visiongaia.gedefense.tv.core.model.PostureBand
import de.visiongaia.gedefense.tv.core.model.PostureScore
import de.visiongaia.gedefense.tv.core.model.ScoreContribution
import de.visiongaia.gedefense.tv.core.model.Severity
import de.visiongaia.gedefense.tv.core.model.clampScore

/**
 * Tuning knobs of the explainable posture score.
 *
 * All penalties are expressed in points of the 0..100 score. Every non-zero penalty is emitted as a
 * [ScoreContribution] so that UI and report can show where each point of the score came from.
 */
data class ScoringConfig(
    val baseScore: Int = 100,
    val criticalPenalty: Int = 40,
    val highPenalty: Int = 25,
    val mediumPenalty: Int = 12,
    val lowPenalty: Int = 5,
    val agingPenalty: Int = 5,
    val outdatedPenalty: Int = 15,
    val criticallyOutdatedPenalty: Int = 25,
    val strongThreshold: Int = 80,
    val moderateThreshold: Int = 55,
    val partialCapsStrong: Boolean = true,
    val unknownPatchCapsStrong: Boolean = true,
    val maxContributions: Int = 200,
) {
    init {
        require(baseScore in 0..100) { "invalid base score" }
        require(criticalPenalty in 0..100) { "invalid critical penalty" }
        require(highPenalty in 0..100) { "invalid high penalty" }
        require(mediumPenalty in 0..100) { "invalid medium penalty" }
        require(lowPenalty in 0..100) { "invalid low penalty" }
        require(agingPenalty in 0..100) { "invalid aging penalty" }
        require(outdatedPenalty in 0..100) { "invalid outdated penalty" }
        require(criticallyOutdatedPenalty in 0..100) { "invalid critically outdated penalty" }
        require(strongThreshold in 1..100) { "invalid strong threshold" }
        require(moderateThreshold in 0..strongThreshold) { "invalid moderate threshold" }
        require(maxContributions in 8..256) { "invalid contribution bound" }
    }

    companion object {
        val DEFAULT = ScoringConfig()
    }
}

/**
 * Default coverage aggregation shared by scan outcome, UI and report.
 *
 * The aggregate is the worst observed visibility: a single area the app could not observe makes the
 * overall result non-full instead of hiding the blind spot behind successful collectors. A collector
 * that explicitly reports incomplete quantitative coverage also downgrades the aggregate to
 * [DataVisibility.PARTIAL]; a null denominator means "unknown", not "complete".
 */
object DefaultCoverageAggregator : CoverageAggregator {
    override fun aggregate(results: List<CollectorResult>): DataVisibility {
        if (results.isEmpty()) return DataVisibility.NONE
        if (results.any { it.capability == CapabilityState.FAILED || it.visibility == DataVisibility.NONE }) {
            return DataVisibility.NONE
        }
        if (results.any { it.visibility == DataVisibility.PARTIAL }) return DataVisibility.PARTIAL
        if (results.any { it.visibility == DataVisibility.STALE }) return DataVisibility.STALE
        if (results.any { result ->
                val coverage = result.coverage
                coverage != null && coverage.total != null && !coverage.complete
            }
        ) {
            return DataVisibility.PARTIAL
        }
        return DataVisibility.FULL
    }
}

/**
 * Deterministic rule-based posture scoring.
 *
 * Guarantees:
 *  - every finding with a non-zero penalty yields exactly one [ScoreContribution] carrying the
 *    originating rule id and a catalog message;
 *  - the numeric value equals `baseScore + sum(contribution deltas)` clamped to 0..100, so the score
 *    is fully reconstructible;
 *  - [DataVisibility.NONE] yields [PostureBand.INSUFFICIENT_COVERAGE] with a null value;
 *  - partial/stale visibility or an unknown patch level can never yield [PostureBand.STRONG];
 *  - an old patch level is penalty-scored as "old", never described as "known vulnerable".
 */
object RuleBasedScoringEngine : ScoringEngine {

    override fun score(results: List<CollectorResult>, patch: PatchAssessment): PostureScore =
        score(results, patch, ScoringConfig.DEFAULT)

    /** Configurable variant used by tests and future UI tuning presets. */
    fun score(results: List<CollectorResult>, patch: PatchAssessment, config: ScoringConfig): PostureScore {
        val baseVisibility = DefaultCoverageAggregator.aggregate(results)
        val patchUnknown = patch.status == PatchStatus.UNKNOWN
        val visibility = if (patchUnknown && config.unknownPatchCapsStrong) {
            worseOf(baseVisibility, DataVisibility.PARTIAL)
        } else {
            baseVisibility
        }

        val rawContributions = mutableListOf<ScoreContribution>()
        val findings = results
            .flatMap { it.findings }
            .distinctBy { it.id }
            .sortedWith(compareByDescending<Finding> { it.severity.rank }.thenBy { it.id })
        findings.forEach { finding ->
            val penalty = when (finding.severity) {
                Severity.CRITICAL -> config.criticalPenalty
                Severity.HIGH -> config.highPenalty
                Severity.MEDIUM -> config.mediumPenalty
                Severity.LOW -> config.lowPenalty
                Severity.INFO -> 0
            }
            val messageKey = when (finding.severity) {
                Severity.CRITICAL -> "score.finding.critical"
                Severity.HIGH -> "score.finding.high"
                Severity.MEDIUM -> "score.finding.medium"
                Severity.LOW -> "score.finding.low"
                Severity.INFO -> "score.finding.info"
            }
            rawContributions += ScoreContribution(
                ruleId = finding.ruleId,
                delta = -penalty,
                message = MessageRef(messageKey, listOf(finding.component)),
            )
        }

        val ageArg = patch.ageDays?.toString() ?: "-"
        val (patchDelta, patchKey) = when (patch.status) {
            PatchStatus.CURRENT -> 0 to "score.patch.current"
            PatchStatus.AGING -> -config.agingPenalty to "score.patch.aging"
            PatchStatus.OUTDATED -> -config.outdatedPenalty to "score.patch.outdated"
            PatchStatus.CRITICALLY_OUTDATED -> -config.criticallyOutdatedPenalty to "score.patch.critically_outdated"
            PatchStatus.UNKNOWN -> 0 to "score.patch.unknown"
        }
        rawContributions += ScoreContribution(
            ruleId = "patch-policy",
            delta = patchDelta,
            message = MessageRef(patchKey, if (patch.status == PatchStatus.UNKNOWN) emptyList() else listOf(ageArg)),
        )

        when (baseVisibility) {
            DataVisibility.PARTIAL -> rawContributions += ScoreContribution(
                ruleId = "coverage-policy",
                delta = 0,
                message = MessageRef("score.coverage.partial"),
            )
            DataVisibility.STALE -> rawContributions += ScoreContribution(
                ruleId = "coverage-policy",
                delta = 0,
                message = MessageRef("score.coverage.stale"),
            )
            DataVisibility.NONE -> rawContributions += ScoreContribution(
                ruleId = "coverage-policy",
                delta = 0,
                message = MessageRef("score.coverage.none"),
            )
            DataVisibility.FULL -> Unit
        }

        val contributions = compact(rawContributions, config.maxContributions)
        val value = clampScore(config.baseScore + contributions.sumOf { it.delta })

        if (baseVisibility == DataVisibility.NONE) {
            return PostureScore(
                value = null,
                band = PostureBand.INSUFFICIENT_COVERAGE,
                contributions = contributions,
                visibility = DataVisibility.NONE,
            )
        }

        val naturalBand = when {
            value >= config.strongThreshold -> PostureBand.STRONG
            value >= config.moderateThreshold -> PostureBand.MODERATE
            else -> PostureBand.WEAK
        }
        var band = naturalBand
        var capReason: MessageRef? = null
        if (naturalBand == PostureBand.STRONG && visibility != DataVisibility.FULL && config.partialCapsStrong) {
            band = PostureBand.MODERATE
            capReason = when {
                patchUnknown && baseVisibility == DataVisibility.FULL -> MessageRef("score.cap.patchunknown")
                baseVisibility == DataVisibility.STALE -> MessageRef("score.cap.stale")
                else -> MessageRef("score.cap.partial")
            }
        }
        return PostureScore(
            value = value,
            band = band,
            contributions = contributions,
            visibility = visibility,
            capReason = capReason,
        )
    }

    /**
     * Keeps the contribution list bounded while preserving the total delta as exactly as the
     * per-contribution bound allows. The compacted contribution is explainable itself.
     */
    private fun compact(
        contributions: MutableList<ScoreContribution>,
        maxContributions: Int,
    ): List<ScoreContribution> {
        if (contributions.size <= maxContributions) return contributions.toList()
        val keep = contributions.take(maxContributions - 1)
        val dropped = contributions.drop(maxContributions - 1)
        val droppedDelta = dropped.sumOf { it.delta }.coerceIn(-100, 100)
        val compacted = keep + ScoreContribution(
            ruleId = "score-compaction",
            delta = droppedDelta,
            message = MessageRef("score.contributions.compacted", listOf(dropped.size.toString())),
        )
        return compacted
    }

    private fun worseOf(first: DataVisibility, second: DataVisibility): DataVisibility =
        if (rank(first) >= rank(second)) first else second

    private fun rank(visibility: DataVisibility): Int = when (visibility) {
        DataVisibility.FULL -> 0
        DataVisibility.STALE -> 1
        DataVisibility.PARTIAL -> 2
        DataVisibility.NONE -> 3
    }
}
