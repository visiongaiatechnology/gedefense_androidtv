package de.visiongaia.gedefense.tv.core.score

import de.visiongaia.gedefense.tv.core.model.CollectorResult
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.PatchAssessment
import de.visiongaia.gedefense.tv.core.model.PostureScore

/**
 * Turns collector results into an explainable posture score.
 *
 * Rules (mandatory):
 *  - every non-zero contribution is a [de.visiongaia.gedefense.tv.core.model.ScoreContribution]
 *    with a stable rule id and a message reference that the catalog can resolve;
 *  - [DataVisibility.NONE] coverage yields [de.visiongaia.gedefense.tv.core.model.PostureBand.INSUFFICIENT_COVERAGE]
 *    and a null numeric value;
 *  - partial/stale coverage may never produce `STRONG`;
 *  - an old patch level is reported as "old", never as "known vulnerable".
 */
interface ScoringEngine {
    fun score(results: List<CollectorResult>, patch: PatchAssessment): PostureScore
}

/**
 * Aggregation of per-collector visibility into one honest overall visibility.
 *
 * Implemented as a pure object so the UI, report and event layers share exactly one definition.
 */
interface CoverageAggregator {
    fun aggregate(results: List<CollectorResult>): DataVisibility
}
