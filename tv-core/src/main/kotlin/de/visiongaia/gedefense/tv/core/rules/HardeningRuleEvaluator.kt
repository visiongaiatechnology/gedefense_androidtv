package de.visiongaia.gedefense.tv.core.rules

import de.visiongaia.gedefense.tv.core.model.EvidenceRef
import de.visiongaia.gedefense.tv.core.model.Finding
import de.visiongaia.gedefense.tv.core.model.HardeningObservations

/**
 * Pure hardening rule engine. It receives read-only observations and turns them into findings.
 *
 * Mandatory behaviour:
 *  - unreadable values produce visibility notes, never "secure";
 *  - every finding carries evidence, a stable rule id and a recommendation message;
 *  - risky automation is never proposed: V1 recommendations are manual steps for the user.
 */
interface HardeningRuleEvaluator {
    fun evaluate(observations: HardeningObservations, evidence: EvidenceRef): List<Finding>
}
