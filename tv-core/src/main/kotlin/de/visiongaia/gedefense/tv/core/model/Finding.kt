package de.visiongaia.gedefense.tv.core.model

/** Where a finding comes from. [source] is a stable collector/rule identifier, never free text. */
data class EvidenceRef(
    val source: String,
    val collectedAtMillis: Long,
    val digest: String? = null,
) {
    init {
        require(source.matches(Regex("[a-z][a-z0-9-]{1,63}"))) { "invalid evidence source: $source" }
        require(collectedAtMillis >= 0L) { "invalid evidence timestamp" }
        require(digest == null || digest.matches(Regex("[0-9a-f]{64}"))) { "invalid evidence digest" }
    }
}

/**
 * A single, explainable security finding.
 *
 * A finding is a *review signal* backed by evidence, not a malware verdict. [title], [why] and
 * [recommendation] are user-facing message references resolved by the active [TextCatalog].
 * [id] is deterministic: it is derived from [ruleId] and the affected component so that repeated
 * scans can be correlated without inventing new identities.
 */
data class Finding(
    val id: String,
    val ruleId: String,
    val severity: Severity,
    val confidence: Confidence,
    val category: CollectorCategory,
    val title: MessageRef,
    val why: MessageRef,
    val component: String,
    val evidence: EvidenceRef,
    val recommendation: MessageRef? = null,
    val visibility: DataVisibility = DataVisibility.FULL,
    val firstSeenMillis: Long,
    val lastSeenMillis: Long,
    val policyAction: PolicyAction = PolicyAction.OBSERVE,
) {
    init {
        require(id.matches(Regex("[a-z0-9][a-z0-9._-]{2,127}"))) { "invalid finding id: $id" }
        require(ruleId.matches(Regex("[a-z][a-z0-9-]{2,63}"))) { "invalid rule id: $ruleId" }
        require(component.length in 1..160) { "invalid finding component" }
        require(lastSeenMillis >= firstSeenMillis) { "finding lastSeen before firstSeen" }
    }

    companion object {
        /** Deterministic finding identity: rule + subject. */
        fun identity(ruleId: String, component: String): String {
            val slug = component.lowercase().map { if (it.isLetterOrDigit()) it else '-' }.joinToString("")
            return "$ruleId.${slug.take(96).trim('-').ifEmpty { "unknown" }}"
        }
    }
}
