package de.visiongaia.gedefense.mobile.core

import java.security.MessageDigest

enum class PrivacyCategory {
    ADS,
    ANALYTICS,
    DEVICE_TELEMETRY,
    CRASH_REPORTING,
    DIAGNOSTICS,
    ATTRIBUTION,
    ENCRYPTED_DNS,
    ESSENTIAL_CONNECTIVITY,
    ESSENTIAL_PUSH,
    ESSENTIAL_UPDATE,
    UNKNOWN,
}

enum class PrivacyConfidence { LOW, MEDIUM, HIGH }
enum class PrivacyBreakageRisk { LOW, MEDIUM, HIGH }
enum class PrivacyAction { ALLOW, OBSERVE, BLOCK }
enum class PrivacyProfile { OFF, CONSERVATIVE, BALANCED, STRICT }

data class PrivacyProvenance(
    val sourceId: String,
    val sourceUrl: String,
    val licenseId: String,
    val observedAt: String,
) {
    init {
        require(sourceId.matches(SAFE_ID)) { "invalid privacy provenance source id" }
        require(sourceUrl.length in 8..512 && sourceUrl.startsWith("https://")) {
            "invalid privacy provenance URL"
        }
        require(licenseId.matches(SAFE_LICENSE)) { "invalid privacy provenance license" }
        require(observedAt.matches(ISO_DATE)) { "invalid privacy provenance date" }
    }

    private companion object {
        val SAFE_ID = Regex("[a-z0-9][a-z0-9._-]{1,63}")
        val SAFE_LICENSE = Regex("[A-Za-z0-9.+-]{2,64}")
        val ISO_DATE = Regex("\\d{4}-\\d{2}-\\d{2}")
    }
}

data class PrivacyRule(
    val id: String,
    val domain: String,
    val includeSubdomains: Boolean,
    val category: PrivacyCategory,
    val confidence: PrivacyConfidence,
    val breakageRisk: PrivacyBreakageRisk,
    val essential: Boolean,
    val provenance: PrivacyProvenance,
) {
    val canonicalDomain: String = canonicalPrivacyDomain(domain)
        ?: throw IllegalArgumentException("invalid privacy rule domain")

    init {
        require(id.matches(SAFE_ID)) { "invalid privacy rule id" }
        if (essential) {
            require(category == PrivacyCategory.ESSENTIAL_CONNECTIVITY || category == PrivacyCategory.ESSENTIAL_PUSH || category == PrivacyCategory.ESSENTIAL_UPDATE) {
                "essential privacy rule must use essential category"
            }
        }
    }

    private companion object {
        val SAFE_ID = Regex("[a-z0-9][a-z0-9._-]{2,95}")
    }
}



data class PrivacyPolicyRecord(
    val id: String,
    val domain: String,
    val includeSubdomains: Boolean,
    val essential: Boolean,
    val confidence: PrivacyConfidence,
    val breakageRisk: PrivacyBreakageRisk,
    val action: PrivacyAction,
)

data class PrivacyDecision(
    val action: PrivacyAction,
    val category: PrivacyCategory,
    val confidence: PrivacyConfidence,
    val breakageRisk: PrivacyBreakageRisk,
    val ruleId: String?,
    val sourceId: String?,
    val matchedDomain: String?,
) {
    companion object {
        fun unknown(): PrivacyDecision = PrivacyDecision(
            action = PrivacyAction.ALLOW,
            category = PrivacyCategory.UNKNOWN,
            confidence = PrivacyConfidence.LOW,
            breakageRisk = PrivacyBreakageRisk.HIGH,
            ruleId = null,
            sourceId = null,
            matchedDomain = null,
        )
    }
}

/**
 * Immutable local-only privacy intelligence index.
 *
 * Rules never gain blocking authority merely because they exist in a downloaded/community data set.
 * Blocking authority is derived locally from profile + confidence + breakage risk. Essential rules
 * always override telemetry rules, regardless of insertion order.
 */
class PrivacyIntelligenceRegistry private constructor(
    private val exact: Map<String, List<PrivacyRule>>,
    private val suffix: Map<String, List<PrivacyRule>>,
    val count: Int,
    val fingerprintSha256: String,
) {
    fun decide(rawDomain: String, profile: PrivacyProfile): PrivacyDecision {
        if (profile == PrivacyProfile.OFF) return PrivacyDecision.unknown()
        val domain = canonicalPrivacyDomain(rawDomain) ?: return PrivacyDecision.unknown()
        val candidates = ArrayList<PrivacyRule>(8)
        exact[domain]?.let(candidates::addAll)
        var cursor = domain
        while (true) {
            suffix[cursor]?.let(candidates::addAll)
            val dot = cursor.indexOf('.')
            if (dot < 0 || dot + 1 >= cursor.length) break
            cursor = cursor.substring(dot + 1)
        }
        if (candidates.isEmpty()) return PrivacyDecision.unknown()

        val essential = candidates.filter { it.essential }.maxWithOrNull(RULE_PRECEDENCE)
        if (essential != null) return decisionFor(essential, PrivacyAction.ALLOW)

        val selected = candidates.maxWithOrNull(RULE_PRECEDENCE) ?: return PrivacyDecision.unknown()
        return decisionFor(selected, actionFor(selected, profile))
    }

    fun forEachRule(action: (PrivacyRule) -> Unit) {
        val seen = HashSet<String>(count)
        (exact.values.asSequence() + suffix.values.asSequence())
            .flatten()
            .sortedWith(compareBy<PrivacyRule>({ it.canonicalDomain }, { it.id }))
            .forEach { rule -> if (seen.add(rule.id)) action(rule) }
    }

    /**
     * Deterministic, transport-safe representation of this registry for GaiaNet. The native side
     * receives the locally derived action for each signed rule, but still re-applies overlap and
     * essential-service precedence before enforcing a DNS decision.
     */
    fun policyRecords(profile: PrivacyProfile): List<PrivacyPolicyRecord> {
        val out = ArrayList<PrivacyPolicyRecord>(count)
        forEachRule { rule ->
            out += PrivacyPolicyRecord(
                id = rule.id,
                domain = rule.canonicalDomain,
                includeSubdomains = rule.includeSubdomains,
                essential = rule.essential,
                confidence = rule.confidence,
                breakageRisk = rule.breakageRisk,
                action = actionFor(rule, profile),
            )
        }
        return out
    }

    companion object {
        private val RULE_PRECEDENCE = compareBy<PrivacyRule>(
            { if (it.essential) 1 else 0 },
            { it.confidence.ordinal },
            { -it.breakageRisk.ordinal },
            { it.canonicalDomain.length },
            { it.id },
        )

        fun build(rules: Collection<PrivacyRule>, maxRules: Int = 8192): PrivacyIntelligenceRegistry {
            require(maxRules in 1..65536) { "privacy rule bound invalid" }
            require(rules.size <= maxRules) { "privacy rule bound exceeded" }
            val ids = HashSet<String>(rules.size)
            val exact = LinkedHashMap<String, MutableList<PrivacyRule>>()
            val suffix = LinkedHashMap<String, MutableList<PrivacyRule>>()
            val digest = MessageDigest.getInstance("SHA-256")
            val sorted = rules.sortedWith(compareBy<PrivacyRule>({ it.canonicalDomain }, { it.id }))
            for (rule in sorted) {
                require(ids.add(rule.id)) { "duplicate privacy rule id" }
                val target = if (rule.includeSubdomains) suffix else exact
                target.getOrPut(rule.canonicalDomain) { ArrayList(1) }.add(rule)
                updateFingerprint(digest, rule)
            }
            return PrivacyIntelligenceRegistry(
                exact = exact.mapValues { it.value.toList() },
                suffix = suffix.mapValues { it.value.toList() },
                count = sorted.size,
                fingerprintSha256 = hex(digest.digest()),
            )
        }

        private fun actionFor(rule: PrivacyRule, profile: PrivacyProfile): PrivacyAction {
            if (rule.essential) return PrivacyAction.ALLOW
            return when (profile) {
                PrivacyProfile.OFF -> PrivacyAction.ALLOW
                PrivacyProfile.CONSERVATIVE -> if (
                    rule.confidence == PrivacyConfidence.HIGH &&
                    rule.breakageRisk == PrivacyBreakageRisk.LOW &&
                    rule.category in CONSERVATIVE_BLOCK_CATEGORIES
                ) PrivacyAction.BLOCK else PrivacyAction.OBSERVE
                PrivacyProfile.BALANCED -> if (
                    rule.confidence != PrivacyConfidence.LOW &&
                    rule.breakageRisk == PrivacyBreakageRisk.LOW &&
                    rule.category in BALANCED_BLOCK_CATEGORIES
                ) PrivacyAction.BLOCK else PrivacyAction.OBSERVE
                PrivacyProfile.STRICT -> if (
                    rule.confidence != PrivacyConfidence.LOW &&
                    rule.breakageRisk != PrivacyBreakageRisk.HIGH &&
                    rule.category !in ESSENTIAL_CATEGORIES
                ) PrivacyAction.BLOCK else PrivacyAction.OBSERVE
            }
        }

        private fun decisionFor(rule: PrivacyRule, action: PrivacyAction) = PrivacyDecision(
            action = action,
            category = rule.category,
            confidence = rule.confidence,
            breakageRisk = rule.breakageRisk,
            ruleId = rule.id,
            sourceId = rule.provenance.sourceId,
            matchedDomain = rule.canonicalDomain,
        )

        private fun updateFingerprint(digest: MessageDigest, rule: PrivacyRule) {
            val record = buildString(768) {
                append(rule.id).append('\u0000')
                append(rule.canonicalDomain).append('\u0000')
                append(if (rule.includeSubdomains) '1' else '0').append('\u0000')
                append(rule.category.name).append('\u0000')
                append(rule.confidence.name).append('\u0000')
                append(rule.breakageRisk.name).append('\u0000')
                append(if (rule.essential) '1' else '0').append('\u0000')
                append(rule.provenance.sourceId).append('\u0000')
                append(rule.provenance.sourceUrl).append('\u0000')
                append(rule.provenance.licenseId).append('\u0000')
                append(rule.provenance.observedAt).append('\n')
            }
            digest.update(record.toByteArray(Charsets.UTF_8))
        }

        private fun hex(bytes: ByteArray): String {
            val alphabet = "0123456789abcdef"
            val chars = CharArray(bytes.size * 2)
            var offset = 0
            for (byte in bytes) {
                val value = byte.toInt() and 0xff
                chars[offset++] = alphabet[value ushr 4]
                chars[offset++] = alphabet[value and 0x0f]
            }
            return String(chars)
        }

        private val ESSENTIAL_CATEGORIES = setOf(
            PrivacyCategory.ESSENTIAL_CONNECTIVITY,
            PrivacyCategory.ESSENTIAL_PUSH,
            PrivacyCategory.ESSENTIAL_UPDATE,
        )
        private val CONSERVATIVE_BLOCK_CATEGORIES = setOf(
            PrivacyCategory.ADS,
            PrivacyCategory.ANALYTICS,
            PrivacyCategory.ATTRIBUTION,
        )
        private val BALANCED_BLOCK_CATEGORIES = CONSERVATIVE_BLOCK_CATEGORIES + PrivacyCategory.DEVICE_TELEMETRY
    }
}

fun canonicalPrivacyDomain(raw: String): String? {
    val value = raw.trim().trimEnd('.').lowercase()
    if (value.length !in 1..253 || value.startsWith('.') || value.endsWith('.') || ".." in value) return null
    val labels = value.split('.')
    if (labels.size < 2) return null
    for (label in labels) {
        if (label.length !in 1..63 || label.startsWith('-') || label.endsWith('-')) return null
        if (label.any { ch -> !(ch in 'a'..'z' || ch in '0'..'9' || ch == '-') }) return null
    }
    return value
}
