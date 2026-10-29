package de.visiongaia.gedefense.tv.core.policy

import de.visiongaia.gedefense.mobile.core.EnforcementClass
import de.visiongaia.gedefense.mobile.core.FeedSemantics
import de.visiongaia.gedefense.mobile.core.PrivacyAction
import de.visiongaia.gedefense.mobile.core.PrivacyCategory
import de.visiongaia.gedefense.mobile.core.PrivacyConfidence
import de.visiongaia.gedefense.mobile.core.PrivacyIntelligenceRegistry
import de.visiongaia.gedefense.mobile.core.PrivacyProfile
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.tv.core.model.Confidence
import de.visiongaia.gedefense.tv.core.model.TrafficAction
import de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile
import java.util.Locale

/** Which local data source produced a [TrafficDecision]. */
enum class TrafficMatchSource { THREAT_INTEL, PRIVACY_INTELLIGENCE, TRACKER_CATALOG, NONE }

/**
 * Complete, explainable traffic decision for one observed destination.
 *
 * [reasonCode] is a stable machine code (see [TrafficPolicy] constants, e.g.
 * `ti_route_block`), [ruleId] names the concrete threat/privacy/tracker rule and [source] tells the
 * UI which local data set matched. No field is guessed: an unmatched destination is
 * `ALLOW / no_signal / NONE`.
 */
data class TrafficDecision(
    val action: TrafficAction,
    val reasonCode: String,
    val ruleId: String,
    val category: TrackerCategory?,
    val source: TrafficMatchSource,
    val confidence: Confidence,
)

/** Input of one local policy evaluation. Both identifiers are optional; absent data is not guessed. */
data class TrafficPolicyRequest(
    val destinationAddress: String? = null,
    val destinationDomain: String? = null,
    val profile: TvPrivacyProfile = TvPrivacyProfile.BALANCED,
)

/**
 * Pure, network-free traffic policy for the local loopback VPN.
 *
 * Signal precedence is deterministic:
 *  1. a blocking threat-intelligence match always blocks;
 *  2. a privacy-intelligence ALLOW (essential service) suppresses local tracker heuristics;
 *  3. otherwise the strongest action wins, and on ties threat intel beats privacy, privacy beats
 *     the curated tracker catalog.
 *
 * All rules are local; the policy never performs I/O and never enforces by itself.
 */
class TrafficPolicy(
    private val threatIndex: ThreatIndex = ThreatIndex.empty(),
    private val privacyRegistry: PrivacyIntelligenceRegistry? = null,
    private val trackerCatalog: TrackerCatalog = TrackerCatalog.TV_DEFAULT,
) {

    fun evaluate(request: TrafficPolicyRequest): TrafficDecision {
        val threat = evaluateThreat(request.destinationAddress)
        if (threat != null && threat.action == TrafficAction.BLOCK) return threat

        val privacy = evaluatePrivacy(request.destinationDomain, request.profile)
        if (privacy != null && privacy.action == TrafficAction.ALLOW) return privacy

        val tracker = evaluateTracker(request.destinationDomain, request.profile)
        val candidates = listOfNotNull(threat, privacy, tracker)
        if (candidates.isEmpty()) return NO_SIGNAL_DECISION
        return candidates.maxWith(SELECTION)
    }

    /** Convenience overload for callers that do not build a request object. */
    fun evaluate(
        destinationAddress: String?,
        destinationDomain: String?,
        profile: TvPrivacyProfile,
    ): TrafficDecision = evaluate(
        TrafficPolicyRequest(
            destinationAddress = destinationAddress,
            destinationDomain = destinationDomain,
            profile = profile,
        ),
    )

    private fun evaluateThreat(address: String?): TrafficDecision? {
        if (address.isNullOrBlank()) return null
        val match = threatIndex.match(address) ?: return null
        val blocking = match.feeds.filter { it.enforcement == EnforcementClass.ROUTE_BLOCK }
        val correlating = match.feeds.filter { it.enforcement == EnforcementClass.CORRELATE_ONLY }
        val annotating = match.feeds.filter { it.enforcement == EnforcementClass.ANNOTATE_ONLY }
        val selected = when {
            blocking.isNotEmpty() -> blocking
            correlating.isNotEmpty() -> correlating
            annotating.isNotEmpty() -> annotating
            else -> return null
        }
        val action = when {
            blocking.isNotEmpty() -> TrafficAction.BLOCK
            correlating.isNotEmpty() -> TrafficAction.CORRELATE
            else -> TrafficAction.ANNOTATE
        }
        val reasonCode = when (action) {
            TrafficAction.BLOCK -> REASON_TI_BLOCK
            TrafficAction.CORRELATE -> REASON_TI_CORRELATE
            else -> REASON_TI_ANNOTATE
        }
        val confidence = if (action == TrafficAction.BLOCK) Confidence.HIGH else Confidence.MEDIUM
        val category = if (match.feeds.any { it.semantics == FeedSemantics.MALICIOUS_C2 }) {
            TrackerCategory.C2
        } else {
            null
        }
        val ruleId = "ti." + selected.map { it.id }.distinct().sorted().joinToString("+").take(120)
        return TrafficDecision(action, reasonCode, ruleId, category, TrafficMatchSource.THREAT_INTEL, confidence)
    }

    private fun evaluatePrivacy(domain: String?, profile: TvPrivacyProfile): TrafficDecision? {
        val registry = privacyRegistry ?: return null
        if (domain.isNullOrBlank()) return null
        val decision = registry.decide(domain, profile.toPrivacyProfile())
        val ruleId = decision.ruleId ?: return null
        val action = when (decision.action) {
            PrivacyAction.BLOCK -> TrafficAction.BLOCK
            PrivacyAction.OBSERVE -> TrafficAction.ANNOTATE
            PrivacyAction.ALLOW -> TrafficAction.ALLOW
        }
        val reasonCode = when (action) {
            TrafficAction.BLOCK -> REASON_PRIVACY_BLOCK
            TrafficAction.ANNOTATE -> REASON_PRIVACY_OBSERVE
            else -> if (decision.category in ESSENTIAL_PRIVACY_CATEGORIES) {
                REASON_PRIVACY_ESSENTIAL_ALLOW
            } else {
                REASON_PRIVACY_ALLOW
            }
        }
        return TrafficDecision(
            action = action,
            reasonCode = reasonCode,
            ruleId = ruleId,
            category = decision.category.toTrackerCategory(),
            source = TrafficMatchSource.PRIVACY_INTELLIGENCE,
            confidence = decision.confidence.toModelConfidence(),
        )
    }

    private fun evaluateTracker(domain: String?, profile: TvPrivacyProfile): TrafficDecision? {
        if (domain.isNullOrBlank()) return null
        val rule = trackerCatalog.match(domain) ?: return null
        if (profile == TvPrivacyProfile.OFF) {
            return TrafficDecision(
                action = TrafficAction.ALLOW,
                reasonCode = REASON_TRACKER_OFF_PROFILE,
                ruleId = rule.id,
                category = rule.category,
                source = TrafficMatchSource.TRACKER_CATALOG,
                confidence = rule.confidence,
            )
        }
        val action = when {
            rule.category == TrackerCategory.C2 -> TrafficAction.BLOCK
            profile == TvPrivacyProfile.CONSERVATIVE ->
                if (rule.confidence == Confidence.HIGH) TrafficAction.BLOCK else TrafficAction.ANNOTATE
            profile == TvPrivacyProfile.BALANCED ->
                if (rule.confidence != Confidence.LOW) TrafficAction.BLOCK else TrafficAction.ANNOTATE
            else -> TrafficAction.BLOCK
        }
        val reasonCode = "tracker_${rule.category.name.lowercase(Locale.ROOT)}_${action.name.lowercase(Locale.ROOT)}"
        return TrafficDecision(
            action = action,
            reasonCode = reasonCode,
            ruleId = rule.id,
            category = rule.category,
            source = TrafficMatchSource.TRACKER_CATALOG,
            confidence = rule.confidence,
        )
    }

    companion object {
        const val REASON_TI_BLOCK = "ti_route_block"
        const val REASON_TI_CORRELATE = "ti_correlate"
        const val REASON_TI_ANNOTATE = "ti_annotate"
        const val REASON_PRIVACY_BLOCK = "privacy_block"
        const val REASON_PRIVACY_OBSERVE = "privacy_observe"
        const val REASON_PRIVACY_ALLOW = "privacy_allow"
        const val REASON_PRIVACY_ESSENTIAL_ALLOW = "privacy_essential_allow"
        const val REASON_TRACKER_OFF_PROFILE = "tracker_off_profile"
        const val REASON_NO_SIGNAL = "no_signal"

        private val NO_SIGNAL_DECISION = TrafficDecision(
            action = TrafficAction.ALLOW,
            reasonCode = REASON_NO_SIGNAL,
            ruleId = "none",
            category = null,
            source = TrafficMatchSource.NONE,
            confidence = Confidence.LOW,
        )

        private val ESSENTIAL_PRIVACY_CATEGORIES = setOf(
            PrivacyCategory.ESSENTIAL_CONNECTIVITY,
            PrivacyCategory.ESSENTIAL_PUSH,
            PrivacyCategory.ESSENTIAL_UPDATE,
        )

        private fun actionRank(action: TrafficAction): Int = when (action) {
            TrafficAction.ALLOW -> 0
            TrafficAction.ANNOTATE -> 1
            TrafficAction.CORRELATE -> 2
            TrafficAction.BLOCK -> 3
        }

        private fun sourcePriority(source: TrafficMatchSource): Int = when (source) {
            TrafficMatchSource.THREAT_INTEL -> 3
            TrafficMatchSource.PRIVACY_INTELLIGENCE -> 2
            TrafficMatchSource.TRACKER_CATALOG -> 1
            TrafficMatchSource.NONE -> 0
        }

        private val SELECTION = compareBy<TrafficDecision>(
            { actionRank(it.action) },
            { sourcePriority(it.source) },
        )
    }
}

/** Maps the TV settings profile to the vendored privacy engine's profile enum. */
fun TvPrivacyProfile.toPrivacyProfile(): PrivacyProfile = when (this) {
    TvPrivacyProfile.OFF -> PrivacyProfile.OFF
    TvPrivacyProfile.CONSERVATIVE -> PrivacyProfile.CONSERVATIVE
    TvPrivacyProfile.BALANCED -> PrivacyProfile.BALANCED
    TvPrivacyProfile.STRICT -> PrivacyProfile.STRICT
}

/** Maps a privacy-intelligence category to the shared TV tracker category (null = no public category). */
fun PrivacyCategory.toTrackerCategory(): TrackerCategory? = when (this) {
    PrivacyCategory.ADS -> TrackerCategory.ADS
    PrivacyCategory.ANALYTICS -> TrackerCategory.ANALYTICS
    PrivacyCategory.ATTRIBUTION -> TrackerCategory.ANALYTICS
    PrivacyCategory.DEVICE_TELEMETRY -> TrackerCategory.TELEMETRY
    PrivacyCategory.CRASH_REPORTING -> TrackerCategory.TELEMETRY
    PrivacyCategory.DIAGNOSTICS -> TrackerCategory.TELEMETRY
    PrivacyCategory.ENCRYPTED_DNS,
    PrivacyCategory.ESSENTIAL_CONNECTIVITY,
    PrivacyCategory.ESSENTIAL_PUSH,
    PrivacyCategory.ESSENTIAL_UPDATE,
    PrivacyCategory.UNKNOWN,
    -> null
}

private fun PrivacyConfidence.toModelConfidence(): Confidence = when (this) {
    PrivacyConfidence.LOW -> Confidence.LOW
    PrivacyConfidence.MEDIUM -> Confidence.MEDIUM
    PrivacyConfidence.HIGH -> Confidence.HIGH
}
