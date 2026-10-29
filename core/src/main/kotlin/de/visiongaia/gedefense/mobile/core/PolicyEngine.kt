package de.visiongaia.gedefense.mobile.core

/**
 * Pure local policy evaluation. Detection data is evidence; the policy layer decides what authority
 * that evidence receives. This keeps feed semantics out of the Android VPN transport code.
 */
enum class ThreatVerdict { ALLOW, ANNOTATE, CORRELATE, BLOCK }

data class PolicyDecision(
    val verdict: ThreatVerdict,
    val match: ThreatMatch? = null,
) {
    val blockingFeeds: List<ThreatFeed> get() = match?.blockingFeeds ?: emptyList()
}

class PolicyEngine(private val index: ThreatIndex) {
    fun evaluate(destination: IpAddress): PolicyDecision {
        val match = index.match(destination) ?: return PolicyDecision(ThreatVerdict.ALLOW)
        if (match.hasBlockingSignal) return PolicyDecision(ThreatVerdict.BLOCK, match)
        if (match.feeds.any { it.enforcement == EnforcementClass.CORRELATE_ONLY }) {
            return PolicyDecision(ThreatVerdict.CORRELATE, match)
        }
        return PolicyDecision(ThreatVerdict.ANNOTATE, match)
    }
}
