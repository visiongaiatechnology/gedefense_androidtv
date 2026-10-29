package de.visiongaia.gedefense.tv.core.anomaly

import de.visiongaia.gedefense.mobile.core.EnforcementClass
import de.visiongaia.gedefense.mobile.core.IpPrefix
import de.visiongaia.gedefense.mobile.core.ThreatFeedCatalog
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.mobile.core.ThreatRecord
import de.visiongaia.gedefense.tv.core.model.ContainmentRecord
import de.visiongaia.gedefense.tv.core.model.ContainmentState
import de.visiongaia.gedefense.tv.core.model.ContainmentTargetType

/**
 * Pure composition of the base threat-intelligence policy and the currently active local containments
 * into a new [ThreatIndex] for the VPN data plane.
 *
 * Invariants:
 *  - the base policy is replayed exactly via [ThreatIndex.forEachPolicyRecord] (every original feed
 *    bit is preserved, so blocking/correlating/annotating semantics do not drift);
 *  - each ACTIVE destination-prefix containment becomes one synthetic ROUTE_BLOCK record using a
 *    feed that is itself configured as ROUTE_BLOCK (IPv4 `spamhaus-drop-v4`, IPv6
 *    `spamhaus-drop-v6`);
 *  - targets are canonicalised, deduplicated, sorted deterministically and bounded by
 *    [MAX_SYNTHETIC_PREFIXES];
 *  - no I/O, no global state — the app can rebuild the policy on every containment change.
 */
fun composeThreatIndex(
    base: ThreatIndex,
    active: List<ContainmentRecord>,
): ThreatIndex {
    val builder = ThreatIndex.Builder()
    base.forEachPolicyRecord { prefix, feedBits, _ ->
        ThreatFeedCatalog.all.forEachIndexed { index, feed ->
            if (feedBits and (1L shl index) != 0L) {
                builder.add(ThreatRecord(feed.id, prefix))
            }
        }
    }

    val syntheticTargets = active
        .asSequence()
        .filter { record ->
            record.state == ContainmentState.ACTIVE &&
                record.target.type == ContainmentTargetType.DESTINATION_PREFIX
        }
        .mapNotNull { record -> PrefixSupport.parsePrefix(record.target.value) }
        .map(PrefixSupport::forceAggregation)
        .distinctBy { prefix -> prefix.toString() }
        .sortedWith(compareBy<IpPrefix> { it.family }.thenBy { it.toString() })
        .take(MAX_SYNTHETIC_PREFIXES)
        .toList()

    syntheticTargets.forEach { prefix ->
        val feedId = if (prefix.family == 4) IPV4_SYNTHETIC_FEED else IPV6_SYNTHETIC_FEED
        val feed = ThreatFeedCatalog.require(feedId)
        require(feed.enforcement == EnforcementClass.ROUTE_BLOCK) {
            "synthetic containment feed must be ROUTE_BLOCK"
        }
        builder.add(ThreatRecord(feedId, prefix))
    }
    return builder.build()
}

private const val IPV4_SYNTHETIC_FEED = "spamhaus-drop-v4"
private const val IPV6_SYNTHETIC_FEED = "spamhaus-drop-v6"

/** Hard cap of synthetic containment prefixes merged into one policy generation. */
const val MAX_SYNTHETIC_PREFIXES: Int = 64
