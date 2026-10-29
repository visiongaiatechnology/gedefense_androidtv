package de.visiongaia.gedefense.tv.core.anomaly

import de.visiongaia.gedefense.mobile.core.IpPrefix
import de.visiongaia.gedefense.tv.core.model.AnomalyKind
import de.visiongaia.gedefense.tv.core.model.ContainmentOrigin
import de.visiongaia.gedefense.tv.core.model.ContainmentPolicy
import de.visiongaia.gedefense.tv.core.model.ContainmentProposal
import de.visiongaia.gedefense.tv.core.model.ContainmentRecord
import de.visiongaia.gedefense.tv.core.model.ContainmentState
import de.visiongaia.gedefense.tv.core.model.ContainmentTarget
import de.visiongaia.gedefense.tv.core.model.ContainmentTargetType
import de.visiongaia.gedefense.tv.core.model.OutboundAnomaly

/**
 * Pure containment proposal logic for the TV "Kinetic-Lite" mode.
 *
 * Proposals are produced only when the operator opted in ([ContainmentPolicy.enabled]) and every
 * guardrail holds:
 *  - the anomaly has at least [ContainmentPolicy.minSignals] independent signal kinds;
 *  - the anomaly score is at least [ContainmentPolicy.minScore];
 *  - the package is known and not under a protected package prefix;
 *  - the country is known when [ContainmentPolicy.requireKnownCountry] is set;
 *  - a destination aggregation exists (/24 IPv4 or /64 IPv6) with at least two distinct observed
 *    destination addresses inside it (never a single CDN host/IP);
 *  - the target neither overlaps a policy allowlisted prefix nor the caller's allowlist check.
 *
 * Containment is temporary and always reversible; this object never enforces anything itself.
 */
object OutboundContainmentPolicy {

    private val REASON_CODES: Map<AnomalyKind, String> = mapOf(
        AnomalyKind.DNS_BURST to "anomaly_dns_burst",
        AnomalyKind.DESTINATION_FANOUT to "anomaly_fanout",
        AnomalyKind.BEACON_PATTERN to "anomaly_beacon",
        AnomalyKind.VOLUME_SPIKE to "anomaly_volume_spike",
        AnomalyKind.REPEATED_BLOCK to "anomaly_repeated_block",
        AnomalyKind.TRACKER_CATEGORY to "anomaly_tracker_category",
        AnomalyKind.C2_MATCH to "anomaly_c2_match",
        AnomalyKind.HIGH_RISK_CORRIDOR to "anomaly_high_risk_corridor",
    )

    fun reasonCode(kind: AnomalyKind): String = REASON_CODES.getValue(kind)

    /** Builds the canonical /24 (IPv4) or /64 (IPv6) containment target from an observed prefix. */
    fun aggregationTarget(destinationPrefix: String): ContainmentTarget? {
        val prefix = PrefixSupport.parsePrefix(destinationPrefix) ?: return null
        val aggregated = PrefixSupport.forceAggregation(prefix)
        return runCatching {
            ContainmentTarget(
                ContainmentTargetType.DESTINATION_PREFIX,
                PrefixSupport.canonicalPrefix(aggregated),
            )
        }.getOrNull()
    }

    fun propose(
        anomalies: List<OutboundAnomaly>,
        policy: ContainmentPolicy = ContainmentPolicy(),
        allowlistCheck: (String) -> Boolean = { false },
    ): List<ContainmentProposal> {
        if (!policy.enabled) return emptyList()
        val policyAllowlist = policy.allowlistedPrefixes.mapNotNull(PrefixSupport::parsePrefix)
        val acceptedTargets = ArrayList<IpPrefix>(policy.maxActive)
        val proposals = ArrayList<ContainmentProposal>(policy.maxActive)

        anomalies
            .sortedWith(compareByDescending<OutboundAnomaly> { it.score }.thenBy { it.id })
            .forEach { anomaly ->
                if (anomaly.score < policy.minScore) return@forEach
                if (anomaly.signals.map { it.kind }.distinct().size < policy.minSignals) return@forEach
                val packageName = anomaly.packageName ?: return@forEach
                if (isProtectedPackage(packageName, policy)) return@forEach
                if (policy.requireKnownCountry && !anomaly.isKnownCountry) return@forEach
                val destinationPrefix = anomaly.destinationPrefix ?: return@forEach
                val targetPrefix = PrefixSupport.parsePrefix(destinationPrefix)?.let(PrefixSupport::forceAggregation) ?: return@forEach
                val target = runCatching {
                    ContainmentTarget(
                        ContainmentTargetType.DESTINATION_PREFIX,
                        PrefixSupport.canonicalPrefix(targetPrefix),
                    )
                }.getOrNull() ?: return@forEach

                val distinctAddresses = anomaly.signals
                    .flatMap { signal -> AnomalyDetailCodec.destinationAddresses(signal.detail) }
                    .mapNotNull { raw -> PrefixSupport.parseAddress(raw) }
                    .filter { address -> de.visiongaia.gedefense.mobile.core.IpPrefix.isPublic(address) }
                    .filter { address -> targetPrefix.contains(address) }
                    .map { address -> address.toString() }
                    .distinct()
                if (distinctAddresses.size < 2) return@forEach

                if (policyAllowlist.any { allowlisted -> PrefixSupport.overlaps(allowlisted, targetPrefix) }) {
                    return@forEach
                }
                if (allowlistCheck(target.value)) return@forEach
                if (acceptedTargets.any { accepted -> PrefixSupport.overlaps(accepted, targetPrefix) }) return@forEach

                acceptedTargets += targetPrefix
                proposals += ContainmentProposal(
                    id = "prp-" + PrefixSupport.sha256Hex(
                        "${anomaly.id}|${target.value}|${reasonCode(anomaly.kind)}",
                    ).take(20),
                    target = target,
                    reasonCode = reasonCode(anomaly.kind),
                    anomalyKind = anomaly.kind,
                    anomalyScore = anomaly.score,
                    confidence = anomaly.confidence,
                    packageName = anomaly.packageName,
                    appLabel = anomaly.appLabel,
                    countryCode = anomaly.countryCode,
                    signals = anomaly.signals,
                    proposedTtlMillis = policy.defaultTtlMillis.coerceIn(
                        ContainmentProposal.MIN_TTL_MILLIS,
                        policy.maxTtlMillis,
                    ),
                )
            }
        return proposals.sortedWith(compareByDescending<ContainmentProposal> { it.anomalyScore }.thenBy { it.id })
    }

    private fun isProtectedPackage(packageName: String, policy: ContainmentPolicy): Boolean {
        // SECV2-05: exact comparison only; never treat a caller-chosen package name as protected.
        return policy.protectedPackagePrefixes.any { protected -> protected.isNotBlank() && protected == packageName }
    }


}

/**
 * Thread-safe, bounded registry of temporary containments.
 *
 * The registry enforces the opt-in policy, the active bound, overlapping-target dedupe, deterministic
 * `cnt-<hash>` ids and TTL clamping. Records are bounded to [MAX_RECORDS]; only released/expired
 * historical records are evicted, an all-active registry simply rejects further proposals.
 */
class ContainmentRegistry(
    private val policy: ContainmentPolicy = ContainmentPolicy(),
    private val clock: () -> Long = { System.currentTimeMillis() },
) {

    private val lock = Any()
    private val records = ArrayList<ContainmentRecord>(MAX_RECORDS)
    private var revisionCounter = 0L

    fun policy(): ContainmentPolicy = policy

    fun revision(): Long = synchronized(lock) { revisionCounter }

    /** Applies a proposal; returns the created record or null when a guardrail rejects it. */
    fun apply(proposal: ContainmentProposal): ContainmentRecord? = synchronized(lock) {
        if (!policy.enabled) return null
        val now = clock().coerceAtLeast(1L)
        pruneExpiredLocked(now)
        if (records.count { it.state == ContainmentState.ACTIVE } >= policy.maxActive) return null
        val targetPrefix = PrefixSupport.parsePrefix(proposal.target.value) ?: return null
        if (records.any { record ->
                record.state == ContainmentState.ACTIVE &&
                    PrefixSupport.parsePrefix(record.target.value)?.let { activePrefix ->
                        PrefixSupport.overlaps(activePrefix, targetPrefix)
                    } == true
            }
        ) {
            return null
        }
        val bucket = now / 60_000L
        val id = "cnt-" + PrefixSupport.sha256Hex(
            "${proposal.target.value}|${proposal.reasonCode}|${proposal.anomalyKind.name}|${proposal.packageName ?: "-"}|$bucket",
        ).take(20)
        if (records.any { record -> record.id == id }) return null
        if (records.size >= MAX_RECORDS) {
            val removable = records
                .filter { record -> record.state != ContainmentState.ACTIVE }
                .minByOrNull { record -> record.createdAtMillis }
                ?: return null
            records.remove(removable)
        }
        val ttl = proposal.proposedTtlMillis.coerceIn(ContainmentProposal.MIN_TTL_MILLIS, policy.maxTtlMillis)
        val record = ContainmentRecord(
            id = id,
            target = proposal.target,
            reasonCode = proposal.reasonCode,
            anomalyKind = proposal.anomalyKind,
            anomalyScore = proposal.anomalyScore,
            confidence = proposal.confidence,
            packageName = proposal.packageName,
            appLabel = proposal.appLabel,
            countryCode = proposal.countryCode,
            signals = proposal.signals,
            origin = ContainmentOrigin.AUTO,
            state = ContainmentState.ACTIVE,
            createdAtMillis = now,
            expiresAtMillis = now + ttl,
        )
        records += record
        revisionCounter += 1L
        record
    }

    fun release(id: String, nowMillis: Long = clock()): Boolean = synchronized(lock) {
        val now = nowMillis.coerceAtLeast(1L)
        pruneExpiredLocked(now)
        val record = records.firstOrNull { it.id == id && it.state == ContainmentState.ACTIVE } ?: return false
        val released = record.copy(
            state = ContainmentState.RELEASED,
            releasedAtMillis = now.coerceAtLeast(record.createdAtMillis),
        )
        replaceLocked(record, released)
        revisionCounter += 1L
        true
    }

    /** Marks all active records whose TTL elapsed as EXPIRED and returns them (deterministic order). */
    fun expire(nowMillis: Long = clock()): List<ContainmentRecord> = synchronized(lock) {
        pruneExpiredLocked(nowMillis.coerceAtLeast(1L))
    }

    fun active(nowMillis: Long = clock()): List<ContainmentRecord> = synchronized(lock) {
        pruneExpiredLocked(nowMillis.coerceAtLeast(1L))
        records
            .filter { record -> record.state == ContainmentState.ACTIVE }
            .sortedWith(compareBy<ContainmentRecord> { it.createdAtMillis }.thenBy { it.id })
    }

    fun all(limit: Int = MAX_RECORDS): List<ContainmentRecord> = synchronized(lock) {
        if (limit <= 0) return emptyList()
        records
            .sortedWith(compareByDescending<ContainmentRecord> { it.createdAtMillis }.thenBy { it.id })
            .take(limit.coerceAtMost(MAX_RECORDS))
    }

    fun isActive(target: ContainmentTarget): Boolean = synchronized(lock) {
        pruneExpiredLocked(clock().coerceAtLeast(1L))
        val prefix = PrefixSupport.parsePrefix(target.value) ?: return false
        records.any { record ->
            record.state == ContainmentState.ACTIVE &&
                PrefixSupport.parsePrefix(record.target.value)?.let { activePrefix ->
                    PrefixSupport.overlaps(activePrefix, prefix)
                } == true
        }
    }

    fun clear() {
        synchronized(lock) {
            records.clear()
            revisionCounter += 1L
        }
    }

    private fun pruneExpiredLocked(now: Long): List<ContainmentRecord> {
        val expiredActive = records
            .filter { record -> record.state == ContainmentState.ACTIVE && record.expiresAtMillis <= now }
        val replacements = expiredActive.map { record -> record.copy(state = ContainmentState.EXPIRED) }
        expiredActive.zip(replacements).forEach { (previous, replacement) ->
            replaceLocked(previous, replacement)
        }
        if (replacements.isNotEmpty()) revisionCounter += 1L
        return replacements.sortedWith(compareBy<ContainmentRecord> { it.expiresAtMillis }.thenBy { it.id })
    }

    private fun replaceLocked(previous: ContainmentRecord, replacement: ContainmentRecord) {
        val index = records.indexOfFirst { record -> record.id == previous.id }
        if (index >= 0) records[index] = replacement else records += replacement
    }

    companion object {
        const val MAX_RECORDS = 64
    }
}
