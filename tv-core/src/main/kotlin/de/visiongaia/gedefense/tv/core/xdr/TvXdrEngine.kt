package de.visiongaia.gedefense.tv.core.xdr

import de.visiongaia.gedefense.mobile.core.FeedSemantics
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.tv.core.model.CollectorCategory
import de.visiongaia.gedefense.tv.core.model.Confidence
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.EvidenceRef
import de.visiongaia.gedefense.tv.core.model.Finding
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.PolicyAction
import de.visiongaia.gedefense.tv.core.model.Severity
import de.visiongaia.gedefense.tv.core.model.TrafficAction
import de.visiongaia.gedefense.tv.core.model.TrafficFlow
import de.visiongaia.gedefense.tv.core.model.TrafficSnapshot
import de.visiongaia.gedefense.tv.core.policy.TrackerCatalog
import de.visiongaia.gedefense.tv.core.policy.TrackerCategory
import java.util.Locale
import kotlin.math.min

/** Tunable bounds and thresholds of the TV XDR-light engine. */
data class XdrConfig(
    val windowMillis: Long = 15L * 60L * 1_000L,
    val dedupeWindowMillis: Long = 10L * 60L * 1_000L,
    val repeatedBlockThreshold: Int = 3,
    val maxIncidents: Int = 32,
    val maxKnownApps: Int = 512,
    val maxDedupeEntries: Int = 512,
    val scanFlowLimit: Int = 500,
    val highRiskCountries: Set<String> = setOf("RU", "CN", "IR", "KP", "SY"),
    val trackerCategories: Set<TrackerCategory> = setOf(TrackerCategory.TELEMETRY, TrackerCategory.ACR),
) {
    init {
        require(windowMillis in 60_000L..(24L * 60L * 60L * 1_000L)) { "invalid XDR window" }
        require(dedupeWindowMillis in 60_000L..(24L * 60L * 60L * 1_000L)) { "invalid XDR dedupe window" }
        require(repeatedBlockThreshold in 1..100) { "invalid repeat threshold" }
        require(maxIncidents in 1..128) { "invalid incident bound" }
        require(maxKnownApps in 1..4096) { "invalid known app bound" }
        require(maxDedupeEntries in 1..4096) { "invalid dedupe bound" }
        require(scanFlowLimit in 1..2_000) { "invalid flow scan bound" }
        require(highRiskCountries.all { it.matches(Regex("[A-Z]{2}")) }) { "invalid high risk country code" }
    }
}

/** Independent local evidence classes that the TV XDR-light engine correlates. */
enum class XdrSignalKind { REPEATED_BLOCKED, TRACKER_BLOCK, NEW_APP, C2_MATCH, HIGH_RISK_CORRIDOR }

/** One explainable score contribution inside an [XdrIncident]. */
data class XdrSignal(
    val kind: XdrSignalKind,
    val score: Int,
    val detail: String,
    val count: Int = 1,
    val category: TrackerCategory? = null,
    val countryCode: String? = null,
    val destination: String? = null,
) {
    init {
        require(score in 0..100) { "invalid XDR signal score" }
        require(detail.isNotBlank() && detail.length <= 200) { "invalid XDR signal detail" }
        require(count >= 1) { "invalid XDR signal count" }
        require(countryCode == null || countryCode.matches(Regex("[A-Z]{2}"))) { "invalid XDR signal country" }
    }
}

/**
 * One explainable, bounded XDR-light incident.
 *
 * The incident is a correlation result, not an enforcement order: [policyAction] is always
 * [PolicyAction.OBSERVE] and [toFinding] maps it into the shared TV finding model with partial
 * visibility, because VPN telemetry never proves complete device coverage.
 */
data class XdrIncident(
    val id: String,
    val ruleId: String,
    val severity: Severity,
    val confidence: Confidence,
    val score: Int,
    val packageName: String?,
    val countryCode: String?,
    val category: TrackerCategory?,
    val signals: List<XdrSignal>,
    val title: MessageRef,
    val why: MessageRef,
    val recommendation: MessageRef,
    val firstSeenMillis: Long,
    val lastSeenMillis: Long,
    val count: Int,
    val collectorCategory: CollectorCategory,
    val policyAction: PolicyAction = PolicyAction.OBSERVE,
) {
    init {
        require(id.matches(Regex("[a-z0-9][a-z0-9._-]{2,127}"))) { "invalid XDR incident id: $id" }
        require(ruleId.matches(Regex("[a-z][a-z0-9-]{2,63}"))) { "invalid XDR rule id: $ruleId" }
        require(score in 0..100) { "invalid XDR incident score" }
        require(signals.isNotEmpty() && signals.size <= 16) { "invalid XDR signal list" }
        require(lastSeenMillis >= firstSeenMillis) { "XDR incident time order invalid" }
        require(count >= 1) { "invalid XDR incident count" }
    }

    fun toFinding(evidence: EvidenceRef): Finding = Finding(
        id = id,
        ruleId = ruleId,
        severity = severity,
        confidence = confidence,
        category = collectorCategory,
        title = title,
        why = why,
        component = packageName ?: countryCode ?: "device",
        evidence = evidence,
        recommendation = recommendation,
        visibility = DataVisibility.PARTIAL,
        firstSeenMillis = firstSeenMillis,
        lastSeenMillis = lastSeenMillis,
        policyAction = policyAction,
    )
}

/**
 * Deterministic XDR-light evaluation over locally observed flow history.
 *
 * Rules: repeated blocked flows per app, blocked telemetry/ACR categories per app, first-seen app
 * traffic, C2 threat-intelligence matches and high-risk-country corridors (INFO only). Independent
 * signals for the same app are correlated into one explainable incident with a summed score.
 *
 * State is bounded: the known-app set, dedupe table and incident output all have hard caps. No rule
 * auto-enforces anything; blocked flows are already blocked by the data plane policy.
 */
class TvXdrEngine(
    private val trackerCatalog: TrackerCatalog = TrackerCatalog.TV_DEFAULT,
    private val threatIndex: ThreatIndex = ThreatIndex.empty(),
    private val config: XdrConfig = XdrConfig(),
    private val clock: () -> Long = { System.currentTimeMillis() },
) {
    private val lock = Any()
    private val knownApps = LinkedHashSet<String>()
    private val dedupe = LinkedHashMap<String, Long>()

    /** Number of apps already seen; bounded by [XdrConfig.maxKnownApps]. */
    val knownAppCount: Int get() = synchronized(lock) { knownApps.size }

    /** Clears correlation/dedupe state (e.g. on VPN restart). */
    fun reset() {
        synchronized(lock) {
            knownApps.clear()
            dedupe.clear()
        }
    }

    fun evaluate(
        snapshot: TrafficSnapshot,
        flows: List<TrafficFlow>,
        nowMillis: Long = clock(),
    ): List<XdrIncident> = synchronized(lock) {
        if (flows.isEmpty() && !snapshot.hasObservation) return emptyList()
        val now = nowMillis
        val windowStart = now - config.windowMillis
        val considered = flows.asSequence()
            .filter { flow -> flow.lastSeenMillis in windowStart..now && flow.openedAtMillis <= now }
            .sortedWith(compareByDescending<TrafficFlow> { it.lastSeenMillis }.thenBy { it.id })
            .take(config.scanFlowLimit)
            .toList()
        if (considered.isEmpty()) return emptyList()

        val signalsByPackage = LinkedHashMap<String, MutableList<XdrSignal>>()
        val firstSeenByPackage = LinkedHashMap<String, Long>()
        val lastSeenByPackage = LinkedHashMap<String, Long>()

        fun observePackage(flow: TrafficFlow) {
            firstSeenByPackage[flow.ownerPackage] =
                minOf(firstSeenByPackage[flow.ownerPackage] ?: flow.openedAtMillis, flow.openedAtMillis)
            lastSeenByPackage[flow.ownerPackage] =
                maxOf(lastSeenByPackage[flow.ownerPackage] ?: flow.lastSeenMillis, flow.lastSeenMillis)
        }

        fun addSignal(packageName: String, signal: XdrSignal) {
            signalsByPackage.getOrPut(packageName) { ArrayList(4) }.add(signal)
        }

        considered.forEach(::observePackage)

        // Rule 1: repeated blocked flows per app.
        val blockedCounts = LinkedHashMap<String, Int>()
        considered.forEach { flow ->
            if (flow.action == TrafficAction.BLOCK) {
                blockedCounts[flow.ownerPackage] = (blockedCounts[flow.ownerPackage] ?: 0) + 1
            }
        }
        blockedCounts.forEach { (packageName, count) ->
            if (count >= config.repeatedBlockThreshold) {
                val score = min(45, 25 + 5 * (count - config.repeatedBlockThreshold))
                addSignal(
                    packageName,
                    XdrSignal(
                        kind = XdrSignalKind.REPEATED_BLOCKED,
                        score = score,
                        detail = "blocked_flows=$count",
                        count = count,
                    ),
                )
            }
        }

        // Rule 2: blocked telemetry/ACR tracker categories per app.
        val trackerGroups = LinkedHashMap<String, TrackerGroup>()
        considered.forEach { flow ->
            if (flow.action != TrafficAction.BLOCK) return@forEach
            val domain = flow.destinationDomain ?: return@forEach
            val rule = trackerCatalog.match(domain) ?: return@forEach
            if (rule.category !in config.trackerCategories) return@forEach
            val key = flow.ownerPackage + "\u0000" + rule.category.name
            val group = trackerGroups.getOrPut(key) {
                TrackerGroup(flow.ownerPackage, rule.category, mutableSetOf())
            }
            group.domains += rule.canonicalDomain
        }
        trackerGroups.values.forEach { group ->
            val score = when (group.category) {
                TrackerCategory.ACR -> 30
                TrackerCategory.ADS, TrackerCategory.ANALYTICS -> 20
                TrackerCategory.TELEMETRY -> 15
                TrackerCategory.C2 -> 60
            }
            addSignal(
                group.packageName,
                XdrSignal(
                    kind = XdrSignalKind.TRACKER_BLOCK,
                    score = score,
                    detail = "domains=${group.domains.sorted().joinToString(",").take(160)}",
                    count = group.domains.size,
                    category = group.category,
                ),
            )
        }

        // Rule 3: first-seen app traffic (session-scoped, bounded known-app set).
        val seenInWindow = LinkedHashSet<String>()
        considered.forEach { flow -> seenInWindow += flow.ownerPackage }
        seenInWindow.forEach { packageName ->
            if (knownApps.add(packageName)) {
                addSignal(
                    packageName,
                    XdrSignal(
                        kind = XdrSignalKind.NEW_APP,
                        score = 5,
                        detail = "first_seen_package",
                    ),
                )
                while (knownApps.size > config.maxKnownApps) {
                    val iterator = knownApps.iterator()
                    if (!iterator.hasNext()) break
                    iterator.next()
                    iterator.remove()
                }
            }
        }

        // Rule 4: C2 threat-intelligence match on the observed destination.
        val c2Groups = LinkedHashMap<String, C2Group>()
        considered.forEach { flow ->
            val match = threatIndex.match(flow.destinationAddress) ?: return@forEach
            val c2Feeds = match.feeds.filter { it.semantics == FeedSemantics.MALICIOUS_C2 }
            if (c2Feeds.isEmpty()) return@forEach
            val group = c2Groups.getOrPut(flow.ownerPackage) {
                C2Group(mutableSetOf(), mutableSetOf())
            }
            group.feeds += c2Feeds.map { it.id }
            group.addresses += flow.destinationAddress
        }
        c2Groups.forEach { (packageName, group) ->
            addSignal(
                packageName,
                XdrSignal(
                    kind = XdrSignalKind.C2_MATCH,
                    score = 60,
                    detail = "feeds=${group.feeds.sorted().joinToString(",")}",
                    count = group.addresses.size,
                    category = TrackerCategory.C2,
                    destination = group.addresses.sorted().first(),
                ),
            )
        }

        // Rule 5: corridor to a high-risk country. Weak geo signal, INFO only.
        val corridorGroups = LinkedHashMap<String, MutableSet<String>>()
        considered.forEach { flow ->
            val country = flow.countryCode ?: return@forEach
            if (country !in config.highRiskCountries) return@forEach
            corridorGroups.getOrPut(flow.ownerPackage) { LinkedHashSet() } += country
        }
        corridorGroups.forEach { (packageName, countryCodes) ->
            addSignal(
                packageName,
                XdrSignal(
                    kind = XdrSignalKind.HIGH_RISK_CORRIDOR,
                    score = 5 * min(countryCodes.size, 4),
                    detail = "countries=${countryCodes.sorted().joinToString(",")}",
                    count = countryCodes.size,
                    countryCode = countryCodes.sorted().first(),
                ),
            )
        }

        val incidents = ArrayList<XdrIncident>()
        signalsByPackage.forEach { (packageName, signals) ->
            if (signals.isEmpty()) return@forEach
            val orderedSignals = signals.sortedWith(
                compareBy<XdrSignal> { it.kind.ordinal }.thenBy { it.detail },
            )
            val kinds = orderedSignals.map { it.kind }.distinct()
            val firstSeen = firstSeenByPackage[packageName] ?: now
            val lastSeen = lastSeenByPackage[packageName] ?: now
            if (kinds.size >= 2) {
                incidents += correlatedIncident(packageName, orderedSignals, firstSeen, lastSeen)
            } else {
                orderedSignals.forEach { signal ->
                    incidents += atomicIncident(packageName, signal, firstSeen, lastSeen)
                }
            }
        }

        // Dedupe per incident and time bucket; the table is bounded and pruned.
        val emitted = ArrayList<XdrIncident>(incidents.size)
        incidents.forEach { incident ->
            val bucket = now / config.dedupeWindowMillis
            val key = "${incident.id}|$bucket"
            if (dedupe.containsKey(key)) return@forEach
            dedupe[key] = now
            emitted += incident
        }
        pruneDedupe(now)
        emitted
            .sortedWith(
                compareByDescending<XdrIncident> { it.severity.rank }
                    .thenByDescending { it.score }
                    .thenBy { it.packageName ?: "" }
                    .thenBy { it.ruleId },
            )
            .take(config.maxIncidents)
    }

    // --- incident builders ---------------------------------------------------------------------

    private data class TrackerGroup(
        val packageName: String,
        val category: TrackerCategory,
        val domains: MutableSet<String>,
    )

    private data class C2Group(val feeds: MutableSet<String>, val addresses: MutableSet<String>)

    private fun atomicIncident(
        packageName: String,
        signal: XdrSignal,
        firstSeen: Long,
        lastSeen: Long,
    ): XdrIncident {
        val category = signal.category
        val ruleId = when (signal.kind) {
            XdrSignalKind.REPEATED_BLOCKED -> "xdr-repeated-block"
            XdrSignalKind.TRACKER_BLOCK -> "xdr-tracker-block"
            XdrSignalKind.NEW_APP -> "xdr-new-app"
            XdrSignalKind.C2_MATCH -> "xdr-c2-match"
            XdrSignalKind.HIGH_RISK_CORRIDOR -> "xdr-high-risk-corridor"
        }
        val severity = when (signal.kind) {
            XdrSignalKind.REPEATED_BLOCKED -> Severity.MEDIUM
            XdrSignalKind.TRACKER_BLOCK -> when (category) {
                TrackerCategory.ACR -> Severity.MEDIUM
                TrackerCategory.C2 -> Severity.HIGH
                else -> Severity.LOW
            }
            XdrSignalKind.NEW_APP -> Severity.INFO
            XdrSignalKind.C2_MATCH -> Severity.HIGH
            XdrSignalKind.HIGH_RISK_CORRIDOR -> Severity.INFO
        }
        val confidence = when (signal.kind) {
            XdrSignalKind.REPEATED_BLOCKED -> Confidence.MEDIUM
            XdrSignalKind.TRACKER_BLOCK -> Confidence.MEDIUM
            XdrSignalKind.NEW_APP -> Confidence.MEDIUM
            XdrSignalKind.C2_MATCH -> Confidence.HIGH
            XdrSignalKind.HIGH_RISK_CORRIDOR -> Confidence.LOW
        }
        val component = packageName + "|" + (category?.name ?: signal.kind.name)
        val (title, why, recommendation) = messagesFor(signal, packageName, category)
        return XdrIncident(
            id = Finding.identity(ruleId, component),
            ruleId = ruleId,
            severity = severity,
            confidence = confidence,
            score = signal.score,
            packageName = packageName,
            countryCode = signal.countryCode,
            category = category,
            signals = listOf(signal),
            title = title,
            why = why,
            recommendation = recommendation,
            firstSeenMillis = firstSeen,
            lastSeenMillis = lastSeen,
            count = signal.count,
            collectorCategory = if (category == TrackerCategory.C2) {
                CollectorCategory.THREAT_INTEL
            } else {
                CollectorCategory.CONNECTIVITY
            },
        )
    }

    private fun correlatedIncident(
        packageName: String,
        signals: List<XdrSignal>,
        firstSeen: Long,
        lastSeen: Long,
    ): XdrIncident {
        val score = signals.sumOf { it.score }.coerceIn(0, 100)
        val nonCorridor = signals.filter { it.kind != XdrSignalKind.HIGH_RISK_CORRIDOR }
        val hasC2 = signals.any { it.kind == XdrSignalKind.C2_MATCH }
        val severity = when {
            hasC2 -> Severity.HIGH
            score >= 70 -> Severity.HIGH
            score >= 40 -> Severity.MEDIUM
            nonCorridor.any { it.kind != XdrSignalKind.NEW_APP } -> Severity.MEDIUM
            else -> Severity.INFO
        }
        val category = listOf(
            TrackerCategory.C2,
            TrackerCategory.ACR,
            TrackerCategory.TELEMETRY,
            TrackerCategory.ADS,
            TrackerCategory.ANALYTICS,
        ).firstOrNull { candidate -> signals.any { it.category == candidate } }
        val country = signals.firstNotNullOfOrNull { it.countryCode }
        val kinds = signals.map { it.kind }.distinct()
            .joinToString(", ") { it.name.lowercase(Locale.ROOT) }
        return XdrIncident(
            id = Finding.identity("xdr-correlated", packageName),
            ruleId = "xdr-correlated",
            severity = severity,
            confidence = if (hasC2) Confidence.HIGH else Confidence.MEDIUM,
            score = score,
            packageName = packageName,
            countryCode = country,
            category = category,
            signals = signals.take(16),
            title = MessageRef("xdr.correlated.title", listOf(packageName)),
            why = MessageRef("xdr.correlated.why", listOf(packageName, kinds)),
            recommendation = MessageRef("xdr.correlated.recommendation"),
            firstSeenMillis = firstSeen,
            lastSeenMillis = lastSeen,
            count = signals.sumOf { it.count }.coerceAtLeast(1),
            collectorCategory = if (hasC2) CollectorCategory.THREAT_INTEL else CollectorCategory.CONNECTIVITY,
        )
    }

    private data class SignalMessages(
        val title: MessageRef,
        val why: MessageRef,
        val recommendation: MessageRef,
    )

    private fun messagesFor(
        signal: XdrSignal,
        packageName: String,
        category: TrackerCategory?,
    ): SignalMessages = when (signal.kind) {
        XdrSignalKind.REPEATED_BLOCKED -> SignalMessages(
            MessageRef("xdr.repeatedblock.title", listOf(packageName, signal.count.toString())),
            MessageRef("xdr.repeatedblock.why", listOf(packageName, signal.count.toString())),
            MessageRef("xdr.repeatedblock.recommendation"),
        )
        XdrSignalKind.TRACKER_BLOCK -> SignalMessages(
            MessageRef("xdr.trackerblock.title", listOf(packageName, category?.name ?: "UNKNOWN")),
            MessageRef("xdr.trackerblock.why", listOf(packageName, category?.name ?: "UNKNOWN")),
            MessageRef("xdr.trackerblock.recommendation"),
        )
        XdrSignalKind.NEW_APP -> SignalMessages(
            MessageRef("xdr.newapp.title", listOf(packageName)),
            MessageRef("xdr.newapp.why", listOf(packageName)),
            MessageRef("xdr.newapp.recommendation"),
        )
        XdrSignalKind.C2_MATCH -> SignalMessages(
            MessageRef("xdr.c2match.title", listOf(signal.destination ?: "unknown")),
            MessageRef(
                "xdr.c2match.why",
                listOf(packageName, signal.destination ?: "unknown", signal.detail.substringAfter("feeds=", "unknown")),
            ),
            MessageRef("xdr.c2match.recommendation"),
        )
        XdrSignalKind.HIGH_RISK_CORRIDOR -> SignalMessages(
            MessageRef("xdr.corridor.title", listOf(signal.countryCode ?: "??")),
            MessageRef("xdr.corridor.why", listOf(packageName, signal.countryCode ?: "??")),
            MessageRef("xdr.corridor.recommendation"),
        )
    }

    private fun pruneDedupe(now: Long) {
        if (dedupe.size <= config.maxDedupeEntries) {
            val expiry = now - config.dedupeWindowMillis * 2L
            dedupe.entries.removeAll { it.value < expiry }
            return
        }
        val sorted = dedupe.entries.sortedBy { it.value }
        val removeCount = (sorted.size - config.maxDedupeEntries).coerceAtLeast(0)
        sorted.take(removeCount).forEach { dedupe.remove(it.key) }
    }
}
