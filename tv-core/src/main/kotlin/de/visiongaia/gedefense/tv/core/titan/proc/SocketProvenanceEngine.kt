package de.visiongaia.gedefense.tv.core.titan.proc

import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.Severity
import de.visiongaia.gedefense.tv.core.titan.model.RawSocket
import de.visiongaia.gedefense.tv.core.titan.model.SocketObservation
import de.visiongaia.gedefense.tv.core.titan.model.SocketProvenanceConfig
import de.visiongaia.gedefense.tv.core.titan.model.SocketRisk
import de.visiongaia.gedefense.tv.core.titan.model.SocketSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.SocketState
import de.visiongaia.gedefense.tv.core.titan.model.TitanTextKeys

/**
 * Correlates decoded kernel socket rows with process/package provenance and the threat index.
 *
 * The engine is pure and deterministic: it never reads `/proc`, never invents a timestamp (the
 * caller passes [nowMillis]) and never claims an attribution it did not receive. Rows that cannot be
 * attributed stay [SocketRisk.UNATTRIBUTED] - a visibility gap, never a malware verdict.
 *
 * Inclusion rule: live connection states plus a `LISTEN` on [SocketProvenanceConfig.adbPort] (ADB
 * exposure). Idle `LISTEN`/`CLOSE`/`TIME_WAIT` rows and rows whose remote endpoint is the unspecified
 * `0.0.0.0:0` / `::0` address are not observations of outbound activity and are skipped, except for
 * the ADB listener.
 *
 * Attribution order (binding): the socket-table UID is primary; only a UID of `0` (unset kernel row)
 * falls back to `uidByPid[pid]`. The PID comes from the inode join (`inodeToPid`). A package is
 * attributed only when exactly one valid visible package maps to the effective UID; a shared UID with
 * several packages is ambiguous and stays unattributed (visibility gap, never a guessed verdict).
 *
 * Every bound is hard: [SocketProvenanceConfig.maxSockets] input rows, [SocketProvenanceConfig.maxProcessEntries]
 * inode lookups, [SocketProvenanceConfig.maxObservations] emitted observations. Any drop sets [SocketSnapshot.truncated].
 *
 * Visibility rule (Zero-Snake-Oil): [DataVisibility.FULL] requires a non-truncated pass with more than
 * half of the emitted observations package-attributed. A truncated pass - even a fully attributed one -
 * is [DataVisibility.PARTIAL] and carries [TitanTextKeys.NOTE_SOCKET_LIMITED], because dropped rows mean
 * the table was not completely observed.
 */
class SocketProvenanceEngine(
    private val threatIndexProvider: () -> ThreatIndex = { ThreatIndex.empty() },
    private val config: SocketProvenanceConfig = SocketProvenanceConfig.DEFAULT,
) {

    /**
     * Runs one provenance pass.
     *
     * @param sockets decoded rows, typically [ProcNetParser.parseAll] output.
     * @param inodeToPid kernel inode -> owning PID (only entries the platform could actually read).
     * @param uidByPid PID -> UID fallback for kernel rows whose socket UID is `0`.
     * @param packagesByUid UID -> installed package candidates (order irrelevant, pick is sorted).
     * @param nowMillis capture time used for every observation; non-positive values clamp to 1 ms.
     */
    fun analyze(
        sockets: List<RawSocket>,
        inodeToPid: Map<Long, Int>,
        uidByPid: Map<Int, Int>,
        packagesByUid: Map<Int, List<String>>,
        nowMillis: Long,
    ): SocketSnapshot {
        val now = nowMillis.coerceAtLeast(1L)
        if (sockets.isEmpty()) return SocketSnapshot.empty(now, DataVisibility.PARTIAL)
        val threatIndex = threatIndexProvider()
        var truncated = sockets.size > config.maxSockets
        val considered = ArrayList<SocketObservation>(minOf(config.maxObservations, INITIAL_CAPACITY))
        var evaluated = 0
        var processLookups = 0
        for (socket in sockets) {
            if (evaluated >= config.maxSockets) {
                truncated = true
                break
            }
            evaluated += 1
            if (!isMeaningful(socket)) continue
            val withinProcessBudget = processLookups < config.maxProcessEntries
            if (!withinProcessBudget) truncated = true
            val pid = if (withinProcessBudget) {
                processLookups += 1
                sanitizePid(inodeToPid[socket.inode])
            } else {
                null
            }
            val uid = effectiveUid(socket, pid, uidByPid)
            val packageName = resolvePackage(packagesByUid[uid])
            val threatMatch = if (isUnspecifiedRemote(socket)) null else threatIndex.match(socket.remoteAddress)
            val risk: SocketRisk
            val feedIds: List<String>
            when {
                threatMatch != null -> {
                    risk = SocketRisk.THREAT_FEED_MATCH
                    feedIds = threatMatch.feeds.map { feed -> feed.id }.take(SocketObservation.MAX_FEEDS)
                }

                socket.localPort == config.adbPort -> {
                    risk = SocketRisk.ADB_EXPOSED
                    feedIds = emptyList()
                }

                pid == null || packageName == null -> {
                    risk = SocketRisk.UNATTRIBUTED
                    feedIds = emptyList()
                }

                else -> {
                    risk = SocketRisk.NONE
                    feedIds = emptyList()
                }
            }
            val severity = when (risk) {
                SocketRisk.THREAT_FEED_MATCH -> Severity.CRITICAL
                SocketRisk.ADB_EXPOSED -> Severity.HIGH
                SocketRisk.UNATTRIBUTED -> Severity.MEDIUM
                SocketRisk.NONE -> null
            }
            considered += SocketObservation(
                protocol = socket.protocol,
                state = socket.state,
                localAddress = socket.localAddress,
                localPort = socket.localPort,
                remoteAddress = socket.remoteAddress,
                remotePort = socket.remotePort,
                inode = socket.inode,
                pid = pid,
                uid = uid,
                packageName = packageName,
                risk = risk,
                threatFeedIds = feedIds,
                severity = severity,
                observedAtMillis = now,
            )
        }
        if (considered.isEmpty()) {
            return SocketSnapshot.empty(now, DataVisibility.PARTIAL, limitedNote(truncated))
        }
        considered.sortWith(OBSERVATION_ORDER)
        val totalSockets = considered.size
        val capped = if (totalSockets > config.maxObservations) {
            truncated = true
            considered.subList(0, config.maxObservations).toList()
        } else {
            considered.toList()
        }
        val attributable = capped.count { observation -> observation.packageName != null }
        val suspicious = capped.count { observation -> observation.risk != SocketRisk.NONE }
        // Zero-Snake-Oil: a dropped row means the table was not fully observed, so visibility can
        // never be FULL once the pass truncated (socket/process/observation cap or budget).
        val visibility = if (!truncated && capped.isNotEmpty() && attributable * 2 > capped.size) {
            DataVisibility.FULL
        } else {
            DataVisibility.PARTIAL
        }
        return SocketSnapshot(
            observations = capped,
            totalSockets = totalSockets,
            attributableSockets = attributable,
            suspiciousCount = suspicious,
            capturedAtMillis = now,
            visibility = visibility,
            truncated = truncated,
            note = limitedNote(truncated && visibility != DataVisibility.FULL),
        )
    }

    private fun limitedNote(limited: Boolean): MessageRef? =
        if (limited) MessageRef(TitanTextKeys.NOTE_SOCKET_LIMITED) else null

    private fun isMeaningful(socket: RawSocket): Boolean {
        if (socket.state == SocketState.LISTEN) return socket.localPort == config.adbPort
        if (!socket.state.isConnected) return false
        // A connected row without a peer endpoint is not an outbound activity observation.
        return !isUnspecifiedRemote(socket)
    }

    private fun isUnspecifiedRemote(socket: RawSocket): Boolean =
        socket.remotePort == 0 && (socket.remoteAddress == IPV4_UNSPECIFIED || socket.remoteAddress == IPV6_UNSPECIFIED)

    private fun sanitizePid(pid: Int?): Int? =
        if (pid != null && pid in 1..SocketObservation.MAX_PID) pid else null

    /** Socket-table UID is primary; only an unset (`0`) row value falls back to the process UID. */
    private fun effectiveUid(socket: RawSocket, pid: Int?, uidByPid: Map<Int, Int>): Int {
        if (socket.uid != 0) return socket.uid
        if (pid == null) return socket.uid
        val processUid = uidByPid[pid] ?: return socket.uid
        return if (processUid in 0..RawSocket.MAX_UID) processUid else socket.uid
    }

    /**
     * Package resolution of one effective UID.
     *
     * Security (F-11) - never guess: a UID shared by several packages is ambiguous, and picking one
     * of them could blame an innocent app for another package's socket. Exactly one valid visible
     * package is attributed; zero packages stays unattributed; two or more distinct candidates - or a
     * candidate list that cannot be fully inspected inside the bounded window - return `null`, so the
     * socket is reported as [SocketRisk.UNATTRIBUTED] (visibility gap, not a verdict).
     */
    private fun resolvePackage(candidates: List<String>?): String? {
        if (candidates.isNullOrEmpty()) return null
        var single: String? = null
        var scanned = 0
        for (candidate in candidates) {
            if (scanned >= MAX_PACKAGE_CANDIDATES) return null
            scanned += 1
            if (!candidate.matches(PACKAGE_PATTERN)) continue
            if (single == null) {
                single = candidate
            } else if (single != candidate) {
                return null
            }
        }
        return single
    }

    companion object {
        /** Threat-first observation order, then a total deterministic tie-break chain. */
        val OBSERVATION_ORDER: Comparator<SocketObservation> = Comparator { first, second ->
            var result = riskRank(first.risk).compareTo(riskRank(second.risk))
            if (result == 0) result = first.remoteEndpoint.compareTo(second.remoteEndpoint)
            if (result == 0) result = first.protocol.name.compareTo(second.protocol.name)
            if (result == 0) result = first.localPort.compareTo(second.localPort)
            if (result == 0) result = first.inode.compareTo(second.inode)
            result
        }

        private const val INITIAL_CAPACITY = 256
        private const val MAX_PACKAGE_CANDIDATES = 64
        private const val IPV4_UNSPECIFIED = "0.0.0.0"
        private const val IPV6_UNSPECIFIED = "::"
        private val PACKAGE_PATTERN = Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+){1,15}")

        private fun riskRank(risk: SocketRisk): Int = when (risk) {
            SocketRisk.THREAT_FEED_MATCH -> 0
            SocketRisk.ADB_EXPOSED -> 1
            SocketRisk.UNATTRIBUTED -> 2
            SocketRisk.NONE -> 3
        }
    }
}
